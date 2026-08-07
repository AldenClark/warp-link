use std::collections::{BTreeMap, HashMap};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use warp_link_core::{
    AckMsg, AckStatus, DecodedClientFrame, DecodedServerFrame, DeliverMsg, HelloCtx, WelcomeMsg,
    WireError, WireProfile,
};

pub const WIRE_CODEC_POSTCARD: u8 = 1;
pub const WIRE_VERSION_V2: u8 = 2;
pub const PRIVATE_PAYLOAD_VERSION_V1: u8 = 1;
pub const SUPPORTED_WIRE_VERSIONS: &[u8] = &[WIRE_VERSION_V2];
pub const SUPPORTED_PAYLOAD_VERSIONS: &[u8] = &[PRIVATE_PAYLOAD_VERSION_V1];

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    ClientHello = 1,
    ServerWelcome = 4,
    Deliver = 8,
    Ack = 9,
    Error = 10,
    Ping = 11,
    Pong = 12,
    GoAway = 13,
}

impl FrameType {
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ClientHello),
            4 => Some(Self::ServerWelcome),
            8 => Some(Self::Deliver),
            9 => Some(Self::Ack),
            10 => Some(Self::Error),
            11 => Some(Self::Ping),
            12 => Some(Self::Pong),
            13 => Some(Self::GoAway),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientHelloWire {
    device_key: String,
    #[serde(default)]
    gateway_token: Option<String>,
    #[serde(default)]
    resume_token: Option<String>,
    #[serde(default)]
    last_acked_seq: Option<u64>,
    #[serde(default)]
    supported_wire_versions: Vec<u8>,
    #[serde(default)]
    supported_payload_versions: Vec<u8>,
    #[serde(default)]
    perf_tier: Option<String>,
    #[serde(default)]
    app_state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ServerWelcomeWire {
    session_id: String,
    resume_token: String,
    heartbeat_secs: u16,
    ping_interval_secs: u16,
    idle_timeout_secs: u16,
    max_backoff_secs: u16,
    #[serde(default)]
    auth_expires_at_unix_secs: Option<i64>,
    #[serde(default)]
    auth_refresh_before_secs: u16,
    max_frame_bytes: u32,
    negotiated_wire_version: u8,
    negotiated_payload_version: u8,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeliverWire {
    seq: u64,
    delivery_id: String,
    payload: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AckWire {
    #[serde(default)]
    seq: Option<u64>,
    delivery_id: String,
    status: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorWire {
    code: String,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivatePayloadEnvelope {
    pub payload_version: u8,
    pub data: HashMap<String, String>,
}

#[derive(Debug, Default)]
pub struct PushgoWireProfile;

impl PushgoWireProfile {
    pub fn new() -> Self {
        Self
    }
}

impl WireProfile for PushgoWireProfile {
    fn encode_client_hello(&self, hello: &HelloCtx) -> Result<Bytes, WireError> {
        let payload = postcard::to_allocvec(&ClientHelloWire {
            device_key: hello.identity.clone(),
            gateway_token: hello.auth_token.clone(),
            resume_token: hello.resume_token.clone(),
            last_acked_seq: hello.last_acked_seq,
            supported_wire_versions: normalize_client_wire_versions(&hello.supported_wire_versions),
            supported_payload_versions: normalize_client_payload_versions(
                &hello.supported_payload_versions,
            ),
            perf_tier: hello.perf_tier.clone(),
            app_state: hello.app_state.clone(),
        })
        .map_err(|e| WireError::Encode(e.to_string()))?;
        Ok(encode_frame(
            FrameType::ClientHello,
            postcard_v1_flags(),
            &payload,
        ))
    }

    fn decode_server_frame(&self, frame: &[u8]) -> Result<DecodedServerFrame, WireError> {
        let (ty, flags, payload) = decode_frame(frame)?;
        validate_wire_flags(flags)?;
        match ty {
            FrameType::ServerWelcome => {
                let welcome: ServerWelcomeWire =
                    postcard::from_bytes(payload).map_err(|e| WireError::Decode(e.to_string()))?;
                Ok(DecodedServerFrame::Welcome(WelcomeMsg {
                    session_id: welcome.session_id,
                    identity: String::new(),
                    resume_token: Some(welcome.resume_token),
                    heartbeat_secs: welcome.heartbeat_secs,
                    ping_interval_secs: welcome.ping_interval_secs,
                    idle_timeout_secs: welcome.idle_timeout_secs,
                    max_backoff_secs: welcome.max_backoff_secs,
                    auth_expires_at_unix_secs: welcome.auth_expires_at_unix_secs,
                    auth_refresh_before_secs: welcome.auth_refresh_before_secs,
                    max_frame_bytes: welcome.max_frame_bytes,
                    negotiated_wire_version: welcome.negotiated_wire_version,
                    negotiated_payload_version: welcome.negotiated_payload_version,
                    metadata: BTreeMap::new(),
                }))
            }
            FrameType::Deliver => {
                let deliver: DeliverWire =
                    postcard::from_bytes(payload).map_err(|e| WireError::Decode(e.to_string()))?;
                Ok(DecodedServerFrame::Deliver(DeliverMsg {
                    seq: Some(deliver.seq),
                    id: deliver.delivery_id,
                    payload: Bytes::from(deliver.payload),
                }))
            }
            FrameType::Ping => Ok(DecodedServerFrame::Ping),
            FrameType::Pong => Ok(DecodedServerFrame::Pong),
            FrameType::GoAway => {
                let reason = if payload.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(payload).trim().to_string())
                };
                Ok(DecodedServerFrame::GoAway(reason))
            }
            FrameType::Error => {
                let err: ErrorWire =
                    postcard::from_bytes(payload).map_err(|e| WireError::Decode(e.to_string()))?;
                Ok(DecodedServerFrame::Error {
                    code: err.code,
                    message: err.message,
                })
            }
            _ => Ok(DecodedServerFrame::Unknown),
        }
    }

    fn encode_client_ack(&self, ack: &AckMsg) -> Result<Bytes, WireError> {
        let status = match ack.status {
            AckStatus::Ok => "ok",
            AckStatus::InvalidPayload => "invalid_payload",
            AckStatus::Error => "error",
        };
        let payload = postcard::to_allocvec(&AckWire {
            seq: ack.seq,
            delivery_id: ack.id.clone(),
            status: status.to_string(),
        })
        .map_err(|e| WireError::Encode(e.to_string()))?;
        Ok(encode_frame(FrameType::Ack, postcard_v1_flags(), &payload))
    }

    fn encode_client_ping(&self) -> Bytes {
        encode_frame(FrameType::Ping, postcard_v1_flags(), &[])
    }

    fn encode_client_pong(&self) -> Bytes {
        encode_frame(FrameType::Pong, postcard_v1_flags(), &[])
    }

    fn decode_client_frame(&self, frame: &[u8]) -> Result<DecodedClientFrame, WireError> {
        let (ty, flags, payload) = decode_frame(frame)?;
        validate_wire_flags(flags)?;
        match ty {
            FrameType::ClientHello => {
                let hello: ClientHelloWire =
                    postcard::from_bytes(payload).map_err(|e| WireError::Decode(e.to_string()))?;
                Ok(DecodedClientFrame::Hello(HelloCtx {
                    identity: hello.device_key,
                    auth_token: hello.gateway_token,
                    resume_token: hello.resume_token,
                    last_acked_seq: hello.last_acked_seq,
                    supported_wire_versions: normalize_client_wire_versions(
                        &hello.supported_wire_versions,
                    ),
                    supported_payload_versions: normalize_client_payload_versions(
                        &hello.supported_payload_versions,
                    ),
                    perf_tier: hello.perf_tier,
                    app_state: hello.app_state,
                    metadata: BTreeMap::new(),
                }))
            }
            FrameType::Ack => {
                let ack: AckWire =
                    postcard::from_bytes(payload).map_err(|e| WireError::Decode(e.to_string()))?;
                let status = match ack.status.trim().to_ascii_lowercase().as_str() {
                    "ok" => AckStatus::Ok,
                    "invalid_payload" => AckStatus::InvalidPayload,
                    _ => AckStatus::Error,
                };
                Ok(DecodedClientFrame::Ack(AckMsg {
                    seq: ack.seq,
                    id: ack.delivery_id,
                    status,
                }))
            }
            FrameType::Ping => Ok(DecodedClientFrame::Ping),
            FrameType::Pong => Ok(DecodedClientFrame::Pong),
            FrameType::GoAway => {
                let reason = if payload.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(payload).trim().to_string())
                };
                Ok(DecodedClientFrame::GoAway(reason))
            }
            _ => Ok(DecodedClientFrame::Unknown),
        }
    }

    fn encode_server_welcome(&self, welcome: &WelcomeMsg) -> Result<Bytes, WireError> {
        let payload = postcard::to_allocvec(&ServerWelcomeWire {
            session_id: welcome.session_id.clone(),
            resume_token: welcome.resume_token.clone().unwrap_or_default(),
            heartbeat_secs: welcome.heartbeat_secs,
            ping_interval_secs: welcome.ping_interval_secs,
            idle_timeout_secs: welcome.idle_timeout_secs,
            max_backoff_secs: welcome.max_backoff_secs,
            auth_expires_at_unix_secs: welcome.auth_expires_at_unix_secs,
            auth_refresh_before_secs: welcome.auth_refresh_before_secs,
            max_frame_bytes: welcome.max_frame_bytes,
            negotiated_wire_version: welcome.negotiated_wire_version,
            negotiated_payload_version: welcome.negotiated_payload_version,
        })
        .map_err(|e| WireError::Encode(e.to_string()))?;
        Ok(encode_frame(
            FrameType::ServerWelcome,
            postcard_v1_flags(),
            &payload,
        ))
    }

    fn encode_server_deliver(&self, msg: &DeliverMsg) -> Result<Bytes, WireError> {
        let payload = postcard::to_allocvec(&DeliverWire {
            seq: msg.seq.unwrap_or(0),
            delivery_id: msg.id.clone(),
            payload: msg.payload.to_vec(),
        })
        .map_err(|e| WireError::Encode(e.to_string()))?;
        Ok(encode_frame(
            FrameType::Deliver,
            postcard_v1_flags(),
            &payload,
        ))
    }

    fn encode_server_ping(&self) -> Bytes {
        encode_frame(FrameType::Ping, postcard_v1_flags(), &[])
    }

    fn encode_server_pong(&self) -> Bytes {
        encode_frame(FrameType::Pong, postcard_v1_flags(), &[])
    }

    fn encode_server_goaway(&self, reason: &str) -> Result<Bytes, WireError> {
        Ok(encode_frame(
            FrameType::GoAway,
            postcard_v1_flags(),
            reason.as_bytes(),
        ))
    }

    fn encode_server_error(&self, code: &str, message: &str) -> Result<Bytes, WireError> {
        let payload = postcard::to_allocvec(&ErrorWire {
            code: code.to_string(),
            message: message.to_string(),
        })
        .map_err(|e| WireError::Encode(e.to_string()))?;
        Ok(encode_frame(
            FrameType::Error,
            postcard_v1_flags(),
            &payload,
        ))
    }
}

fn encode_frame(ty: FrameType, flags: u8, payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(ty as u8);
    out.push(flags);
    out.extend_from_slice(payload);
    Bytes::from(out)
}

fn decode_frame(frame: &[u8]) -> Result<(FrameType, u8, &[u8]), WireError> {
    if frame.len() < 2 {
        return Err(WireError::InvalidFrame("frame too short".to_string()));
    }
    let ty = FrameType::from_byte(frame[0])
        .ok_or_else(|| WireError::InvalidFrame("unsupported frame type".to_string()))?;
    let flags = frame[1];
    Ok((ty, flags, &frame[2..]))
}

pub const fn wire_flags(codec: u8, version: u8) -> u8 {
    ((codec & 0x0F) << 4) | (version & 0x0F)
}

pub const fn wire_codec(flags: u8) -> u8 {
    (flags >> 4) & 0x0F
}

pub const fn wire_version(flags: u8) -> u8 {
    flags & 0x0F
}

pub const fn postcard_v1_flags() -> u8 {
    wire_flags(WIRE_CODEC_POSTCARD, WIRE_VERSION_V2)
}

fn validate_wire_flags(flags: u8) -> Result<(), WireError> {
    let codec = wire_codec(flags);
    if codec != WIRE_CODEC_POSTCARD {
        return Err(WireError::InvalidFrame(format!(
            "unsupported codec={codec}"
        )));
    }
    let version = wire_version(flags);
    if version != WIRE_VERSION_V2 {
        return Err(WireError::VersionIncompatible(format!(
            "unsupported wire version={version}"
        )));
    }
    Ok(())
}

pub fn normalize_client_wire_versions(versions: &[u8]) -> Vec<u8> {
    if versions.is_empty() {
        vec![WIRE_VERSION_V2]
    } else {
        versions.to_vec()
    }
}

pub fn normalize_client_payload_versions(versions: &[u8]) -> Vec<u8> {
    if versions.is_empty() {
        vec![PRIVATE_PAYLOAD_VERSION_V1]
    } else {
        versions.to_vec()
    }
}

pub fn negotiate_version(
    preferred: u8,
    client_supported: &[u8],
    server_supported: &[u8],
) -> Option<u8> {
    if client_supported.contains(&preferred) && server_supported.contains(&preferred) {
        return Some(preferred);
    }
    client_supported
        .iter()
        .copied()
        .filter(|v| server_supported.contains(v))
        .max()
}

pub fn negotiate_hello_versions(hello: &HelloCtx) -> Result<(u8, u8), WireError> {
    let wire_versions = normalize_client_wire_versions(&hello.supported_wire_versions);
    let payload_versions = normalize_client_payload_versions(&hello.supported_payload_versions);
    let Some(wire) = negotiate_version(WIRE_VERSION_V2, &wire_versions, SUPPORTED_WIRE_VERSIONS)
    else {
        return Err(WireError::VersionIncompatible(
            "no compatible wire version".to_string(),
        ));
    };
    let Some(payload) = negotiate_version(
        PRIVATE_PAYLOAD_VERSION_V1,
        &payload_versions,
        SUPPORTED_PAYLOAD_VERSIONS,
    ) else {
        return Err(WireError::VersionIncompatible(
            "no compatible payload version".to_string(),
        ));
    };
    Ok((wire, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_versions_fallback_to_defaults() {
        assert_eq!(normalize_client_wire_versions(&[]), vec![WIRE_VERSION_V2]);
        assert_eq!(
            normalize_client_payload_versions(&[]),
            vec![PRIVATE_PAYLOAD_VERSION_V1]
        );
    }

    #[test]
    fn negotiate_version_prefers_target_then_highest_common() {
        assert_eq!(
            negotiate_version(2, &[1, 2], &[2, 3]),
            Some(2),
            "preferred version should win when both sides support it"
        );
        assert_eq!(
            negotiate_version(2, &[1, 3], &[1, 4]),
            Some(1),
            "fallback should pick highest common version"
        );
        assert_eq!(negotiate_version(2, &[1], &[3]), None);
    }

    #[test]
    fn negotiate_hello_versions_returns_incompatible_error_when_no_overlap() {
        let hello = HelloCtx {
            identity: "device".to_string(),
            auth_token: None,
            resume_token: None,
            last_acked_seq: None,
            supported_wire_versions: vec![9],
            supported_payload_versions: vec![PRIVATE_PAYLOAD_VERSION_V1],
            perf_tier: None,
            app_state: None,
            metadata: BTreeMap::new(),
        };
        let error = negotiate_hello_versions(&hello).expect_err("should reject unsupported wire");
        assert!(
            matches!(error, WireError::VersionIncompatible(_)),
            "expected version incompatibility error"
        );
    }

    #[test]
    fn profile_roundtrips_client_hello_and_ack() {
        let profile = PushgoWireProfile::new();
        let hello = HelloCtx {
            identity: "device-key".to_string(),
            auth_token: Some("token".to_string()),
            resume_token: Some("resume".to_string()),
            last_acked_seq: Some(42),
            supported_wire_versions: vec![],
            supported_payload_versions: vec![],
            perf_tier: Some("balanced".to_string()),
            app_state: Some("foreground".to_string()),
            metadata: BTreeMap::new(),
        };

        let encoded_hello = profile
            .encode_client_hello(&hello)
            .expect("hello encoding should succeed");
        match profile
            .decode_client_frame(&encoded_hello)
            .expect("hello decoding should succeed")
        {
            DecodedClientFrame::Hello(decoded) => {
                assert_eq!(decoded.identity, "device-key");
                assert_eq!(decoded.auth_token.as_deref(), Some("token"));
                assert_eq!(decoded.resume_token.as_deref(), Some("resume"));
                assert_eq!(decoded.last_acked_seq, Some(42));
                assert_eq!(decoded.supported_wire_versions, vec![WIRE_VERSION_V2]);
                assert_eq!(
                    decoded.supported_payload_versions,
                    vec![PRIVATE_PAYLOAD_VERSION_V1]
                );
            }
            other => panic!("unexpected decoded frame: {other:?}"),
        }

        let encoded_ack = profile
            .encode_client_ack(&AckMsg {
                seq: Some(7),
                id: "delivery-1".to_string(),
                status: AckStatus::InvalidPayload,
            })
            .expect("ack encoding should succeed");
        match profile
            .decode_client_frame(&encoded_ack)
            .expect("ack decoding should succeed")
        {
            DecodedClientFrame::Ack(decoded) => {
                assert_eq!(decoded.seq, Some(7));
                assert_eq!(decoded.id, "delivery-1");
                assert_eq!(decoded.status, AckStatus::InvalidPayload);
            }
            other => panic!("unexpected decoded frame: {other:?}"),
        }
    }

    #[test]
    fn decode_server_frame_rejects_non_postcard_codec() {
        let profile = PushgoWireProfile::new();
        let frame = vec![FrameType::Ping as u8, wire_flags(0, WIRE_VERSION_V2)];
        let error = profile
            .decode_server_frame(&frame)
            .expect_err("non postcard codec should be rejected");
        assert!(matches!(error, WireError::InvalidFrame(_)));
    }

    #[test]
    fn decode_server_frame_rejects_unsupported_wire_version() {
        let profile = PushgoWireProfile::new();
        let frame = vec![FrameType::Ping as u8, wire_flags(WIRE_CODEC_POSTCARD, 9)];
        let error = profile
            .decode_server_frame(&frame)
            .expect_err("unsupported wire version should be rejected");
        assert!(matches!(error, WireError::VersionIncompatible(_)));
    }

    #[test]
    fn decode_client_ack_unknown_status_maps_to_error() {
        let payload = postcard::to_allocvec(&AckWire {
            seq: Some(5),
            delivery_id: "d-1".to_string(),
            status: "mystery".to_string(),
        })
        .expect("postcard encode should succeed");
        let frame = encode_frame(FrameType::Ack, postcard_v1_flags(), &payload);
        let profile = PushgoWireProfile::new();
        match profile
            .decode_client_frame(&frame)
            .expect("decode should succeed")
        {
            DecodedClientFrame::Ack(ack) => {
                assert_eq!(ack.status, AckStatus::Error);
            }
            other => panic!("unexpected decoded frame: {other:?}"),
        }
    }
}
