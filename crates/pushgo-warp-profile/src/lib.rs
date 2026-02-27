use std::collections::{BTreeMap, HashMap};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use warp_link_core::{
    AckMsg, AckStatus, DecodedClientFrame, DecodedServerFrame, DeliverMsg, HelloCtx, WelcomeMsg,
    WireError, WireProfile,
};

pub const WIRE_CODEC_POSTCARD: u8 = 1;
pub const WIRE_VERSION_V1: u8 = 1;
pub const PRIVATE_PAYLOAD_VERSION_V1: u8 = 1;
pub const SUPPORTED_WIRE_VERSIONS: &[u8] = &[WIRE_VERSION_V1];
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
        validate_codec(flags)?;
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
        validate_codec(flags)?;
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
    wire_flags(WIRE_CODEC_POSTCARD, WIRE_VERSION_V1)
}

fn validate_codec(flags: u8) -> Result<(), WireError> {
    let codec = wire_codec(flags);
    if codec != WIRE_CODEC_POSTCARD {
        return Err(WireError::InvalidFrame(format!(
            "unsupported codec={codec}"
        )));
    }
    Ok(())
}

pub fn normalize_client_wire_versions(versions: &[u8]) -> Vec<u8> {
    if versions.is_empty() {
        vec![WIRE_VERSION_V1]
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
    let Some(wire) = negotiate_version(WIRE_VERSION_V1, &wire_versions, SUPPORTED_WIRE_VERSIONS)
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
    use bytes::Bytes;
    use warp_link_core::{DecodedClientFrame, DecodedServerFrame, WireProfile};

    use super::*;

    #[test]
    fn negotiate_defaults_to_v1() {
        let hello = HelloCtx {
            identity: "device".to_string(),
            ..HelloCtx::default()
        };
        let versions = negotiate_hello_versions(&hello).expect("default versions must negotiate");
        assert_eq!(versions, (WIRE_VERSION_V1, PRIVATE_PAYLOAD_VERSION_V1));
    }

    #[test]
    fn negotiate_rejects_incompatible_versions() {
        let hello = HelloCtx {
            identity: "device".to_string(),
            supported_wire_versions: vec![9],
            supported_payload_versions: vec![7],
            ..HelloCtx::default()
        };
        let err = negotiate_hello_versions(&hello).expect_err("must reject incompatible versions");
        match err {
            WireError::VersionIncompatible(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn hello_frame_roundtrip() {
        let profile = PushgoWireProfile::new();
        let hello = HelloCtx {
            identity: "dev-1".to_string(),
            auth_token: Some("token".to_string()),
            resume_token: Some("resume".to_string()),
            last_acked_seq: Some(42),
            supported_wire_versions: vec![WIRE_VERSION_V1],
            supported_payload_versions: vec![PRIVATE_PAYLOAD_VERSION_V1],
            perf_tier: Some("balanced".to_string()),
            app_state: Some("background".to_string()),
            metadata: BTreeMap::new(),
        };
        let bytes = profile
            .encode_client_hello(&hello)
            .expect("encode hello must succeed");
        let decoded = profile
            .decode_client_frame(bytes.as_ref())
            .expect("decode hello must succeed");
        match decoded {
            DecodedClientFrame::Hello(v) => {
                assert_eq!(v.identity, hello.identity);
                assert_eq!(v.auth_token, hello.auth_token);
                assert_eq!(v.resume_token, hello.resume_token);
                assert_eq!(v.last_acked_seq, hello.last_acked_seq);
                assert_eq!(v.supported_wire_versions, vec![WIRE_VERSION_V1]);
                assert_eq!(
                    v.supported_payload_versions,
                    vec![PRIVATE_PAYLOAD_VERSION_V1]
                );
            }
            other => panic!("unexpected decoded frame: {other:?}"),
        }
    }

    #[test]
    fn server_frames_roundtrip() {
        let profile = PushgoWireProfile::new();
        let welcome = WelcomeMsg {
            session_id: "s1".to_string(),
            identity: "dev".to_string(),
            resume_token: Some("rt".to_string()),
            heartbeat_secs: 12,
            ping_interval_secs: 6,
            idle_timeout_secs: 48,
            max_backoff_secs: 30,
            auth_expires_at_unix_secs: None,
            auth_refresh_before_secs: 0,
            max_frame_bytes: 32 * 1024,
            negotiated_wire_version: WIRE_VERSION_V1,
            negotiated_payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            metadata: BTreeMap::new(),
        };
        let welcome_frame = profile
            .encode_server_welcome(&welcome)
            .expect("encode welcome must succeed");
        match profile
            .decode_server_frame(welcome_frame.as_ref())
            .expect("decode welcome must succeed")
        {
            DecodedServerFrame::Welcome(v) => {
                assert_eq!(v.session_id, welcome.session_id);
                assert_eq!(v.resume_token, welcome.resume_token);
                assert_eq!(v.negotiated_wire_version, WIRE_VERSION_V1);
                assert_eq!(v.negotiated_payload_version, PRIVATE_PAYLOAD_VERSION_V1);
            }
            other => panic!("unexpected decoded frame: {other:?}"),
        }

        let deliver = DeliverMsg {
            seq: Some(7),
            id: "d-7".to_string(),
            payload: Bytes::from_static(b"payload"),
        };
        let deliver_frame = profile
            .encode_server_deliver(&deliver)
            .expect("encode deliver must succeed");
        match profile
            .decode_server_frame(deliver_frame.as_ref())
            .expect("decode deliver must succeed")
        {
            DecodedServerFrame::Deliver(v) => {
                assert_eq!(v.seq, Some(7));
                assert_eq!(v.id, "d-7");
                assert_eq!(v.payload.as_ref(), b"payload");
            }
            other => panic!("unexpected decoded frame: {other:?}"),
        }
    }

    #[test]
    fn frame_encoding_golden_vectors_stable() {
        fn to_hex(bytes: &[u8]) -> String {
            use std::fmt::Write as _;

            let mut out = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                let _ = write!(&mut out, "{byte:02x}");
            }
            out
        }

        let profile = PushgoWireProfile::new();
        let hello = HelloCtx {
            identity: "dev-1".to_string(),
            auth_token: Some("token".to_string()),
            resume_token: Some("resume".to_string()),
            last_acked_seq: Some(42),
            supported_wire_versions: vec![WIRE_VERSION_V1],
            supported_payload_versions: vec![PRIVATE_PAYLOAD_VERSION_V1],
            perf_tier: Some("balanced".to_string()),
            app_state: Some("background".to_string()),
            metadata: BTreeMap::new(),
        };
        let hello_frame = profile
            .encode_client_hello(&hello)
            .expect("encode hello must succeed");

        let welcome = WelcomeMsg {
            session_id: "s1".to_string(),
            identity: "dev".to_string(),
            resume_token: Some("rt".to_string()),
            heartbeat_secs: 12,
            ping_interval_secs: 6,
            idle_timeout_secs: 48,
            max_backoff_secs: 30,
            auth_expires_at_unix_secs: None,
            auth_refresh_before_secs: 0,
            max_frame_bytes: 32 * 1024,
            negotiated_wire_version: WIRE_VERSION_V1,
            negotiated_payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            metadata: BTreeMap::new(),
        };
        let welcome_frame = profile
            .encode_server_welcome(&welcome)
            .expect("encode welcome must succeed");

        let deliver = DeliverMsg {
            seq: Some(7),
            id: "d-7".to_string(),
            payload: Bytes::from_static(b"payload"),
        };
        let deliver_frame = profile
            .encode_server_deliver(&deliver)
            .expect("encode deliver must succeed");

        let ack = AckMsg {
            seq: Some(7),
            id: "d-7".to_string(),
            status: AckStatus::Ok,
        };
        let ack_frame = profile
            .encode_client_ack(&ack)
            .expect("encode ack must succeed");
        assert_eq!(
            to_hex(hello_frame.as_ref()),
            "0111056465762d310105746f6b656e0106726573756d65012a01010101010862616c616e636564010a6261636b67726f756e64"
        );
        assert_eq!(
            to_hex(welcome_frame.as_ref()),
            "04110273310272740c06301e00008080020101"
        );
        assert_eq!(
            to_hex(deliver_frame.as_ref()),
            "08110703642d37077061796c6f6164"
        );
        assert_eq!(to_hex(ack_frame.as_ref()), "0911010703642d37026f6b");
    }

    #[test]
    fn server_error_frame_roundtrip() {
        let profile = PushgoWireProfile::new();
        let frame = profile
            .encode_server_error("auth_failed", "token invalid")
            .expect("encode server error must succeed");
        match profile
            .decode_server_frame(frame.as_ref())
            .expect("decode server error must succeed")
        {
            DecodedServerFrame::Error { code, message } => {
                assert_eq!(code, "auth_failed");
                assert_eq!(message, "token invalid");
            }
            other => panic!("unexpected decoded frame: {other:?}"),
        }
    }

    #[test]
    fn rejects_non_postcard_codec_flag() {
        let profile = PushgoWireProfile::new();
        let mut frame = profile.encode_client_ping().to_vec();
        frame[1] = wire_flags(2, WIRE_VERSION_V1);
        let err = profile
            .decode_client_frame(frame.as_slice())
            .expect_err("non-postcard codec must be rejected");
        match err {
            WireError::InvalidFrame(message) => {
                assert!(message.contains("unsupported codec"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
