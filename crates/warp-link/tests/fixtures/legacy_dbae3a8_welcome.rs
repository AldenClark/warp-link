// Fixed historical validation fixture, not a legacy-client network test.
// Source revision: dbae3a80c8b796969cadc9045ee982a0a60c4d27
// Source: crates/warp-link/src/lib.rs (exact constant and function below).
// SHA-256 of constant + blank line + function + newline: 406e23e9412cf217ae642ef9ade4b575e46ae858f2f16ea7cc16f196806f83e5
use warp_link_core::{HelloCtx, WarpLinkError};

const TRANSPORT_MAX_FRAME_BYTES: u32 = ((32 * 1024) + 2) as u32;

fn validate_welcome_negotiation(
    hello: &HelloCtx,
    welcome: &warp_link_core::WelcomeMsg,
) -> Result<(), WarpLinkError> {
    if !hello.supported_wire_versions.is_empty()
        && !hello
            .supported_wire_versions
            .contains(&welcome.negotiated_wire_version)
    {
        return Err(WarpLinkError::Wire(
            warp_link_core::WireError::VersionIncompatible(format!(
                "server selected unsupported wire version {}",
                welcome.negotiated_wire_version
            )),
        ));
    }
    if !hello.supported_payload_versions.is_empty()
        && !hello
            .supported_payload_versions
            .contains(&welcome.negotiated_payload_version)
    {
        return Err(WarpLinkError::Wire(
            warp_link_core::WireError::VersionIncompatible(format!(
                "server selected unsupported payload version {}",
                welcome.negotiated_payload_version
            )),
        ));
    }
    if !(2..=TRANSPORT_MAX_FRAME_BYTES).contains(&welcome.max_frame_bytes) {
        return Err(WarpLinkError::Protocol(format!(
            "server selected invalid max frame bytes {}",
            welcome.max_frame_bytes
        )));
    }
    Ok(())
}
