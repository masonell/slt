use super::representative_cases;
use crate::error::{ConnectError, Stage};

/// No `ConnectError` whose `stage() != Auth` may render the substring
/// `auth`, and no `stage() == Auth` variant may render without carrying its
/// auth-specific detail.
///
/// Regression guard against a blanket "PermissionDenied => authentication
/// rejected" branch at any call site: the variant's own `Display` is the
/// surface that flows to logs and the UI. Cases come from
/// [`representative_cases`] so a future variant can't slip through untested.
#[test]
fn no_misleading_auth_messages() {
    for err in representative_cases() {
        let rendered = err.to_string();
        let lower = rendered.to_ascii_lowercase();
        if err.stage() != Stage::Auth {
            assert!(
                !lower.contains("auth"),
                "non-Auth stage {:?} rendered auth substring: {rendered:?}",
                err.stage()
            );
        } else {
            // Auth-stage variants must carry their auth-specific detail.
            // AuthRejected carries its code; the other auth-specific
            // variants name auth or preserve their source. Proto errors are
            // version mismatch/corruption surfaced during the auth exchange
            // and render their own non-auth-keyword detail.
            match &err {
                ConnectError::AuthRejected { code, .. } => {
                    assert!(
                        rendered.contains(&format!("{code:?}")),
                        "AuthRejected must render its code: {rendered:?}"
                    );
                }
                ConnectError::AuthTimeout
                | ConnectError::AuthDisconnected
                | ConnectError::AuthProtocolError
                | ConnectError::AuthUnexpectedMessage
                | ConnectError::AuthTlsExport { .. } => {
                    assert!(
                        lower.contains("auth"),
                        "Auth-stage variant must reference auth: {rendered:?}"
                    );
                }
                // Proto errors surface during the auth exchange; they don't
                // carry an AuthFailCode and must not be forced to render
                // "auth". They are exempt from the keyword check but stay
                // fatal (asserted in is_retriable_matches_policy_table).
                ConnectError::Frame(_) | ConnectError::Message(_) | ConnectError::Payload(_) => {}
                _ => unreachable!("stage() said Auth for a non-auth variant: {rendered:?}"),
            }
        }
    }
}
