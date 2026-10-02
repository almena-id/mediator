//! Out-of-Band 2.0 invitation to use this mediator.
//!
//! A wallet that scans the invitation (as a URL or QR code) learns the mediator's
//! DID, resolves it, and sends `mediate-request` with the invitation `id` as
//! `pthid`. The invitation is the same on every request and across restarts:
//! its `id` derives from the mediator's DID, so a printed QR code keeps working.

use almena_didcomm::{Message, b64};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::home::{escape, layout};
use crate::identity::Identity;

pub const INVITATION: &str = "https://didcomm.org/out-of-band/2.0/invitation";
/// Path of the human-readable page the invitation URL points at.
pub const OOB_PATH: &str = "/oob";
/// The wallet's own URL scheme: a link with it opens the invitation in the
/// Almena wallet, when installed. QR codes keep the `https` form, which lands
/// on a page instead of nowhere when the wallet is missing.
pub const WALLET_SCHEME: &str = "almena";
/// Goal code of the mediator's invitation.
pub const GOAL_CODE: &str = "request-mediate";

/// The mediator's mediation invitation.
pub fn invitation(identity: &Identity) -> Message {
    let digest = Sha256::digest(identity.did.as_bytes());
    let id: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    let mut message = Message::new(
        INVITATION,
        json!({
            "goal_code": GOAL_CODE,
            "goal": "Use this mediator for your DIDComm messages",
            "accept": ["didcomm/v2"],
        }),
    )
    .from(&identity.did);
    message.id = id;
    message.created_time = None;
    message
}

/// The invitation as a URL: `<origin>/oob?_oob=<base64url(JSON)>`.
pub fn invitation_url(public_url: &str, invitation: &Message) -> String {
    format!("{public_url}{OOB_PATH}?_oob={}", encode(invitation))
}

/// The invitation as a link into the wallet: `almena://oob?_oob=<base64url(JSON)>`,
/// the same `_oob` parameter as [`invitation_url`].
pub fn wallet_url(invitation: &Message) -> String {
    format!("{WALLET_SCHEME}:/{OOB_PATH}?_oob={}", encode(invitation))
}

fn encode(invitation: &Message) -> String {
    // Serialising a Message cannot fail: it is plain JSON data.
    b64::encode(serde_json::to_string(invitation).unwrap_or_default())
}

/// The page shown when someone opens the invitation URL in a browser, with a
/// link that opens the invitation in the wallet (`wallet_url`).
pub fn page(did: &str, wallet_url: &str) -> String {
    let main = format!(
        r#"<h1>Mediation invitation</h1>
<p>This is an invitation to use this mediator on Almena Network.
Open it in the Almena wallet, or scan its QR code with the wallet.</p>
<a class="open" href="{wallet_url}">Open in Almena wallet</a>
<p class="did">Mediator DID: <code>{did}</code></p>
"#,
        wallet_url = escape(wallet_url),
        did = escape(did),
    );
    layout("Almena Mediator", PAGE_CSS, &main)
}

/// The invitation page's own styles, on top of the shared layout's.
const PAGE_CSS: &str = r#"
h1{margin:0;font-size:clamp(1.5rem,5vw,2rem);font-weight:600;letter-spacing:-.02em}
p{margin:0;max-width:36rem;color:var(--muted)}
.did{font-size:.875rem}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_is_stable_and_round_trips_through_the_url() {
        let identity = Identity::ephemeral("https://mediator.example.com").unwrap();
        let first = invitation(&identity);
        assert_eq!(first, invitation(&identity));
        assert_eq!(first.id.len(), 32);
        assert_eq!(first.from.as_deref(), Some("did:web:mediator.example.com"));

        let wallet = wallet_url(&first);
        assert!(wallet.starts_with("almena://oob?_oob="));
        let url = invitation_url("https://mediator.example.com", &first);
        assert_eq!(
            url.split_once('?').unwrap().1,
            wallet.split_once('?').unwrap().1
        );
        let encoded = url.split_once("?_oob=").unwrap().1;
        let decoded: Message = serde_json::from_slice(&b64::decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, first);
    }

    #[test]
    fn page_escapes_html() {
        assert!(page("did:x", "https://x/?a=1&b=<2>").contains("a=1&amp;b=&lt;2&gt;"));
    }
}
