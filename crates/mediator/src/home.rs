//! The page a browser shows at the mediator's root: what `/health` already
//! makes public (status, version, DID), under the header that names it. Nothing about
//! traffic: those numbers stay on the metrics listener. Below them, the
//! mediation invitation as a QR code for the wallet to scan, and as an
//! `almena://` link for whoever is reading the page on the phone itself.
//!
//! Every page the mediator serves to a browser goes through [`layout`]: the
//! header and footer of Almena's portals (catalog, registry, status) and
//! their typefaces, served by the mediator itself from [`FONTS_PATH`].

use std::time::{SystemTime, UNIX_EPOCH};

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

use crate::routes::DOCS_PATH;

/// The app icon (384 px), the favicon, served at [`ICON_PATH`].
pub const ICON: &[u8] = include_bytes!("../assets/icon.png");
pub const ICON_PATH: &str = "/icon.png";

/// Where the typefaces are served: `/fonts/<name>`, one of [`FONTS`].
pub const FONTS_PATH: &str = "/fonts";

/// The portals' typefaces, latin subset, compiled in (SIL Open Font License,
/// in `assets/fonts`): Chakra Petch for the brand and the headings, Inter for
/// the text, JetBrains Mono for values. Inter and JetBrains Mono are variable.
pub const FONTS: &[(&str, &[u8])] = &[
    (
        "chakra-petch-500.woff2",
        include_bytes!("../assets/fonts/chakra-petch-500.woff2"),
    ),
    (
        "chakra-petch-600.woff2",
        include_bytes!("../assets/fonts/chakra-petch-600.woff2"),
    ),
    (
        "chakra-petch-700.woff2",
        include_bytes!("../assets/fonts/chakra-petch-700.woff2"),
    ),
    ("inter.woff2", include_bytes!("../assets/fonts/inter.woff2")),
    (
        "jetbrains-mono.woff2",
        include_bytes!("../assets/fonts/jetbrains-mono.woff2"),
    ),
];

/// The font file called `name`, if it is one of [`FONTS`].
pub fn font(name: &str) -> Option<&'static [u8]> {
    FONTS
        .iter()
        .find(|(file, _)| *file == name)
        .map(|(_, bytes)| *bytes)
}

/// The Almena mark (three nodes and their links), in the current colour.
fn mark(size: u32) -> String {
    format!(
        r#"<svg width="{size}" height="{size}" viewBox="136 136 752 752" aria-hidden="true"><g stroke="currentColor" stroke-width="24" stroke-linecap="round"><line x1="512" y1="237" x2="237" y2="785"/><line x1="512" y1="237" x2="785" y2="785"/><line x1="237" y1="785" x2="646" y2="507"/></g><g fill="currentColor"><circle cx="512" cy="237" r="94"/><circle cx="237" cy="785" r="94"/><circle cx="785" cy="785" r="94"/></g></svg>"#
    )
}

/// The typefaces, the colours and the frame every page shares. Colours are
/// the wallet's dark tokens with its blue accent, the one the icon is drawn
/// in; green and red carry the status only. Header and footer are the
/// portals': a sticky, blurred bar on top, the page's width up to 1920 px
/// with gutters that grow with the screen.
const LAYOUT_CSS: &str = r#"
@font-face{font-family:"Chakra Petch";font-weight:500;font-display:swap;src:url(/fonts/chakra-petch-500.woff2) format("woff2")}
@font-face{font-family:"Chakra Petch";font-weight:600;font-display:swap;src:url(/fonts/chakra-petch-600.woff2) format("woff2")}
@font-face{font-family:"Chakra Petch";font-weight:700;font-display:swap;src:url(/fonts/chakra-petch-700.woff2) format("woff2")}
@font-face{font-family:"Inter";font-weight:100 900;font-display:swap;src:url(/fonts/inter.woff2) format("woff2")}
@font-face{font-family:"JetBrains Mono";font-weight:100 800;font-display:swap;src:url(/fonts/jetbrains-mono.woff2) format("woff2")}
:root{color-scheme:dark;--brand:#2f6fed;--bg:#0f1013;--glow:rgba(47,111,237,.22);--surface:rgba(255,255,255,.06);--border:rgba(255,255,255,.09);--hover:rgba(255,255,255,.07);--text:#f4f4f6;--muted:rgba(244,244,246,.62);--ok:#3ddc84;--down:#ff6b5e;--font-brand:"Chakra Petch",system-ui,sans-serif;--font-sans:"Inter",system-ui,sans-serif;--font-mono:"JetBrains Mono",ui-monospace,monospace;--page-width:1920px;--gutter:clamp(16px,3vw,48px)}
html,body{margin:0}
body{display:flex;flex-direction:column;min-height:100dvh;background:radial-gradient(60rem 40rem at 50% 40%,var(--glow),transparent 70%) fixed,var(--bg);color:var(--text);font-family:var(--font-sans);line-height:1.5;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
h1,h2,h3{font-family:var(--font-brand)}
code{font-family:var(--font-mono);overflow-wrap:anywhere}
a{color:inherit}
.frame{width:100%;max-width:var(--page-width);margin-inline:auto;padding-inline:var(--gutter);box-sizing:border-box}
.mark{flex:none;color:var(--brand)}
header{position:sticky;top:0;z-index:10;border-bottom:1px solid var(--border);background:rgba(15,16,19,.8);-webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px)}
header .frame{display:flex;align-items:center;gap:1rem;padding-block:.75rem}
.wordmark{display:inline-flex;align-items:center;gap:.625rem;font-family:var(--font-brand);font-size:17px;letter-spacing:-.025em;white-space:nowrap;text-decoration:none}
.wordmark strong{font-weight:600}
main{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1.5rem;padding-block:2rem 3rem;text-align:center}
footer{border-top:1px solid var(--border);color:var(--muted);font-size:.875rem}
footer .frame{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:1rem;padding-block:1.25rem}
footer .name{display:inline-flex;align-items:center;gap:.5rem;color:var(--text)}
footer a{text-decoration:none}
footer a:hover{color:var(--text);text-decoration:underline}
.open{padding:.6rem 1.25rem;border-radius:999px;background:var(--brand);color:#fff;font-size:.875rem;font-weight:500;text-decoration:none}
.open:hover{filter:brightness(1.1)}
"#;

/// A whole page: `title`, the shared [`LAYOUT_CSS`] plus the page's own
/// `style`, the header, `main` (HTML, already escaped) and the footer.
pub fn layout(title: &str, style: &str, main: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="icon" type="image/png" href="{ICON_PATH}">
<link rel="preload" href="{FONTS_PATH}/inter.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="{FONTS_PATH}/chakra-petch-600.woff2" as="font" type="font/woff2" crossorigin>
<style>{LAYOUT_CSS}{style}</style></head>
<body>
<header><div class="frame"><a class="wordmark" href="/" aria-label="Almena Mediator"><span class="mark">{logo}</span><span>Almena <strong>Mediator</strong></span></a></div></header>
<main class="frame">
{main}
</main>
<footer><div class="frame"><span class="name"><span class="mark">{small}</span>Almena Mediator</span><span>© {year} Almena Network · <a href="https://almena.id">almena.id</a> · <a href="{DOCS_PATH}">API</a></span></div></footer>
</body></html>
"#,
        logo = mark(28),
        small = mark(18),
        year = current_year(),
    )
}

/// The current year (UTC), for the footer.
fn current_year() -> i64 {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 86_400) as i64;
    // Days since 1970-01-01 to the civil year (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    yoe + era * 400 + i64::from(mp >= 10)
}

/// HTML-escapes `s` for text and attribute values.
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The root page, inside [`layout`].
pub fn page(
    healthy: bool,
    version: &str,
    did: &str,
    invitation_url: &str,
    wallet_url: &str,
) -> String {
    let (state, label) = if healthy {
        ("ok", "Operational")
    } else {
        ("down", "Degraded")
    };
    let main = format!(
        r#"<span class="status {state}">{label}</span>
<dl>
<dt>Version</dt><dd><code>{version}</code></dd>
<dt>DID</dt><dd><code id="did">{did}</code><button type="button" id="copy">Copy</button></dd>
</dl>
<figure><div class="qr" role="img" aria-label="Mediation invitation QR code">{qr}</div>
<figcaption>Scan with the Almena wallet to use this mediator.</figcaption></figure>
<a class="open" href="{wallet_url}">Open in Almena wallet</a>
<script>
document.getElementById("copy").onclick=async e=>{{try{{await navigator.clipboard.writeText(document.getElementById("did").textContent);e.target.textContent="Copied"}}catch{{e.target.textContent="Failed"}}setTimeout(()=>e.target.textContent="Copy",1500)}};
</script>
"#,
        version = escape(version),
        did = escape(did),
        qr = qr_svg(invitation_url),
        wallet_url = escape(wallet_url),
    );
    layout("Almena Mediator", HOME_CSS, &main)
}

/// The home page's own styles, on top of [`LAYOUT_CSS`].
const HOME_CSS: &str = r#"
.status{display:inline-flex;align-items:center;gap:.5rem;padding:.35rem .85rem;border:1px solid var(--border);border-radius:999px;background:var(--surface);font-size:.875rem}
.status::before{content:"";width:.5rem;height:.5rem;border-radius:50%;background:var(--c);box-shadow:0 0 .5rem var(--c)}
.ok{--c:var(--ok)}.down{--c:var(--down)}
dl{display:grid;grid-template-columns:auto minmax(0,1fr);gap:.5rem 1rem;margin:0;font-size:.875rem;text-align:left;max-width:100%}
dt{color:var(--muted)}dd{margin:0;display:flex;align-items:center;gap:.5rem;min-width:0}
button{flex:none;padding:.2rem .6rem;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--muted);font:inherit;font-size:.75rem;cursor:pointer}
button:hover{background:var(--hover);color:var(--text)}
figure{margin:.5rem 0 0;display:flex;flex-direction:column;align-items:center;gap:.75rem}
.qr{width:16rem;max-width:80vw;padding:.75rem;border-radius:16px;background:#fff;box-sizing:border-box}
.qr svg{display:block;width:100%;height:auto}
figcaption{color:var(--muted);font-size:.875rem}
"#;

/// `text` as an inline SVG QR code, dark on white: what cameras read best.
/// Low error correction: a screen is not a scuffed label, and the ~400-byte
/// invitation URL then needs 69 modules instead of 77, which a phone reads
/// from further away. Empty if it does not fit, which the URL always does.
fn qr_svg(text: &str) -> String {
    QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L)
        .map(|code| {
            code.render::<svg::Color>()
                .quiet_zone(false)
                .dark_color(svg::Color("#0f1013"))
                .light_color(svg::Color("#ffffff"))
                .build()
        })
        .map(|svg| {
            // Drop the XML prolog: the SVG is inlined in HTML.
            svg.find("<svg")
                .map_or(svg.clone(), |at| svg[at..].to_owned())
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_shows_the_status_and_escapes_html() {
        const URL: &str = "https://x/oob?_oob=a";
        const WALLET: &str = "almena://oob?_oob=a&b";
        assert!(page(true, "1", "did:x", URL, WALLET).contains("Operational"));
        assert!(page(false, "1", "did:x", URL, WALLET).contains("Degraded"));
        let html = page(true, "<1>", "did:x", URL, WALLET);
        assert!(html.contains("&lt;1&gt;"));
        assert!(html.contains("href=\"almena://oob?_oob=a&amp;b\""));
        assert!(html.contains("<svg"));
        assert!(!html.contains("<?xml"));
        assert!(html.contains("<header>") && html.contains("<footer>"));
    }

    #[test]
    fn every_font_the_page_asks_for_is_served() {
        for (name, bytes) in FONTS {
            assert!(LAYOUT_CSS.contains(&format!("/fonts/{name}")), "{name}");
            assert!(bytes.starts_with(b"wOF2"), "{name}");
        }
        assert!(font("inter.woff2").is_some());
        assert!(font("../icon.png").is_none());
    }

    #[test]
    fn the_year_is_this_century() {
        assert!((2026..2100).contains(&current_year()));
    }
}
