//! `itmvpn://` deep links — the hand-off from the config-download website.
//!
//! The website links to `itmvpn://import?data=<base64url>&ext=scx&name=…`,
//! carrying the profile itself inside the link, so nothing has to be fetched and
//! no endpoint has to exist on the far side. Windows launches this app (or hands
//! the URL to the already-running instance) with the URL as its single argument.
//!
//! Anyone can put such a link on a page, so a link never writes to disk on its
//! own: the payload is decoded and parsed here, then parked by
//! [`crate::backend::stage_link_import`] until the user confirms it in the UI.
//!
//! Only the inline form is implemented. A `url=` form — the app downloading from
//! a short-lived one-time link, which keeps the pre-shared key off the command
//! line — is specified in `docs/website-deeplink-integration.md` and would slot
//! in beside the `import` verb below.

use base64::Engine as _;

/// The scheme the installer registers. It is baked into every installed client's
/// registry entry, so it cannot change without an update reaching everyone.
pub const SCHEME: &str = "itmvpn";

/// Extensions a link may claim. The importers dispatch on content, so this only
/// decides what the file is called on disk — but an unknown one is still refused
/// rather than silently turned into `.ini`.
const KNOWN_EXTENSIONS: [&str; 6] = ["ini", "scx", "tgb", "mobileconfig", "ovpn", "pro"];

/// Ceiling on the encoded payload. Real profiles are 300 B – 3 KB; this sits far
/// above anything legitimate and only exists so a hostile link cannot make the
/// app chew through an arbitrarily large string.
const MAX_ENCODED: usize = 1024 * 1024;

/// Ceiling on the decoded profile.
const MAX_DECODED: usize = 256 * 1024;

/// A profile carried by a link, decoded but not yet parsed or saved.
#[derive(Debug, Clone)]
pub struct LinkImport {
    /// The name the link asked for, if any. Falls back to the profile's own.
    pub name: Option<String>,
    /// Extension the profile gets on disk.
    pub ext: String,
    /// The profile file's text.
    pub text: String,
}

/// Read an `itmvpn://` URL. Errors are phrased for the user, since they are what
/// the UI shows when a link is malformed.
pub fn parse(url: &url::Url) -> Result<LinkImport, String> {
    if !url.scheme().eq_ignore_ascii_case(SCHEME) {
        return Err(format!("not an {SCHEME}:// link"));
    }
    // `itmvpn://import?…` parses the verb as the host; `itmvpn:import?…` (no
    // slashes) leaves it in the path. Accept both — a hand-written link easily
    // ends up without the slashes.
    let verb = url
        .host_str()
        .map(str::to_ascii_lowercase)
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| url.path().trim_matches('/').to_ascii_lowercase());
    if verb != "import" {
        return Err(format!(
            "unknown {SCHEME}:// action \"{verb}\" — this client understands \"import\""
        ));
    }

    let query = url.query().unwrap_or_default();
    if query.len() > MAX_ENCODED {
        return Err("that link is too large to be a VPN profile".to_string());
    }

    let mut data: Option<String> = None;
    let mut ext: Option<String> = None;
    let mut name: Option<String> = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "data" => data = Some(value.into_owned()),
            "ext" => ext = Some(value.into_owned()),
            "name" => name = Some(value.into_owned()),
            // Ignore anything else, so the website can add a parameter a newer
            // client understands without breaking this one.
            _ => {}
        }
    }

    let data = data.ok_or(
        "that link carries no profile — it needs a `data` parameter with the profile in it",
    )?;
    let text = decode(&data)?;

    let ext = match ext {
        Some(e) => {
            let e = e.trim().trim_start_matches('.').to_ascii_lowercase();
            if !KNOWN_EXTENSIONS.iter().any(|k| *k == e) {
                return Err(format!("\"{e}\" is not a VPN profile format this client reads"));
            }
            e
        }
        None => "ini".to_string(),
    };

    Ok(LinkImport {
        ext,
        name: name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()),
        text,
    })
}

/// Decode the payload into profile text.
///
/// Deliberately lenient about the alphabet: base64url is what the spec asks for,
/// but a website that reaches for a plain `btoa()` emits standard base64, and
/// its `+` characters arrive here as spaces (that is how a query string decodes
/// `+`). All four spellings decode to the same bytes, and being strict would
/// only produce a mystery failure on the website's first attempt.
fn decode(data: &str) -> Result<String, String> {
    let normalized: String = data
        .chars()
        .map(|c| match c {
            ' ' | '-' => '+',
            '_' => '/',
            other => other,
        })
        .filter(|c| *c != '=' && !c.is_whitespace())
        .collect();

    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(normalized.as_bytes())
        .map_err(|_| "the profile in that link is damaged (it is not valid base64)".to_string())?;
    if bytes.len() > MAX_DECODED {
        return Err("that link is too large to be a VPN profile".to_string());
    }
    if bytes.is_empty() {
        return Err("that link carries an empty profile".to_string());
    }

    let text = String::from_utf8(bytes)
        .map_err(|_| "the profile in that link is not text (it is not valid UTF-8)".to_string())?;
    // A profile exported by a Windows tool often starts with a byte-order mark,
    // which the format detectors would otherwise read as the file's first
    // character and fail to recognise.
    Ok(text.strip_prefix('\u{feff}').unwrap_or(&text).to_string())
}

/// Wire deep links into the running app: the URL that launched it, plus every
/// one that arrives later.
pub fn watch(app: &tauri::AppHandle) {
    use tauri_plugin_deep_link::DeepLinkExt;

    // A link that launched the app was parsed by the plugin during its own
    // setup — before this listener could exist — so the cold-start case has to
    // be picked up from `get_current` rather than from the event. It is also too
    // early to emit anything: the web view has not attached its listeners yet,
    // so that request is parked for the UI to collect on load instead.
    if let Ok(Some(urls)) = app.deep_link().get_current() {
        handle(app, urls, Delivery::Deferred);
    }

    let handle_app = app.clone();
    app.deep_link().on_open_url(move |event| {
        handle(&handle_app, event.urls(), Delivery::Emit);
    });

    // An installed client has the scheme registered by its installer; a dev
    // build was never installed and can claim it at runtime instead. Behind an
    // opt-in, because that registration lands in the user hive, where it
    // *shadows* the installed client's — a forgotten one would quietly send
    // every link to a `target/debug` binary that may no longer exist.
    #[cfg(debug_assertions)]
    if std::env::var_os("VPN_REGISTER_SCHEME").is_some() {
        match app.deep_link().register_all() {
            Ok(()) => eprintln!("{SCHEME}:// now points at this dev build for the current user"),
            Err(e) => eprintln!("could not register the {SCHEME} scheme for this dev build: {e}"),
        }
    }
}

/// How the result reaches the window: emitted at a window that is already
/// listening, or parked for one that is still loading.
enum Delivery {
    Emit,
    Deferred,
}

/// Turn an incoming URL into a pending import the UI can confirm.
///
/// Only the first URL is acted on: the window can show one confirmation at a
/// time, and a launch never carries more than one.
fn handle(app: &tauri::AppHandle, urls: Vec<url::Url>, delivery: Delivery) {
    use tauri::{Emitter, Manager};

    let Some(url) = urls.into_iter().next() else {
        return;
    };
    // Bring the window up first, or the confirmation would sit behind the
    // browser with nothing on screen to say why the app started.
    crate::tray::reveal(app);

    let state = app.state::<crate::backend::AppState>();
    let staged = parse(&url).and_then(|link| crate::backend::stage_link_import(state.inner(), link));

    // A malformed link is worth saying out loud — silence looks like the link
    // did nothing at all.
    let request = staged.unwrap_or_else(|message| crate::backend::LinkRequest::Failed { message });

    match delivery {
        Delivery::Deferred => crate::backend::defer_link_request(state.inner(), request),
        Delivery::Emit => {
            let Some(window) = app.get_webview_window("main") else {
                return;
            };
            match request {
                crate::backend::LinkRequest::Confirm(preview) => {
                    let _ = window.emit("link-import", preview);
                }
                // A `.pro` in the link names a portal instead of carrying a
                // connection; hand it to the sign-in dialog a dropped `.pro`
                // already opens.
                crate::backend::LinkRequest::Provisioning { url, name, otp } => {
                    let _ = window.emit(
                        "provisioning-dropped",
                        serde_json::json!({ "url": url, "name": name, "otp": otp }),
                    );
                }
                // Same notice a failed drag-drop import uses.
                crate::backend::LinkRequest::Failed { message } => {
                    let _ = window.emit("import-error", message);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(query: &str) -> Result<LinkImport, String> {
        parse(&url::Url::parse(&format!("itmvpn://import?{query}")).expect("test url"))
    }

    /// base64url of "[main]\nGateway=1.2.3.4\n".
    const SAMPLE: &str = "W21haW5dCkdhdGV3YXk9MS4yLjMuNAo";

    #[test]
    fn reads_an_inline_profile() {
        let got = link(&format!("data={SAMPLE}&ext=scx&name=Kanzlei")).expect("parses");
        assert_eq!(got.text, "[main]\nGateway=1.2.3.4\n");
        assert_eq!(got.ext, "scx");
        assert_eq!(got.name.as_deref(), Some("Kanzlei"));
    }

    #[test]
    fn defaults_the_extension_and_leaves_the_name_open() {
        let got = link(&format!("data={SAMPLE}")).expect("parses");
        assert_eq!(got.ext, "ini");
        assert_eq!(got.name, None);
    }

    /// A website using `btoa()` sends standard base64, whose `+` reaches us as a
    /// space and whose `=` padding may or may not survive. All of it decodes.
    #[test]
    fn accepts_standard_base64_and_spaces_for_plus() {
        let raw = b"\xfb\xff\x00 config";
        let standard = base64::engine::general_purpose::STANDARD.encode(raw);
        assert!(standard.contains('+'), "sample should exercise the + case");
        let via_space = standard.replace('+', " ");
        let urlsafe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        for spelling in [standard.clone(), via_space, urlsafe] {
            let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(
                    spelling
                        .chars()
                        .map(|c| match c {
                            ' ' | '-' => '+',
                            '_' => '/',
                            other => other,
                        })
                        .filter(|c| *c != '=')
                        .collect::<String>(),
                )
                .expect("decodes");
            assert_eq!(bytes, raw, "failed on {spelling}");
        }
    }

    #[test]
    fn rejects_a_foreign_scheme_and_an_unknown_verb() {
        let other = url::Url::parse("vpnclient://import?data=AA").expect("test url");
        assert!(parse(&other).is_err());
        let connect = url::Url::parse("itmvpn://connect?data=AA").expect("test url");
        let err = parse(&connect).expect_err("unknown verb");
        assert!(err.contains("connect"), "{err}");
    }

    #[test]
    fn rejects_junk_payloads() {
        assert!(link("ext=ini").is_err(), "missing data");
        assert!(link("data=not!base64!").is_err());
        assert!(link("data=").is_err(), "empty payload");
        // Lone continuation byte: valid base64, invalid UTF-8.
        assert!(link("data=gA").is_err());
        assert!(link(&format!("data={SAMPLE}&ext=exe")).is_err(), "unknown extension");
    }

    #[test]
    fn rejects_an_oversized_payload() {
        let huge = "A".repeat(MAX_ENCODED + 4);
        assert!(link(&format!("data={huge}")).is_err());
        // Under the query ceiling but over the decoded one.
        let big =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(vec![b'x'; MAX_DECODED + 1]);
        assert!(decode(&big).is_err());
    }

    #[test]
    fn strips_a_byte_order_mark() {
        let with_bom =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("\u{feff}{\"gw\":1}");
        assert_eq!(decode(&with_bom).as_deref(), Ok("{\"gw\":1}"));
    }
}
