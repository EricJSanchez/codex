//! Standard OIDC Authorization Code + PKCE login flow for custom identity providers.
//!
//! This module implements a browser-based login that works with any standards-compliant
//! OIDC provider. It:
//!
//! 1. Fetches the OIDC discovery document to obtain `authorization_endpoint` and `token_endpoint`.
//! 2. Generates a PKCE code verifier / code challenge (S256).
//! 3. Starts a local HTTP callback server.
//! 4. Opens the browser to the authorization endpoint.
//! 5. Exchanges the received authorization code for an access token.
//! 6. Persists the access token via [`codex_core::auth::login_with_oidc_token`].

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use base64::Engine;
use codex_core::auth::AuthCredentialsStoreMode;
use codex_core::auth::login_with_oidc_token;
use rand::RngCore;
use serde::Deserialize;
use tiny_http::Header;
use tiny_http::Response;
use tiny_http::Server;
use tracing::info;

use crate::pkce::PkceCodes;
use crate::pkce::generate_pkce;

const DEFAULT_CALLBACK_PORT: u16 = 1456;
const DEFAULT_SCOPES: &str = "openid profile email";

/// Options for launching a custom OIDC login flow.
#[derive(Debug, Clone)]
pub struct OidcLoginOptions {
    pub codex_home: PathBuf,
    pub issuer: String,
    pub client_id: String,
    pub scopes: Option<String>,
    pub callback_port: Option<u16>,
    pub cli_auth_credentials_store_mode: AuthCredentialsStoreMode,
}

/// Subset of the OIDC discovery document we need.
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

/// Token endpoint response.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Runs the full OIDC Authorization Code + PKCE flow and persists the resulting
/// access token to `auth.json`.
pub async fn run_oidc_login(opts: OidcLoginOptions) -> io::Result<()> {
    let issuer = opts.issuer.trim_end_matches('/').to_string();
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");

    info!("Fetching OIDC discovery from {discovery_url}");
    let client = codex_client::build_reqwest_client_with_custom_ca(reqwest::Client::builder())?;

    let discovery: OidcDiscovery = client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| io::Error::other(format!("OIDC discovery request failed: {e}")))?
        .json()
        .await
        .map_err(|e| io::Error::other(format!("Failed to parse OIDC discovery document: {e}")))?;

    let pkce = generate_pkce();
    let state = generate_state();
    let port = opts.callback_port.unwrap_or(DEFAULT_CALLBACK_PORT);
    let scopes = opts.scopes.as_deref().unwrap_or(DEFAULT_SCOPES).to_string();

    let bind_address = format!("127.0.0.1:{port}");
    let server = Server::http(&bind_address).map_err(|e| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("Failed to bind OIDC callback server on {bind_address}: {e}"),
        )
    })?;
    let actual_port = match server.server_addr().to_ip() {
        Some(addr) => addr.port(),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Unable to determine the callback server port",
            ));
        }
    };
    let server = Arc::new(server);

    let redirect_uri = format!("http://localhost:{actual_port}/callback");
    let auth_url = build_authorize_url(
        &discovery.authorization_endpoint,
        &opts.client_id,
        &redirect_uri,
        &pkce,
        &state,
        &scopes,
    );

    eprintln!("\nOpening browser for OIDC login...");
    eprintln!("If the browser does not open, visit:\n  {auth_url}\n");
    let _ = webbrowser::open(&auth_url);

    // Wait for the authorization code callback in a blocking thread.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1);
    let callback_state = state.clone();
    let callback_server = server.clone();
    thread::spawn(move || {
        wait_for_callback(&callback_server, &callback_state, tx);
    });

    let code = rx
        .recv()
        .await
        .ok_or_else(|| io::Error::other("OIDC callback server closed without receiving a code"))?;

    // Shut down the server.
    server.unblock();

    info!("Exchanging authorization code for tokens");
    let access_token = exchange_code(
        &client,
        &discovery.token_endpoint,
        &opts.client_id,
        &redirect_uri,
        &pkce,
        &code,
    )
    .await?;

    login_with_oidc_token(
        &opts.codex_home,
        &access_token,
        opts.cli_auth_credentials_store_mode,
    )?;

    eprintln!("Successfully logged in via OIDC.");
    Ok(())
}

fn build_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    pkce: &PkceCodes,
    state: &str,
    scopes: &str,
) -> String {
    let params = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", scopes),
        ("code_challenge", &pkce.code_challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
    ];
    let qs = params
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{authorization_endpoint}?{qs}")
}

fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Blocks waiting for the IdP redirect to `/callback?code=...&state=...`.
fn wait_for_callback(server: &Server, expected_state: &str, tx: tokio::sync::mpsc::Sender<String>) {
    while let Ok(request) = server.recv() {
        let url_str = format!("http://localhost{}", request.url());
        let parsed = match url::Url::parse(&url_str) {
            Ok(u) => u,
            Err(_) => {
                let _ = request.respond(Response::from_string("Bad Request").with_status_code(400));
                continue;
            }
        };

        if parsed.path() != "/callback" {
            let _ = request.respond(Response::from_string("Not Found").with_status_code(404));
            continue;
        }

        let params: std::collections::HashMap<String, String> =
            parsed.query_pairs().into_owned().collect();

        // Validate state.
        let received_state = params.get("state").map(String::as_str).unwrap_or("");
        if received_state != expected_state {
            let _ = request.respond(
                Response::from_string("State mismatch – possible CSRF attack")
                    .with_status_code(400),
            );
            continue;
        }

        // Check for errors.
        if let Some(error) = params.get("error") {
            let desc = params.get("error_description").cloned().unwrap_or_default();
            let msg = format!("OIDC login error: {error} – {desc}");
            eprintln!("{msg}");
            let _ = request.respond(Response::from_string(&msg).with_status_code(400));
            return;
        }

        // Extract code.
        if let Some(code) = params.get("code").filter(|c| !c.is_empty()) {
            let success_html = "<html><body><h1>Login successful!</h1><p>You can close this tab and return to Codex CLI.</p></body></html>";
            let content_type: Header = "Content-Type: text/html; charset=utf-8"
                .parse()
                .expect("valid header");
            let _ = request.respond(
                Response::from_string(success_html)
                    .with_header(content_type)
                    .with_status_code(200),
            );
            let _ = tx.blocking_send(code.clone());
            return;
        }

        let _ = request
            .respond(Response::from_string("Missing authorization code").with_status_code(400));
    }
}

async fn exchange_code(
    client: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    pkce: &PkceCodes,
    code: &str,
) -> io::Result<String> {
    let body = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_verifier", &pkce.code_verifier),
        ("code", code),
    ];

    let resp = client
        .post(token_endpoint)
        .form(&body)
        .send()
        .await
        .map_err(|e| io::Error::other(format!("Token exchange request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(io::Error::other(format!(
            "Token exchange failed with status {status}: {text}"
        )));
    }

    let token_resp: TokenResponse = resp
        .json()
        .await
        .map_err(|e| io::Error::other(format!("Failed to parse token response: {e}")))?;

    Ok(token_resp.access_token)
}
