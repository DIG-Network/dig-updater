//! The release source: fetch a component's latest release metadata and download an asset's bytes.
//!
//! It is a trait so the assembly pipeline ([`crate::produce_feed`]) is driven by an in-memory fake
//! in tests (no network) and by [`GithubSource`] in the CI binary. The bytes are UNTRUSTED here —
//! authenticity comes later, from the SHA-256 the signer computes and embeds in the signed
//! manifest; this module only transports them.

use std::io::Read;

use crate::error::FeedsignError;
use crate::resolve::GithubRelease;

/// A source of component release metadata + asset bytes.
pub trait ReleaseSource {
    /// The latest published release of `repo` (GitHub `owner/repo`).
    ///
    /// # Errors
    ///
    /// A transport error or an unparseable response.
    fn latest_release(&self, repo: &str) -> Result<GithubRelease, FeedsignError>;

    /// Download the bytes of a release asset from its URL.
    ///
    /// # Errors
    ///
    /// A transport error or a read failure.
    fn download(&self, url: &str) -> Result<Vec<u8>, FeedsignError>;
}

/// A [`ReleaseSource`] backed by the GitHub REST API over HTTPS.
#[derive(Debug, Clone)]
pub struct GithubSource {
    /// The API base, e.g. `https://api.github.com` (overridable so tests can point at a local
    /// server; production always uses the real host).
    api_base: String,
    /// An optional token for authenticated requests (raises rate limits; not required to read
    /// public release metadata or download public assets).
    token: Option<String>,
}

impl GithubSource {
    /// A source against the real GitHub API (`https://api.github.com`) with an optional token.
    #[must_use]
    pub fn github(token: Option<String>) -> Self {
        Self {
            api_base: "https://api.github.com".to_string(),
            token,
        }
    }

    /// A source against an arbitrary API base — used by tests to target a local HTTP server.
    #[must_use]
    pub fn with_api_base(api_base: impl Into<String>, token: Option<String>) -> Self {
        Self {
            api_base: api_base.into(),
            token,
        }
    }

    /// Apply the headers GitHub expects (a `User-Agent` is mandatory) plus optional auth.
    fn prepare(&self, request: ureq::Request) -> ureq::Request {
        let request = request
            .set("User-Agent", "dig-updater-feedsign")
            .set("Accept", "application/vnd.github+json");
        match &self.token {
            Some(token) => request.set("Authorization", &format!("Bearer {token}")),
            None => request,
        }
    }
}

impl ReleaseSource for GithubSource {
    fn latest_release(&self, repo: &str) -> Result<GithubRelease, FeedsignError> {
        let url = format!("{}/repos/{}/releases/latest", self.api_base, repo);
        let body = self
            .prepare(ureq::get(&url))
            .call()
            .map_err(|e| FeedsignError::Fetch {
                url: url.clone(),
                detail: e.to_string(),
            })?
            .into_string()
            .map_err(|e| FeedsignError::Fetch {
                url: url.clone(),
                detail: e.to_string(),
            })?;
        GithubRelease::from_json(&url, &body)
    }

    fn download(&self, url: &str) -> Result<Vec<u8>, FeedsignError> {
        let response = self
            .prepare(ureq::get(url))
            .call()
            .map_err(|e| FeedsignError::Fetch {
                url: url.to_string(),
                detail: e.to_string(),
            })?;
        let mut bytes = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut bytes)
            .map_err(|e| FeedsignError::Fetch {
                url: url.to_string(),
                detail: e.to_string(),
            })?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    /// A throwaway HTTP server serving a fixed `path -> body` table on an ephemeral loopback port.
    struct TestServer {
        server: Arc<tiny_http::Server>,
        base: String,
    }

    struct ServerGuard {
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Drop for ServerGuard {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    impl TestServer {
        fn bind() -> Self {
            let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind loopback"));
            let port = server.server_addr().to_ip().expect("ip addr").port();
            Self {
                server,
                base: format!("http://127.0.0.1:{port}"),
            }
        }

        fn serve(&self, routes: HashMap<String, Vec<u8>>) -> ServerGuard {
            let stop = Arc::new(AtomicBool::new(false));
            let server = Arc::clone(&self.server);
            let stop_thread = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                while !stop_thread.load(Ordering::SeqCst) {
                    match server.recv_timeout(Duration::from_millis(50)) {
                        Ok(Some(request)) => {
                            let (status, body) = match routes.get(request.url()) {
                                Some(body) => (200u16, body.clone()),
                                None => (404, b"not found".to_vec()),
                            };
                            let response = tiny_http::Response::from_data(body)
                                .with_status_code(tiny_http::StatusCode(status));
                            let _ = request.respond(response);
                        }
                        Ok(None) => {}
                        Err(_) => break,
                    }
                }
            });
            ServerGuard {
                stop,
                handle: Some(handle),
            }
        }
    }

    #[test]
    fn fetches_and_parses_latest_release() {
        let srv = TestServer::bind();
        let release_json = r#"{"tag_name":"v0.29.0","assets":[{"name":"dig-node-0.29.0-linux-x64","browser_download_url":"https://example.test/a"}]}"#;
        let routes = HashMap::from([(
            "/repos/DIG-Network/dig-node/releases/latest".to_string(),
            release_json.as_bytes().to_vec(),
        )]);
        let _guard = srv.serve(routes);

        let source = GithubSource::with_api_base(&srv.base, None);
        let release = source.latest_release("DIG-Network/dig-node").unwrap();
        assert_eq!(release.tag_name, "v0.29.0");
        assert_eq!(release.assets.len(), 1);
    }

    #[test]
    fn downloads_asset_bytes() {
        let srv = TestServer::bind();
        let routes = HashMap::from([("/asset".to_string(), b"the-artifact-bytes".to_vec())]);
        let _guard = srv.serve(routes);

        let source = GithubSource::with_api_base(&srv.base, Some("tok".into()));
        let bytes = source.download(&format!("{}/asset", srv.base)).unwrap();
        assert_eq!(bytes, b"the-artifact-bytes");
    }

    #[test]
    fn missing_release_is_a_fetch_error() {
        let srv = TestServer::bind();
        let _guard = srv.serve(HashMap::new()); // everything 404s
        let source = GithubSource::with_api_base(&srv.base, None);
        assert!(matches!(
            source.latest_release("DIG-Network/nope"),
            Err(FeedsignError::Fetch { .. })
        ));
    }
}
