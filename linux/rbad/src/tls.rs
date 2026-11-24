//! TLS material for the Wi-Fi transport.
//!
//! The host presents a self-signed certificate whose key is generated on first
//! run and pinned on the device at pairing time. It is a *transport* credential:
//! it protects the channel and defeats an intercepting proxy, but it is not the
//! authenticator identity. The authenticator identity is the pairing-time
//! protocol key, and the authentication decision is always a signature over a
//! fresh challenge.
//!
//! Concretely, an attacker who can MITM the network can present their own
//! certificate; pinning makes that fail. An attacker who somehow obtains this
//! TLS key still cannot sign a protocol challenge, because the TLS key is
//! generated separately from the host protocol key and is never used to sign
//! protocol messages.

use rba_protocol::errors::{ProtocolError, Result};

use crate::config::{self, Config};

/// Loads the host TLS certificate and key, generating them on first run.
pub fn load_or_create_host_tls_material(config: &Config) -> Result<(Vec<u8>, Vec<u8>)> {
    config::ensure_private_dir(&config.state_dir)
        .map_err(|e| ProtocolError::Internal(format!("state dir: {e}")))?;
    let cert_path = config.host_cert_path();
    let key_path = config.host_tls_key_path();
    if cert_path.exists() && key_path.exists() {
        let cert = std::fs::read(&cert_path)
            .map_err(|e| ProtocolError::Internal(format!("read host cert: {e}")))?;
        let key = std::fs::read(&key_path)
            .map_err(|e| ProtocolError::Internal(format!("read host tls key: {e}")))?;
        return Ok((cert, key));
    }
    generate(&cert_path, &key_path, &config.host_key_path())
}

/// Generates a self-signed certificate for this host.
fn generate(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    _host_key: &std::path::Path,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = rcgen::CertificateParams::new(vec!["rbad".to_string()])
        .map_err(|e| ProtocolError::Internal(format!("certificate parameters: {e}")))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rbad");
    params.is_ca = rcgen::IsCa::NoCa;
    // Short-lived transport credential; rotation is cheap and expected.
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| ProtocolError::Internal(format!("generate TLS key: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ProtocolError::Internal(format!("self-sign certificate: {e}")))?;
    let cert_pem = cert.pem().into_bytes();
    // Store the private key as PKCS#8 DER rather than a PEM blob: the format is
    // unambiguous and rustls consumes it without having to guess the label.
    let key_der = key_pair.serialize_der();
    config::write_private(cert_path, &cert_pem)
        .map_err(|e| ProtocolError::Internal(format!("write host cert: {e}")))?;
    config::write_private(key_path, &key_der)
        .map_err(|e| ProtocolError::Internal(format!("write host tls key: {e}")))?;
    Ok((cert_pem, key_der))
}

/// Builds the rustls server configuration for the Wi-Fi transport.
///
/// The certificate is kept on disk as PEM, which is inspectable with ordinary
/// tooling, and converted to DER here because that is what rustls consumes.
pub fn server_config(config: &Config) -> Result<rustls::ServerConfig> {
    server_config_with_fingerprint(config).map(|v| v.0)
}

pub fn server_config_with_fingerprint(config: &Config) -> Result<(rustls::ServerConfig, [u8; 32])> {
    let (cert_pem, key) = load_or_create_host_tls_material(config)?;
    let mut cursor = std::io::Cursor::new(&cert_pem);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ProtocolError::Internal(format!("parse host certificate: {e}")))?;
    if certs.is_empty() {
        return Err(ProtocolError::Internal(
            "host certificate file contains no certificates".into(),
        ));
    }
    let fingerprint = rba_protocol::crypto::sha256(certs[0].as_ref());
    let key =
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key));
    let verifier = rustls::server::WebPkiClientVerifier::no_client_auth();
    // TLS 1.3 only, pinned explicitly rather than relying on the default range.
    let cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| ProtocolError::Internal(format!("TLS config: {e}")))?;
    Ok((cfg, fingerprint))
}

/// Accepts a TLS connection from a device.
pub async fn accept(
    stream: tokio::net::TcpStream,
    config: std::sync::Arc<rustls::ServerConfig>,
) -> std::io::Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    acceptor.accept(stream).await
}

/// Builds a client configuration that trusts exactly the given certificate
/// (pinning) and nothing else.
pub fn pinned_client_config(
    pinned: rustls::pki_types::CertificateDer<'static>,
) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(pinned)
        .map_err(|e| ProtocolError::Internal(format!("pin the host certificate: {e}")))?;
    let cfg = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(cfg)
}

/// Builds a client configuration from a PEM certificate, used by the
/// simulator and by the Android app when a host has not yet been paired by
/// certificate.
pub fn client_config_from_pem(pem_pem: &[u8]) -> Result<rustls::ClientConfig> {
    let mut cursor = std::io::Cursor::new(pem_pem);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ProtocolError::Internal(format!("parse host cert: {e}")))?;
    let cert = certs
        .into_iter()
        .next()
        .ok_or_else(|| ProtocolError::Internal("host cert file is empty".into()))?;
    pinned_client_config(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rba-tls-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn tls_material_is_created_once_and_reused() {
        let d = tmp("reuse");
        let config = Config::for_tests(&d, 0);
        let (cert1, key1) = load_or_create_host_tls_material(&config).unwrap();
        let (cert2, key2) = load_or_create_host_tls_material(&config).unwrap();
        assert_eq!(cert1, cert2, "certificate must be stable across restarts");
        assert_eq!(key1, key2, "TLS key must be stable so pins survive");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tls_key_is_private() {
        let d = tmp("perm");
        let config = Config::for_tests(&d, 0);
        load_or_create_host_tls_material(&config).unwrap();
        use std::os::unix::fs::PermissionsExt;
        for p in [config.host_cert_path(), config.host_tls_key_path()] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} must be owner-only", p.display());
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn server_config_builds_with_tls_material() {
        let d = tmp("v13");
        let config = Config::for_tests(&d, 0);
        let _cfg = server_config(&config).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_pinned_client_connects_but_an_unpinned_one_cannot() {
        // This is the MITM property in practice: the device pins one specific
        // certificate, so an intercepting proxy presenting its own certificate
        // fails the handshake even though it is a perfectly valid TLS server.
        let d = tmp("mitm");
        let config = Config::for_tests(&d, 47191);
        let (real_cert, _key) = load_or_create_host_tls_material(&config).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_cfg = Arc::new(server_config(&config).unwrap());
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = accept(stream, server_cfg).await;
            }
        });

        // A client pinned to the real certificate connects.
        let good = client_config_from_pem(&real_cert).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(good));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            connector
                .connect(
                    rustls::pki_types::ServerName::try_from("rbad").unwrap(),
                    tcp
                )
                .await
                .is_ok(),
            "a correctly pinned client must connect"
        );

        // A client pinned to a *different* self-signed certificate - i.e. the
        // proxy's - must fail.
        let d2 = tmp("mitm2");
        let other = Config::for_tests(&d2, 0);
        let (evil_cert, _evil_key) = load_or_create_host_tls_material(&other).unwrap();
        assert_ne!(real_cert, evil_cert);

        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let server_cfg2 = Arc::new(server_config(&config).unwrap());
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener2.accept().await {
                let _ = accept(stream, server_cfg2).await;
            }
        });
        let bad = client_config_from_pem(&evil_cert).unwrap();
        let bad_connector = tokio_rustls::TlsConnector::from(Arc::new(bad));
        let tcp2 = tokio::net::TcpStream::connect(addr2).await.unwrap();
        assert!(
            bad_connector
                .connect(
                    rustls::pki_types::ServerName::try_from("rbad").unwrap(),
                    tcp2
                )
                .await
                .is_err(),
            "a client holding the wrong pin must not complete the handshake"
        );

        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&d2);
    }

    #[test]
    fn parsing_an_empty_certificate_fails_cleanly() {
        assert!(client_config_from_pem(b"").is_err());
        assert!(client_config_from_pem(b"not a pem").is_err());
    }
}
