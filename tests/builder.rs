use std::sync::Arc;

use rand_core::CryptoRng;
use rand_core::Error;
use rand_core::OsRng;
use rand_core::RngCore;
use rustls::crypto::CryptoProvider;
use rustls::crypto::SupportedKxGroup;
use rustls::ClientConfig as RusTlsClientConfig;
use rustls::ServerConfig as RusTlsServerConfig;

mod fake_time;
use fake_time::FakeTime;

mod fake_cert_server_verifier;
use fake_cert_server_verifier::FakeServerCertVerifier;

mod fake_cert_client_verifier;
use fake_cert_client_verifier::FakeClientCertVerifier;

mod fake_cert_server_resolver;
use fake_cert_server_resolver::FakeServerCertResolver;

#[derive(Debug)]
struct GeneratedOsRng(OsRng);

impl GeneratedRng for GeneratedOsRng {
    fn new() -> Self {
        GeneratedOsRng(OsRng)
    }
}

impl RngCore for GeneratedOsRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for GeneratedOsRng {}

fn rustcrypto_provider() -> CryptoProvider {
    static RUSTCRYPTO_PROVIDER: Provider<GeneratedOsRng> = Provider::<GeneratedOsRng>::new();
    const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
        &kx::X25519::<GeneratedOsRng>::new(),
        &kx::SecP256R1::<GeneratedOsRng>::new(),
        &kx::SecP384R1::<GeneratedOsRng>::new(),
    ];

    CryptoProvider {
        cipher_suites: all_cipher_suites(),
        signature_verification_algorithms: all_signature_verification_algorithms(),
        secure_random: &RUSTCRYPTO_PROVIDER,
        key_provider: &RUSTCRYPTO_PROVIDER,
        kx_groups: ALL_KX_GROUPS.to_vec(),
    }
}


// Test integration between rustls and rustls in Client builder context
#[test]
fn integrate_client_builder_with_details_fake() {
    let provider = rustcrypto_provider();
    let time_provider = FakeTime {};

    let fake_server_cert_verifier = FakeServerCertVerifier {};

    let builder_init =
        RusTlsClientConfig::builder_with_details(Arc::new(provider), Arc::new(time_provider));

    let builder_default_versions = builder_init
        .with_safe_default_protocol_versions()
        .expect("Default protocol versions error?");

    let dangerous_verifier = builder_default_versions
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(fake_server_cert_verifier));

    // Out of scope
    let rustls_client_config = dangerous_verifier.with_no_client_auth();

    // RustCrypto is not fips
    assert!(!rustls_client_config.fips());
}

use rustls::DistinguishedName;
use rustls_rustcrypto::all_cipher_suites;
use rustls_rustcrypto::all_signature_verification_algorithms;
use rustls_rustcrypto::kx;
use rustls_rustcrypto::GeneratedRng;
use rustls_rustcrypto::Provider;

// Test integration between rustls and rustls in Server builder context
#[test]
fn integrate_server_builder_with_details_fake() {
    let provider = rustcrypto_provider();
    let time_provider = FakeTime {};

    let builder_init =
        RusTlsServerConfig::builder_with_details(Arc::new(provider), Arc::new(time_provider));

    let builder_default_versions = builder_init
        .with_safe_default_protocol_versions()
        .expect("Default protocol versions error?");

    // A DistinguishedName is a Vec<u8> wrapped in internal types.
    // DER or BER encoded Subject field from RFC 5280 for a single certificate.
    // The Subject field is encoded as an RFC 5280 Name
    //let b_wrap_in: &[u8] = b""; // TODO: should have constant somewhere

    let dummy_entry: &[u8] = b"";

    let client_dn = [DistinguishedName::in_sequence(dummy_entry)];

    let client_cert_verifier = FakeClientCertVerifier { dn: client_dn };

    let dangerous_verifier =
        builder_default_versions.with_client_cert_verifier(Arc::new(client_cert_verifier));

    let server_cert_resolver = FakeServerCertResolver {};

    // Out of scope
    let rustls_client_config =
        dangerous_verifier.with_cert_resolver(Arc::new(server_cert_resolver));

    // RustCrypto is not fips
    assert!(!rustls_client_config.fips());
}
