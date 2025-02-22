use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crypto::SharedSecret;
use paste::paste;
use rustls::crypto;

use crate::GeneratedRng;

#[derive(Debug)]
pub struct X25519<R> {
    marker: PhantomData<R>,
}

impl<R> X25519<R> {
    pub const fn new() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<R> crypto::SupportedKxGroup for X25519<R>
where
    R: GeneratedRng,
{
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let mut rng = R::new();

        let priv_key = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
        let pub_key = (&priv_key).into();

        Ok(Box::new(X25519KeyExchange { priv_key, pub_key }))
    }
}

pub struct X25519KeyExchange {
    priv_key: x25519_dalek::EphemeralSecret,
    pub_key: x25519_dalek::PublicKey,
}

impl crypto::ActiveKeyExchange for X25519KeyExchange {
    fn complete(self: Box<X25519KeyExchange>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_array: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(self
            .priv_key
            .diffie_hellman(&peer_array.into())
            .as_ref()
            .into())
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

macro_rules! impl_kx {
    ($name:ident, $kx_name:ty, $secret:ty, $public_key:ty) => {
        paste! {

            #[derive(Debug)]
            #[allow(non_camel_case_types)]
            pub struct $name<R> {
                marker: PhantomData<R>,
            }

            impl<R> $name<R> {
                pub const fn new() -> Self {
                    Self {
                        marker: PhantomData,
                    }
                }
            }

            impl<R> crypto::SupportedKxGroup for $name<R>
            where
                R: GeneratedRng,
            {
                fn name(&self) -> rustls::NamedGroup {
                    $kx_name
                }

                fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
                    let mut rng = R::new();
                    let priv_key = $secret::random(&mut rng);
                    let pub_key: $public_key = (&priv_key).into();
                    Ok(Box::new([<$name KeyExchange>] {
                        priv_key,
                        pub_key: pub_key.to_sec1_bytes(),
                    }))
                }
            }

            #[allow(non_camel_case_types)]
            pub struct [<$name KeyExchange>] {
                priv_key: $secret,
                pub_key:  Box<[u8]>,
            }

            impl crypto::ActiveKeyExchange for [<$name KeyExchange>] {
                fn complete(
                    self: Box<[<$name KeyExchange>]>,
                    peer: &[u8],
                ) -> Result<SharedSecret, rustls::Error> {
                    let their_pub = $public_key::from_sec1_bytes(peer)
                        .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
                    Ok(self
                        .priv_key
                        .diffie_hellman(&their_pub)
                        .raw_secret_bytes()
                        .as_slice()
                        .into())
                }

                fn pub_key(&self) -> &[u8] {
                    &self.pub_key
                }

                fn group(&self) -> rustls::NamedGroup {
                    $kx_name
                }
            }
        }
    };
}

impl_kx! {SecP256R1, rustls::NamedGroup::secp256r1, p256::ecdh::EphemeralSecret, p256::PublicKey}
impl_kx! {SecP384R1, rustls::NamedGroup::secp384r1, p384::ecdh::EphemeralSecret, p384::PublicKey}

// pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &SecP256R1, &SecP384R1];
