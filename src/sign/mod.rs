//! DNSSEC signing.
//!
//! **This module is experimental and likely to change significantly.**
//!
//! This module provides support for DNSSEC signing of zones.
//!
//! DNSSEC signed zones consist of configuration data such as DNSKEY and
//! NSEC3PARAM records, NSEC(3) chains used to provably deny the existence of
//! records, and signatures that authenticate the authoritative content of the
//! zone.
//!
//! # Overview
//!
//! This module provides support for working with DNSSEC signing keys and
//! using them to DNSSEC sign sorted [`Record`] collections via the traits
//! [`SignableZone`], [`SignableZoneInPlace`] and [`Signable`].
//!
//! <div class="warning">
//!
//! This module does **NOT** yet support signing of records stored in a
//! [`Zone`].
//!
//! </div>
//!
//! Signatures can be generated using a [`SigningKey`], which combines
//! cryptographic key material with additional information that defines how
//! the key should be used.  [`SigningKey`] relies on a cryptographic backend
//! to provide the underlying signing operation (e.g.
//! [`keys::keypair::KeyPair`]).
//!
//! While all records in a zone can be signed with a single key, it is useful
//! to use one key, a Key Signing Key (KSK), "to sign the apex DNSKEY RRset in
//! a zone" and another key, a Zone Signing Key (ZSK), "to sign all the RRsets
//! in a zone that require signatures, other than the apex DNSKEY RRset" (see
//! [RFC 6781 section 3.1]).
//!
//! Cryptographically there is no difference between these key types, they are
//! assigned by the operator to signal their intended usage. This module
//! provides the [`DnssecSigningKey`] wrapper type around a [`SigningKey`] to
//! allow the intended usage of the key to be signalled by the operator, and
//! [`SigningKeyUsageStrategy`] to allow different key usage strategies to be
//! defined and selected to influence how the different types of key affect
//! signing.
//!
//! # Importing keys
//!
//! Keys can be imported from files stored on disk in the conventional BIND
//! format.
//!
//! ```
//! # use domain::base::iana::SecAlg;
//! # use domain::{sign::*, validate};
//! # use domain::sign::keys::signingkey::SigningKey;
//! // Load an Ed25519 key named 'Ktest.+015+56037'.
//! let base = "test-data/dnssec-keys/Ktest.+015+56037";
//! let sec_text = std::fs::read_to_string(format!("{base}.private")).unwrap();
//! let sec_bytes = SecretKeyBytes::parse_from_bind(&sec_text).unwrap();
//! let pub_text = std::fs::read_to_string(format!("{base}.key")).unwrap();
//! let pub_key = validate::Key::<Vec<u8>>::parse_from_bind(&pub_text).unwrap();
//!
//! // Parse the key into Ring or OpenSSL.
//! let key_pair = keys::keypair::KeyPair::from_bytes(&sec_bytes, pub_key.raw_public_key()).unwrap();
//!
//! // Associate the key with important metadata.
//! let key = SigningKey::new(pub_key.owner().clone(), pub_key.flags(), key_pair);
//!
//! // Check that the owner, algorithm, and key tag matched expectations.
//! assert_eq!(key.owner().to_string(), "test");
//! assert_eq!(key.algorithm(), SecAlg::ED25519);
//! assert_eq!(key.public_key().key_tag(), 56037);
//! ```
//!
//! # Generating keys
//!
//! Keys can also be generated.
//!
//! ```
//! # use domain::base::Name;
//! # use domain::sign::keys::keypair;
//! # use domain::sign::keys::keypair::GenerateParams;
//! # use domain::sign::keys::signingkey::SigningKey;
//! // Generate a new Ed25519 key.
//! let params = GenerateParams::Ed25519;
//! let (sec_bytes, pub_bytes) = keypair::generate(params).unwrap();
//!
//! // Parse the key into Ring or OpenSSL.
//! let key_pair = keypair::KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//!
//! // Associate the key with important metadata.
//! let owner: Name<Vec<u8>> = "www.example.org.".parse().unwrap();
//! let flags = 257; // key signing key
//! let key = SigningKey::new(owner, flags, key_pair);
//!
//! // Access the public key (with metadata).
//! let pub_key = key.public_key();
//! println!("{:?}", pub_key);
//! ```
//!
//! # Low level signing
//!
//! Given some data and a key, the data can be signed with the key.
//!
//! ```
//! # use domain::base::Name;
//! # use domain::sign::keys::keypair;
//! # use domain::sign::keys::keypair::GenerateParams;
//! # use domain::sign::keys::signingkey::SigningKey;
//! # use domain::sign::signing::traits::SignRaw;
//! # let (sec_bytes, pub_bytes) = keypair::generate(GenerateParams::Ed25519).unwrap();
//! # let key_pair = keypair::KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//! # let key = SigningKey::new(Name::<Vec<u8>>::root(), 257, key_pair);
//! // Sign arbitrary byte sequences with the key.
//! let sig = key.raw_secret_key().sign_raw(b"Hello, World!").unwrap();
//! println!("{:?}", sig);
//! ```
//!
//! # High level signing
//!
//! Given a type for which [`SignableZone`] or [`SignableZoneInPlace`] is
//! implemented, invoke `sign_zone()` on the type.
//!
//! <div class="warning">
//!
//! Currently there is no support for re-signing a zone, i.e. ensuring
//! that any changes to the authoritative records in the zone are reflected
//! by updating the NSEC(3) chain and generating additional signatures or
//! regenerating existing ones that have expired.
//!
//! </div>
//!
//! ```
//! # use domain::base::{*, iana::Class};
//! # use domain::sign::keys::keypair;
//! # use domain::sign::keys::keypair::GenerateParams;
//! # use domain::sign::keys::signingkey::SigningKey;
//! # let (sec_bytes, pub_bytes) = keypair::generate(GenerateParams::Ed25519).unwrap();
//! # let key_pair = keypair::KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//! # let root = Name::<Vec<u8>>::root();
//! # let key = SigningKey::new(root.clone(), 257, key_pair);
//! use domain::rdata::{rfc1035::Soa, ZoneRecordData};
//! use domain::rdata::dnssec::Timestamp;
//! use domain::sign::keys::keymeta::{DnssecSigningKey, DesignatedSigningKey};
//! use domain::sign::records::{DefaultSorter, SortedRecords};
//! use domain::sign::signing::config::SigningConfig;
//! use domain::sign::signing::traits::SignableZoneInPlace;
//!
//! // Create a sorted collection of records.
//! let mut records = SortedRecords::default();
//!
//! // Insert records into the collection. Just a dummy SOA for this example.
//! let soa = Soa::new(
//!     root.clone(),
//!     root.clone(),
//!     Serial::now(),
//!     Ttl::ZERO,
//!     Ttl::ZERO,
//!     Ttl::ZERO,
//!     Ttl::ZERO);
//! records.insert(Record::new(root, Class::IN, Ttl::ZERO, ZoneRecordData::Soa(soa)));
//!
//! // Generate or import signing keys (see above).
//!
//! // Assign signature validity period and operator intent to the keys.
//! let key = key.with_validity(Timestamp::now(), Timestamp::now());
//! let keys = [DnssecSigningKey::new_csk(key)];
//!
//! // Create a signing configuration.
//! let mut signing_config = SigningConfig::default();
//!
//! // Then sign the zone in place.
//! records.sign_zone(&mut signing_config, &keys).unwrap();
//! ```
//!
//! If needed, individual RRsets can also be signed:
//!
//! ```
//! # use domain::base::Name;
//! # use domain::base::iana::Class;
//! # use domain::sign::keys::keypair;
//! # use domain::sign::keys::keypair::GenerateParams;
//! # use domain::sign::keys::keymeta::{DesignatedSigningKey, DnssecSigningKey};
//! # use domain::sign::records;
//! # use domain::sign::keys::signingkey::SigningKey;
//! # let (sec_bytes, pub_bytes) = keypair::generate(GenerateParams::Ed25519).unwrap();
//! # let key_pair = keypair::KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//! # let root = Name::<Vec<u8>>::root();
//! # let key = SigningKey::new(root, 257, key_pair);
//! # let keys = [DnssecSigningKey::new_csk(key)];
//! # let mut records = records::SortedRecords::<_, _, records::DefaultSorter>::new();
//! use domain::sign::signing::traits::Signable;
//! use domain::sign::signing::strategy::DefaultSigningKeyUsageStrategy as KeyStrat;
//! let apex = records::FamilyName::new(Name::<Vec<u8>>::root(), Class::IN);
//! let rrset = records::Rrset::new(&records);
//! let generated_records = rrset.sign::<KeyStrat>(&apex, &keys).unwrap();
//! ```
//!
//! [`DnssecSigningKey`]: crate::sign::keys::keymeta::DnssecSigningKey
//! [`Record`]: crate::base::record::Record
//! [RFC 6871 section 3.1]: https://rfc-editor.org/rfc/rfc6781#section-3.1
//! [`SigningKeyUsageStrategy`]:
//!     crate::sign::signing::strategy::SigningKeyUsageStrategy
//! [`Signable`]: crate::sign::signing::traits::Signable
//! [`SignableZone`]: crate::sign::signing::traits::SignableZone
//! [`SignableZoneInPlace`]: crate::sign::signing::traits::SignableZoneInPlace
//! [`SortedRecords`]: crate::sign::SortedRecords
//! [`Zone`]: crate::zonetree::Zone
//!
//! # Cryptography
//!
//! This crate supports OpenSSL and Ring for performing cryptography.  These
//! cryptographic backends are gated on the `openssl` and `ring` features,
//! respectively.  They offer mostly equivalent functionality, but OpenSSL
//! supports a larger set of signing algorithms (and, for RSA keys, supports
//! weaker key sizes).  A [`common`] backend is provided for users that wish
//! to use either or both backends at runtime.
//!
//! Each backend module (`openssl`, `ring`, and `common`) exposes a `KeyPair`
//! type, representing a cryptographic key that can be used for signing, and a
//! `generate()` function for creating new keys.
//!
//! Users can choose to bring their own cryptography by providing their own
//! `KeyPair` type that implements [`SignRaw`].  Note that `async` signing
//! (useful for interacting with cryptographic hardware like HSMs) is not
//! currently supported.
//!
//! While each cryptographic backend can support a limited number of signature
//! algorithms, even the types independent of a cryptographic backend (e.g.
//! [`SecretKeyBytes`] and [`GenerateParams`]) support a limited number of
//! algorithms.  Even with custom cryptographic backends, this module can only
//! support these algorithms.
//!
//! # Importing and Exporting
//!
//! The [`SecretKeyBytes`] type is a generic representation of a secret key as
//! a byte slice.  While it does not offer any cryptographic functionality, it
//! is useful to transfer secret keys stored in memory, independent of any
//! cryptographic backend.
//!
//! The `KeyPair` types of the cryptographic backends in this module each
//! support a `from_bytes()` function that parses the generic representation
//! into a functional cryptographic key.  Importantly, these functions require
//! both the public and private keys to be provided -- the pair are verified
//! for consistency.  In some cases, it may also be possible to serialize an
//! existing cryptographic key back to the generic bytes representation.
//!
//! [`SecretKeyBytes`] also supports importing and exporting keys from and to
//! the conventional private-key format popularized by BIND.  This format is
//! used by a variety of tools for storing DNSSEC keys on disk.  See the
//! type-level documentation for a specification of the format.
//!
//! # Key Sets and Key Lifetime
//! The [`keyset`] module provides a way to keep track of the collection of
//! keys that are used to sign a particular zone. In addition, the lifetime of
//! keys can be maintained using key rolls that phase out old keys and
//! introduce new keys.

#![cfg(feature = "unstable-sign")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-sign")))]

pub mod crypto;
pub mod error;
pub mod hashing;
pub mod keys;
pub mod records;
pub mod signing;
pub mod zone;

pub use crate::validate::{PublicKeyBytes, RsaPublicKeyBytes, Signature};

pub use keys::bytes::{RsaSecretKeyBytes, SecretKeyBytes};

use core::cmp::min;
use core::fmt::Display;
use core::hash::Hash;
use core::marker::PhantomData;
use core::ops::Deref;

use std::boxed::Box;
use std::fmt::Debug;
use std::vec::Vec;

use crate::base::{CanonicalOrd, ToName};
use crate::base::{Name, Record, Rtype};
use crate::rdata::ZoneRecordData;

use error::SigningError;
use hashing::config::HashingConfig;
use hashing::nsec::generate_nsecs;
use hashing::nsec3::{
    generate_nsec3s, Nsec3Config, Nsec3HashProvider, Nsec3ParamTtlMode,
    Nsec3Records,
};
use keys::keymeta::DesignatedSigningKey;
use octseq::{
    EmptyBuilder, FromBuilder, OctetsBuilder, OctetsFrom, Truncate,
};
use records::{RecordsIter, Sorter};
use signing::config::SigningConfig;
use signing::rrsigs::generate_rrsigs;
use signing::strategy::SigningKeyUsageStrategy;
use signing::traits::{SignRaw, SignableZone, SortedExtend};

//------------ SignableZoneInOut ---------------------------------------------

pub enum SignableZoneInOut<'a, 'b, N, Octs, S, T, Sort>
where
    N: Clone + ToName + From<Name<Octs>> + Ord + Hash,
    Octs: Clone
        + FromBuilder
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    S: SignableZone<N, Octs, Sort>,
    Sort: Sorter,
    T: SortedExtend<N, Octs, Sort> + ?Sized,
{
    SignInPlace(&'a mut T, PhantomData<(N, Octs, Sort)>),
    SignInto(&'a S, &'b mut T),
}

impl<'a, 'b, N, Octs, S, T, Sort>
    SignableZoneInOut<'a, 'b, N, Octs, S, T, Sort>
where
    N: Clone + ToName + From<Name<Octs>> + Ord + Hash,
    Octs: Clone
        + FromBuilder
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    S: SignableZone<N, Octs, Sort>,
    Sort: Sorter,
    T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>
        + SortedExtend<N, Octs, Sort>
        + ?Sized,
{
    fn new_in_place(signable_zone: &'a mut T) -> Self {
        Self::SignInPlace(signable_zone, Default::default())
    }

    fn new_into(signable_zone: &'a S, out: &'b mut T) -> Self {
        Self::SignInto(signable_zone, out)
    }
}

impl<N, Octs, S, T, Sort> SignableZoneInOut<'_, '_, N, Octs, S, T, Sort>
where
    N: Clone + ToName + From<Name<Octs>> + Ord + Hash,
    Octs: Clone
        + FromBuilder
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    S: SignableZone<N, Octs, Sort>,
    Sort: Sorter,
    T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>
        + SortedExtend<N, Octs, Sort>
        + ?Sized,
{
    fn as_slice(&self) -> &[Record<N, ZoneRecordData<Octs, N>>] {
        match self {
            SignableZoneInOut::SignInPlace(input_output, _) => input_output,

            SignableZoneInOut::SignInto(input, _) => input,
        }
    }

    fn sorted_extend<
        U: IntoIterator<Item = Record<N, ZoneRecordData<Octs, N>>>,
    >(
        &mut self,
        iter: U,
    ) {
        match self {
            SignableZoneInOut::SignInPlace(input_output, _) => {
                input_output.sorted_extend(iter)
            }
            SignableZoneInOut::SignInto(_, output) => {
                output.sorted_extend(iter)
            }
        }
    }
}

//------------ sign_zone() ---------------------------------------------------

pub fn sign_zone<N, Octs, S, DSK, Inner, KeyStrat, Sort, HP, T>(
    mut in_out: SignableZoneInOut<N, Octs, S, T, Sort>,
    apex: &N,
    signing_config: &mut SigningConfig<N, Octs, Inner, KeyStrat, Sort, HP>,
    signing_keys: &[DSK],
) -> Result<(), SigningError>
where
    DSK: DesignatedSigningKey<Octs, Inner>,
    HP: Nsec3HashProvider<N, Octs>,
    Inner: SignRaw,
    N: Display
        + Send
        + CanonicalOrd
        + Clone
        + ToName
        + From<Name<Octs>>
        + Ord
        + Hash,
    <Octs as FromBuilder>::Builder:
        Truncate + EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    <<Octs as FromBuilder>::Builder as OctetsBuilder>::AppendError: Debug,
    KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
    S: SignableZone<N, Octs, Sort>,
    Sort: Sorter,
    T: SortedExtend<N, Octs, Sort> + ?Sized,
    Octs: FromBuilder
        + Clone
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>,
{
    let soa = in_out
        .as_slice()
        .iter()
        .find(|r| r.rtype() == Rtype::SOA)
        .ok_or(SigningError::NoSoaFound)?;
    let ZoneRecordData::Soa(ref soa_data) = soa.data() else {
        return Err(SigningError::NoSoaFound);
    };

    // RFC 9077 updated RFC 4034 (NSEC) and RFC 5155 (NSEC3) to say that
    // the "TTL of the NSEC(3) RR that is returned MUST be the lesser of
    // the MINIMUM field of the SOA record and the TTL of the SOA itself".
    let ttl = min(soa_data.minimum(), soa.ttl());

    let families = RecordsIter::new(in_out.as_slice());

    match &mut signing_config.hashing {
        HashingConfig::Prehashed => {
            // Nothing to do.
        }

        HashingConfig::Nsec => {
            let nsecs = generate_nsecs(
                apex,
                ttl,
                families,
                signing_config.add_used_dnskeys,
            );

            in_out.sorted_extend(nsecs.into_iter().map(Record::from_record));
        }

        HashingConfig::Nsec3(
            Nsec3Config {
                params,
                opt_out,
                ttl_mode,
                hash_provider,
                ..
            },
            extra,
        ) if extra.is_empty() => {
            // RFC 5155 7.1 step 5: "Sort the set of NSEC3 RRs into hash
            // order." We store the NSEC3s as we create them and sort them
            // afterwards.
            let Nsec3Records { recs, mut param } =
                generate_nsec3s::<N, Octs, HP, Sort>(
                    apex,
                    ttl,
                    families,
                    params.clone(),
                    *opt_out,
                    signing_config.add_used_dnskeys,
                    hash_provider,
                )
                .map_err(SigningError::Nsec3HashingError)?;

            let ttl = match ttl_mode {
                Nsec3ParamTtlMode::Fixed(ttl) => *ttl,
                Nsec3ParamTtlMode::Soa => soa.ttl(),
                Nsec3ParamTtlMode::SoaMinimum => {
                    if let ZoneRecordData::Soa(soa_data) = soa.data() {
                        soa_data.minimum()
                    } else {
                        // Errm, this is unexpected. TODO: Should we abort
                        // with an error here about a malformed zonefile?
                        soa.ttl()
                    }
                }
            };

            param.set_ttl(ttl);

            // Add the generated NSEC3 records.
            in_out.sorted_extend(
                std::iter::once(Record::from_record(param))
                    .chain(recs.into_iter().map(Record::from_record)),
            );
        }

        HashingConfig::Nsec3(_nsec3_config, _extra) => {
            todo!();
        }

        HashingConfig::TransitioningNsecToNsec3(
            _nsec3_config,
            _nsec_to_nsec3_transition_state,
        ) => {
            todo!();
        }

        HashingConfig::TransitioningNsec3ToNsec(
            _nsec3_config,
            _nsec3_to_nsec_transition_state,
        ) => {
            todo!();
        }
    }

    if !signing_keys.is_empty() {
        let families = RecordsIter::new(in_out.as_slice());

        let rrsigs_and_dnskeys =
            generate_rrsigs::<N, Octs, DSK, Inner, KeyStrat, Sort>(
                apex,
                families,
                signing_keys,
                signing_config.add_used_dnskeys,
            )?;

        in_out.sorted_extend(rrsigs_and_dnskeys);
    }

    Ok(())
}
