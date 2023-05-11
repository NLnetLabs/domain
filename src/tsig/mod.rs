//! Support for TSIG.
//!
//! This module provides high-level support for signing message exchanges with
//! TSIG as defined in [RFC 2845].
//!
//! TSIG is intended to provide authentication for message exchanges. Messages
//! are signed using a secret key shared between the two participants. The
//! party sending the request – the client – generates a signature over the
//! message it is about to send using that key and adds it in a special record
//! of record type [TSIG] to the additional section of the message. The
//! receiver of the request – the server – verifies the signature using the
//! same key. When creating an answer, it too generates a signature. It
//! includes the request’s signture in this process in order to bind request
//! and answer together. This signature ends up in a TSIG record in the
//! additional section as well and can be verified by the client.
//!
//! TSIG supports a number of algorithms for boths signature generation; it
//! even allows for private algorithms. The specification requires to support
//! at least HMAC-MD5 defined in [RFC 2104]. Since MD5 is widely regarded as
//! unsafe now, we don’t follow that rule and only support the SHA-based
//! algorithms from [RFC 4653]. You can choose the algorithm to use for your
//! keys via the [`Algorithm`] enum.
//!
//! Keys are managed via the [`Key`] type. While technically the actual
//! octets of the key can be used with any algorithm, we tie together a key
//! and the algorithm to use it for. In additiona, each key also has a name,
//! which is in fact a domain name. [`Key`] values also manage the signature
//! truncation that is allowed in a future version of the specification.
//!
//! Finally, there are four types for dealing with message exchanges secured
//! with TSIG. For regular transactions that consist of a request and a
//! single message, the types [`ClientTransaction`] and [`ServerTransaction`]
//! implement the client and server role, respectively. If the answer can
//! consist of a sequence of messages, such as in AXFR, [`ClientSequence`]
//! and [`ServerSequence`] can be used instead.
//!
//! For the server transaction and sequence, there is one more thing you need:
//! a [`KeyStore`], which tries to find the key used by the client. As this
//! is a trait, you may need to implement that your particular use case. There
//! is implementations for a hash map as well as a single key (the latter
//! mostly for testing).
//!
//! [RFC 2104]: https://tools.ietf.org/html/rfc2104
//! [RFC 2845]: https://tools.ietf.org/html/rfc2845
//! [RFC 4635]: https://tools.ietf.org/html/rfc4653
//! [TSIG]: ../rdata/tsig/struct.Tsig.html
//! [`Algorithm`]: enum.Algorithm.html
//! [`Key`]: enum.Key.html
//! [`KeyStore`]: trait.KeyStore.html
//! [`ClientTransaction`]: struct.ClientTransaction.html
//! [`ServerTransaction`]: struct.ServerTransaction.html
//! [`ClientSequence`]: struct.ClientSequence.html
//! [`ServerSequence`]: struct.ServerSequence.html
#![cfg(feature = "tsig")]
#![cfg_attr(docsrs, doc(cfg(feature = "tsig")))]

mod interop;

use crate::base::header::HeaderSection;
use crate::base::iana::{Class, Rcode, TsigRcode};
use crate::base::message::Message;
use crate::base::message_builder::{
    AdditionalBuilder, MessageBuilder, PushError,
};
use crate::base::name::{Dname, Label, ParsedDname, ToDname, ToLabelIter};
use crate::base::record::Record;
use crate::base::wire::{Composer, ParseError};
use crate::rdata::tsig::{Time48, Tsig};
use bytes::{Bytes, BytesMut};
use core::{cmp, fmt, mem, str};
use octseq::octets::Octets;
use ring::{constant_time, hkdf::KeyType, hmac, rand};
#[cfg(feature = "std")]
use std::collections::HashMap;

//------------ KeyName -------------------------------------------------------

pub type KeyName = Dname<octseq::array::Array<255>>;

//------------ Key -----------------------------------------------------------

/// A key for creating and validating TSIG signatures.
///
/// For the algorithms included in this implementation, keys are octet strings
/// of any size that are converted into the algorithm’s native key length
/// through a well defined method. The type provides means both for creating
/// new random keys via the [`create´] function and for loading them from
/// the octets via [`new`].
///
/// Keys are identified in TSIG through a name that is encoded as a domain
/// name. While the TSIG specification allows a key to be used with any
/// algorithm, we tie them together, so each `Key` value also knows which
/// algorithm it can be used for.
///
/// Finally, TSIG allows for the use of truncated signatures. There is hard
/// rules of the minimum signature length which can be limited further by
/// local policy. This policy is kept as part of the key. The [`min_mac_len`]
/// field defines the minimum length a received signature has to have in order
/// to be accepted. Conversely, [`signing_len`] is the length of a signature
/// created with this key.
///
/// [`create`]: #method.create
/// [`new`]: #method.new
/// [`min_mac_len`]: #method.min_mac_len
/// [`signing_len`]: #method.signing_len
#[derive(Debug)]
pub struct Key {
    /// The key’s bits and algorithm.
    key: hmac::Key,

    /// The name of the key as a domain name.
    name: KeyName,

    /// Minimum length of received signatures.
    ///
    /// This is guaranteed to be within the bounds specified by the standard:
    /// at least 10 and at least half the algorithm’s native signature length.
    /// It will also be no larger than the native signature length.
    min_mac_len: usize,

    /// The length of a signature created with this key.
    ///
    /// This has the same bounds as `min_mac_len`.
    signing_len: usize,
}

/// # Creating Keys
///
impl Key {
    /// Creates a new key from its components.
    ///
    /// This function can be used to import a key from some kind of serialized
    /// form. The algorithm, key bits, and name are necessary. By default the
    /// key will not allow any truncation.
    ///
    /// If `min_mac_len` is not `None`, the key will accept received
    /// signatures trucated to the given length. This length must not be less
    /// than 10, it must not be less than half the algorithm’s native
    /// signature length as returned by [`Algorithm::native_len`], and it must
    /// not be larger than the full native length. The function will return an
    /// error if that happens.
    ///
    /// If `signing_len` is not `None`, the signatures produces with this key
    /// will be truncated to the given length. The limits for `min_mac_len`
    /// apply here as well.
    ///
    /// [`Algorithm::native_len`]: struct.Algorithm.html#method.native_len
    pub fn new(
        algorithm: Algorithm,
        key: &[u8],
        name: KeyName,
        min_mac_len: Option<usize>,
        signing_len: Option<usize>,
    ) -> Result<Self, NewKeyError> {
        let (min_mac_len, signing_len) =
            Self::calculate_bounds(algorithm, min_mac_len, signing_len)?;
        Ok(Key {
            key: hmac::Key::new(algorithm.into_hmac_algorithm(), key),
            name,
            min_mac_len,
            signing_len,
        })
    }

    /// Generates a new signing key.
    ///
    /// This is similar to [`new`] but generates the bits for the key from the
    /// given `rng`. It returns both the key and bits for serialization and
    /// exporting.
    ///
    /// [`new`]: #method.new
    pub fn generate(
        algorithm: Algorithm,
        rng: &dyn rand::SecureRandom,
        name: KeyName,
        min_mac_len: Option<usize>,
        signing_len: Option<usize>,
    ) -> Result<(Self, Bytes), GenerateKeyError> {
        let (min_mac_len, signing_len) =
            Self::calculate_bounds(algorithm, min_mac_len, signing_len)?;
        let algorithm = algorithm.into_hmac_algorithm();
        let key_len = algorithm.len();
        let mut bytes = BytesMut::with_capacity(key_len);
        bytes.resize(key_len, 0);
        rng.fill(&mut bytes)?;
        let key = Key {
            key: hmac::Key::new(algorithm, &bytes),
            name,
            min_mac_len,
            signing_len,
        };
        Ok((key, bytes.freeze()))
    }

    /// Calculates the bounds to use in the key.
    ///
    /// Returns the actual bounds for `min_mac_len` and `signing_len` or an
    /// error if the input is out of bounds.
    fn calculate_bounds(
        algorithm: Algorithm,
        min_mac_len: Option<usize>,
        signing_len: Option<usize>,
    ) -> Result<(usize, usize), NewKeyError> {
        let min_mac_len = match min_mac_len {
            Some(len) => {
                if !algorithm.within_len_bounds(len) {
                    return Err(NewKeyError::BadMinMacLen);
                }
                len
            }
            None => algorithm.native_len(),
        };
        let signing_len = match signing_len {
            Some(len) => {
                if !algorithm.within_len_bounds(len) {
                    return Err(NewKeyError::BadSigningLen);
                }
                len
            }
            None => algorithm.native_len(),
        };
        Ok((min_mac_len, signing_len))
    }

    /// Creates a signing context for this key.
    fn signing_context(&self) -> hmac::Context {
        hmac::Context::with_key(&self.key)
    }

    /// Returns a the possibly truncated slice of the signature.
    fn signature_slice<'a>(&self, signature: &'a hmac::Tag) -> &'a [u8] {
        &signature.as_ref()[..self.signing_len]
    }
}

/// # Access to Properties
///
impl Key {
    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::from_hmac_algorithm(self.key.algorithm())
    }

    /// Returns a reference to the name of this key.
    pub fn name(&self) -> &KeyName {
        &self.name
    }

    /// Returns the native length of the signature from this key.
    pub fn native_len(&self) -> usize {
        self.key.algorithm().len()
    }

    /// Returns the minimum acceptable length of a received signature.
    pub fn min_mac_len(&self) -> usize {
        self.min_mac_len
    }

    /// Returns the length of a signature generated by this key.
    pub fn signing_len(&self) -> usize {
        self.signing_len
    }

    /// Checks whether the key in the record is this key.
    fn check_tsig<Octs: Octets>(
        &self,
        tsig: &MessageTsig<Octs>,
    ) -> Result<(), ValidationError> {
        if *tsig.record.owner() != self.name
            || *tsig.record.data().algorithm() != self.algorithm().to_dname()
        {
            Err(ValidationError::BadKey)
        } else {
            Ok(())
        }
    }

    /// Compares two signatures.
    ///
    /// The first signature is the expected value, the second the provided
    /// one. This considers signature truncation limited to whatever is
    /// acceptable by this key.
    fn compare_signatures(
        &self,
        expected: &hmac::Tag,
        provided: &[u8],
    ) -> Result<(), ValidationError> {
        if provided.len() < self.min_mac_len {
            return Err(ValidationError::BadTrunc);
        }
        let expected = if provided.len() < expected.as_ref().len() {
            &expected.as_ref()[..provided.len()]
        } else {
            expected.as_ref()
        };
        constant_time::verify_slices_are_equal(expected, provided)
            .map_err(|_| ValidationError::BadSig)
    }

    /// Completes a message by adding a TSIG record.
    ///
    /// A TSIG record will be added to the additional section. It will be
    /// constructed from the information obtained from this key, the
    /// `variables` and `mac`. Note that the MAC already has to be truncated
    /// if that is required.
    ///
    /// The method fails if the TSIG record doesn’t fit into the message
    /// anymore, in which case the builder is returned unharmed.
    fn complete_message<Target: Composer>(
        &self,
        message: &mut AdditionalBuilder<Target>,
        variables: &Variables,
        mac: &[u8],
    ) -> Result<(), PushError> {
        let id = message.header().id();
        variables.push_tsig(self, mac, id, message)
    }
}

//--- AsRef

impl AsRef<Key> for Key {
    fn as_ref(&self) -> &Self {
        self
    }
}

//------------ KeyStore ------------------------------------------------------

/// A type that stores TSIG secret keys.
///
/// This trait is used by [`ServerTransaction`] and [`ServerSequence`] to
/// determine whether a key of a TSIG signed message is known to this server.
///
/// In order to allow sharing of keys, the trait allows the implementing type
/// to pick its representation via the `Key` associated type. The `get_key`
/// method tries to return a key for a given pair of name and algorithm.
///
/// Implementations are provided for a `HashMap` mapping those pairs of name
/// and algorithm to an as-ref of a key (such as an arc) as well as for
/// as-refs of a single key. The latter is useful if you know the key to use
/// already.
///
/// If you need to limit the keys available based on properties of the
/// received message, you may need to implement your key store type that
/// wraps a more general store and limits its available keys.
pub trait KeyStore {
    /// The representation of the key returned by the store.
    type Key: AsRef<Key>;

    /// Tries to find a key in the store.
    ///
    /// The method looks up a key based on a pair of name and algorithm. If
    /// the key can be found, it is returned. Otherwise, `None` is returned.
    fn get_key<N: ToDname>(
        &self,
        name: &N,
        algorithm: Algorithm,
    ) -> Option<Self::Key>;
}

impl<K: AsRef<Key> + Clone> KeyStore for K {
    type Key = Self;

    fn get_key<N: ToDname>(
        &self,
        name: &N,
        algorithm: Algorithm,
    ) -> Option<Self::Key> {
        if self.as_ref().name() == name
            && self.as_ref().algorithm() == algorithm
        {
            Some(self.clone())
        } else {
            None
        }
    }
}

#[cfg(feature = "std")]
impl<K, S> KeyStore for HashMap<(KeyName, Algorithm), K, S>
where
    K: AsRef<Key> + Clone,
    S: core::hash::BuildHasher,
{
    type Key = K;

    fn get_key<N: ToDname>(
        &self,
        name: &N,
        algorithm: Algorithm,
    ) -> Option<Self::Key> {
        // XXX This seems a bit wasteful.
        let name = name.to_dname().unwrap();
        self.get(&(name, algorithm)).cloned()
    }
}

//------------ ClientTransaction ---------------------------------------------

/// TSIG Client Transaction State.
///
/// This types allows signing a DNS request with a given key and validate an
/// answer received for it.
///
/// You create both a signed message and a client transaction by calling the
/// [`request`] function. You can then send out the signed message and wait
/// for answers. If an answer is received, you pass it into the [`answer`]
/// method. This method will remove a TSIG record if it is present directly
/// in the message and then verify that this record is correctly signing the
/// transaction. If the message doesn’t, you can drop it and try with the next
/// answer received. The transaction will remain valid.
///
/// [`request`]: #method.request
/// [`answer`]: #method.answer
#[derive(Clone, Debug)]
pub struct ClientTransaction<K> {
    context: SigningContext<K>,
}

impl<K: AsRef<Key>> ClientTransaction<K> {
    /// Creates a transaction for a request.
    ///
    /// The method takes a complete message in the form of an additional
    /// builder and a key. It signs the message with the key and adds the
    /// signature as a TSIG record to the message’s additional section. It
    /// also creates a transaction value that can later be used to validate
    /// the response. It returns both the message and the transaction.
    ///
    /// The function can fail if the TSIG record doesn’t actually fit into
    /// the message anymore. In this case, the function returns an error and
    /// the untouched message.
    ///
    /// Unlike [`request_with_fudge`], this function uses the
    /// recommended default value for _fudge:_ 300 seconds.
    ///
    /// [`request_with_fudge`]: #method.request_with_fudge
    pub fn request<Target: Composer>(
        key: K,
        message: &mut AdditionalBuilder<Target>,
        now: Time48,
    ) -> Result<Self, PushError> {
        Self::request_with_fudge(key, message, now, 300)
    }

    /// Creates a transaction for a request with provided fudge.
    ///
    /// The method takes a complete message in the form of an additional
    /// builder and a key. It signs the message with the key and adds the
    /// signature as a TSIG record to the message’s additional section. It
    /// also creates a transaction value that can later be used to validate
    /// the response. It returns both the message and the transaction.
    ///
    /// The `fudge` argument provides the number of seconds that the
    /// receiver’s clock may be off from this system’s current time when it
    /// receives the message. The specification recommends a value of 300
    /// seconds. Unless there is good reason to not use this recommendation,
    /// you can simply use [`request`] instead.
    ///
    /// The function can fail if the TSIG record doesn’t actually fit into
    /// the message anymore. In this case, the function returns an error and
    /// the untouched message.
    ///
    /// [`request`]: #method.request
    pub fn request_with_fudge<Target>(
        key: K,
        message: &mut AdditionalBuilder<Target>,
        now: Time48,
        fudge: u16,
    ) -> Result<Self, PushError>
    where
        Target: Composer,
    {
        let variables = Variables::new(now, fudge, TsigRcode::NoError, None);
        let (mut context, mac) = SigningContext::request(
            key,
            message.as_slice(),
            None,
            &variables,
        );
        let mac = context.key().signature_slice(&mac);
        context.apply_signature(mac);
        context.key().complete_message(message, &variables, mac)?;
        Ok(ClientTransaction { context })
    }

    /// Validates an answer.
    ///
    /// Takes a message and checks whether it is a correctly signed answer
    /// for this transaction.
    ///
    /// First, if the last record in the message’s additional section is the
    /// only TSIG record in the message, it takes it out. It then checks
    /// whether this record is a correct record for this transaction and if
    /// it correctly signs the answer for this transaction. If any of this
    /// fails, returns an error.
    pub fn answer<Octs: Octets + AsMut<[u8]>>(
        &self,
        message: &mut Message<Octs>,
        now: Time48,
    ) -> Result<(), ValidationError> {
        let tsig = match self.context.get_answer_tsig(message)? {
            Some(some) => some,
            None => return Err(ValidationError::ServerUnsigned),
        };
        let mut header = message.header_section();
        header.header_mut().set_id(tsig.record.data().original_id());
        header.counts_mut().dec_arcount();
        let signature = self.context.answer(
            header.as_slice(),
            Some(
                &message.as_slice()
                    [mem::size_of::<HeaderSection>()..tsig.start],
            ),
            &tsig.variables(),
        );
        self.context.key().compare_signatures(
            &signature,
            tsig.record.data().mac().as_ref(),
        )?;
        self.context.check_answer_time(message, &tsig, now)?;
        remove_tsig(tsig.into_original_id(), message);
        Ok(())
    }

    /// Returns a reference to the transaction’s key.
    pub fn key(&self) -> &Key {
        self.context.key()
    }
}

//------------ ServerTransaction ---------------------------------------------

/// TSIG Server Transaction State.
///
/// This type allows checking a received request and sign an answer to it
/// before sending it out.
///
/// A received request is given to [`request`][Self::request] together with
/// a set of acceptable keys via a key store which will produce a server
/// transaction value if the message was signed. Once an answer is ready, it
/// can be given to that transaction value to sign it, thereby producing a
/// message that can be returned to the client.
#[derive(Clone, Debug)]
pub struct ServerTransaction<K> {
    context: SigningContext<K>,
}

impl<K: AsRef<Key>> ServerTransaction<K> {
    /// Creates a transaction for a request.
    ///
    /// The function checks whether the message carries exactly one TSIG
    /// record as the last record of the additional section. If this is the
    /// case, it removes the record form the message and checks whether it
    /// is correctly signing the request with any of the keys provided by
    /// the `store`. If that is the case, too, returns a server transaction.
    ///
    /// If the message did not have a TSIG record, returns `Ok(None)`
    /// indicating the lack of signing.
    ///
    /// If anything is wrong with the message with regards to TSIG, the
    /// function returns the error message that should be returned to the
    /// client as the error case of the result.
    #[allow(clippy::result_large_err)]
    pub fn request<Store, Octs>(
        store: &Store,
        message: &mut Message<Octs>,
        now: Time48,
    ) -> Result<Option<Self>, ServerError<K>>
    where
        Store: KeyStore<Key = K>,
        Octs: Octets + AsMut<[u8]>,
    {
        SigningContext::server_request(store, message, now).map(|context| {
            context.map(|context| ServerTransaction { context })
        })
    }

    /// Produces a signed answer.
    ///
    /// The method takes a message builder that has been processed to the
    /// additional stage already. It will then produce a signature for this
    /// message using the key and additional information derived from the
    /// original request. It tries to add this signature to the message as
    /// a TSIG record. If this succeeds, it freezes the message since the
    /// TSIG record must be the last record and returns it.
    ///
    /// If appending the TSIG record fails, which can only happen if there
    /// isn’t enough space left, it returns the builder unchanged as the
    /// error case.
    pub fn answer<Target: Composer>(
        self,
        message: &mut AdditionalBuilder<Target>,
        now: Time48,
    ) -> Result<(), PushError> {
        self.answer_with_fudge(message, now, 300)
    }

    /// Produces a signed answer with a given fudge.
    ///
    /// This method is similar to [`answer`] but lets you explicitely state
    /// the `fudge`, i.e., the number of seconds the recipient’s clock is
    /// allowed to differ from your current time when checking the signature.
    /// The default, suggested by the RFC, is 300.
    ///
    /// [`answer`]: #method.answer
    pub fn answer_with_fudge<Target>(
        self,
        message: &mut AdditionalBuilder<Target>,
        now: Time48,
        fudge: u16,
    ) -> Result<(), PushError>
    where
        Target: Composer,
    {
        let variables = Variables::new(now, fudge, TsigRcode::NoError, None);
        let (mac, key) =
            self.context
                .final_answer(message.as_slice(), None, &variables);
        let mac = key.as_ref().signature_slice(&mac);
        key.as_ref().complete_message(message, &variables, mac)
    }

    /// Returns a reference to the transaction’s key.
    pub fn key(&self) -> &Key {
        self.context.key()
    }
}

//------------ ClientSequence ------------------------------------------------

/// TSIG client sequence state.
///
/// This type allows a client to create a signed request and later check a
/// series of answers for being signed accordingly. It is necessary because
/// the signatures in the second and later answers in the sequence are
/// generated in a different way than the first one.
///
/// Much like with [`ClientTransaction`], you can sign a request via the
/// [`request`] method provding the signing key and receiving the signed
/// version of the message and a client transaction value. You can then use
/// this value to validate a sequence of answers as they are received by
/// giving them to the [`answer`] method.
///
/// Once you have received the last answer, you call the [`done`] method to
/// check whether the sequence was allowed to end. This is necessary because
/// TSIG allows intermediary messages to be unsigned but demands the last
/// message to be signed.
///
/// [`ClientTransaction`]: struct.ClientTransaction.html
/// [`request`]: #method.request
/// [`answer`]: #method.answer
/// [`done`]: #method.done
#[derive(Clone, Debug)]
pub struct ClientSequence<K> {
    /// A signing context to be used for the next signed answer.
    context: SigningContext<K>,

    /// Are we still waiting for the first answer?
    first: bool,

    /// How many unsigned answers have we seen since the last signed answer?
    unsigned: usize,
}

impl<K: AsRef<Key>> ClientSequence<K> {
    /// Creates a sequence for a request.
    ///
    /// The function will sign the message as it has been built so far using
    /// the given key and add a corresponding TSIG record to it. If this
    /// fails because there wasn’t enough space left in the message builder,
    /// returns the builder untouched as the error case. Otherwise, it will
    /// freeze the message and return both it and a new value of a client
    /// sequence.
    pub fn request<Target: Composer>(
        key: K,
        message: &mut AdditionalBuilder<Target>,
        now: Time48,
    ) -> Result<Self, PushError> {
        Self::request_with_fudge(key, message, now, 300)
    }

    /// Creates a sequence for a request with a specific fudge.
    ///
    /// This is almost identical to [`request`] but allows you to explicitely
    /// specify a value of fudge which describes the number of seconds the
    /// recipients clock may differ from this system’s current time when
    /// checking the request. The default value used by [`request`] is 300
    /// seconds.
    ///
    /// [`request`]: #method.request
    pub fn request_with_fudge<Target>(
        key: K,
        message: &mut AdditionalBuilder<Target>,
        now: Time48,
        fudge: u16,
    ) -> Result<Self, PushError>
    where
        Target: Composer,
    {
        let variables = Variables::new(now, fudge, TsigRcode::NoError, None);
        let (mut context, mac) = SigningContext::request(
            key,
            message.as_slice(),
            None,
            &variables,
        );
        let mac = context.key().signature_slice(&mac);
        context.apply_signature(mac);
        context.key().complete_message(message, &variables, mac)?;
        Ok(ClientSequence {
            context,
            first: true,
            unsigned: 0,
        })
    }

    /// Validates an answer.
    ///
    /// If the answer contains exactly one TSIG record as its last record,
    /// removes this record and checks that it correctly signs this message
    /// as part of the sequence.
    ///
    /// If it doesn’t or if there had been more than 99 unsigned messages in
    /// the sequence since the last signed one, returns an error.
    pub fn answer<Octs>(
        &mut self,
        message: &mut Message<Octs>,
        now: Time48,
    ) -> Result<(), ValidationError>
    where
        Octs: Octets + AsMut<[u8]>,
    {
        if self.first {
            self.answer_first(message, now)
        } else {
            self.answer_subsequent(message, now)
        }
    }

    /// Validates the end of the sequence.
    ///
    /// Specifically, this checks that the last message given to [`answer`]
    /// had been signed.
    ///
    /// [`answer`]: #method.answer
    pub fn done(self) -> Result<(), ValidationError> {
        // The last message must be signed, so the counter must be 0 here.
        if self.unsigned != 0 {
            Err(ValidationError::TooManyUnsigned)
        } else {
            Ok(())
        }
    }

    /// Checks the first answer in the sequence.
    fn answer_first<Octs>(
        &mut self,
        message: &mut Message<Octs>,
        now: Time48,
    ) -> Result<(), ValidationError>
    where
        Octs: Octets + AsMut<[u8]>,
    {
        let tsig = match self.context.get_answer_tsig(message)? {
            Some(some) => some,
            None => return Err(ValidationError::ServerUnsigned),
        };
        let mut header = message.header_section();
        header.header_mut().set_id(tsig.record.data().original_id());
        header.counts_mut().dec_arcount();
        let signature = self.context.first_answer(
            header.as_slice(),
            Some(
                &message.as_slice()
                    [mem::size_of::<HeaderSection>()..tsig.start],
            ),
            &tsig.variables(),
        );
        self.context.key().compare_signatures(
            &signature,
            tsig.record.data().mac().as_ref(),
        )?;
        self.context
            .apply_signature(tsig.record.data().mac().as_ref());
        self.context.check_answer_time(message, &tsig, now)?;
        self.first = false;
        remove_tsig(tsig.into_original_id(), message);
        Ok(())
    }

    /// Checks any subsequent answer in the sequence.
    fn answer_subsequent<Octs>(
        &mut self,
        message: &mut Message<Octs>,
        now: Time48,
    ) -> Result<(), ValidationError>
    where
        Octs: Octets + AsMut<[u8]>,
    {
        let tsig = match self.context.get_answer_tsig(message)? {
            Some(tsig) => tsig,
            None => {
                if self.unsigned < 99 {
                    self.context.unsigned_subsequent(message.as_slice());
                    self.unsigned += 1;
                    return Ok(());
                } else {
                    return Err(ValidationError::TooManyUnsigned);
                }
            }
        };

        // Check the MAC.
        let mut header = message.header_section();
        header.header_mut().set_id(tsig.record.data().original_id());
        header.counts_mut().dec_arcount();
        let signature = self.context.signed_subsequent(
            header.as_slice(),
            Some(
                &message.as_slice()
                    [mem::size_of::<HeaderSection>()..tsig.start],
            ),
            &tsig.variables(),
        );
        self.context.key().compare_signatures(
            &signature,
            tsig.record.data().mac().as_ref(),
        )?;
        self.context
            .apply_signature(tsig.record.data().mac().as_ref());
        self.context.check_answer_time(message, &tsig, now)?;
        self.unsigned = 0;
        remove_tsig(tsig.into_original_id(), message);
        Ok(())
    }

    /// Returns a reference to the transaction’s key.
    pub fn key(&self) -> &Key {
        self.context.key()
    }
}

//------------ ServerSequence ------------------------------------------------

/// TSIG server sequence state.
///
/// This type allows to verify that a request has been correctly signed with
/// a known key and produce a sequence of answers to this request.
///
/// A sequence is created by giving a received message and a set of
/// acceptable keys to the [`request`][Self::request] function. It will
/// produce a server sequence value if the message was correctly signed with
/// any of keys.  Each answer message is then given to
/// [`answer`][Self::answer] to finalize it into a signed message.
///
/// Note that while the original [RFC 2845] allows a sequence of up to 99
/// intermediary messages not to be signed, this is in the process of being
/// deprecated. This implementation therefore signs each and every answer.
///
/// [RFC 2845]: https://tools.ietf.org/html/rfc2845
#[derive(Clone, Debug)]
pub struct ServerSequence<K> {
    /// A signing context to be used for the next signed answer.
    ///
    context: SigningContext<K>,

    /// Are we still waiting for the first answer?
    first: bool,
}

impl<K: AsRef<Key>> ServerSequence<K> {
    /// Creates a sequence from the request.
    ///
    /// The function checks whether the message carries exactly one TSIG
    /// record as the last record of the additional section. If this is the
    /// case, it removes the record form the message and checks whether it
    /// is correctly signing the request with any of the keys provided by
    /// the `store`. If that is the case, too, returns a server transaction.
    ///
    /// If the message did not have a TSIG record, returns `Ok(None)`
    /// indicating the lack of signing.
    ///
    /// If anything is wrong with the message with regards to TSIG, the
    /// function returns the error message that should be returned to the
    /// client as the error case of the result.
    #[allow(clippy::result_large_err)]
    pub fn request<Store, Octs>(
        store: &Store,
        message: &mut Message<Octs>,
        now: Time48,
    ) -> Result<Option<Self>, ServerError<K>>
    where
        Store: KeyStore<Key = K>,
        Octs: Octets + AsMut<[u8]>,
    {
        SigningContext::server_request(store, message, now).map(|context| {
            context.map(|context| ServerSequence {
                context,
                first: false,
            })
        })
    }

    /// Produces a signed answer.
    ///
    /// The method takes a message builder progressed into the additional
    /// section and signs it as the next answer in the sequence. To do so,
    /// it attempts to add a TSIG record to the additional section, if that
    /// fails because there wasn’t enough space in the builder, returns the
    /// unchanged builder as an error.
    pub fn answer<Target: Composer>(
        &mut self,
        message: &mut AdditionalBuilder<Target>,
        now: Time48,
    ) -> Result<(), PushError> {
        self.answer_with_fudge(message, now, 300)
    }

    /// Produces a signed answer with a given fudge.
    ///
    /// This is nearly identical to [`answer`][Self::answer] except that it
    /// allows to specify the ‘fudge’ which declares the number of seconds
    /// the receiver’s clock may be off from this systems current time.
    pub fn answer_with_fudge<Target>(
        &mut self,
        message: &mut AdditionalBuilder<Target>,
        now: Time48,
        fudge: u16,
    ) -> Result<(), PushError>
    where
        Target: Composer,
    {
        let variables = Variables::new(now, fudge, TsigRcode::NoError, None);
        let mac = if self.first {
            self.first = false;
            self.context
                .first_answer(message.as_slice(), None, &variables)
        } else {
            self.context.signed_subsequent(
                message.as_slice(),
                None,
                &variables,
            )
        };
        let mac = self.key().signature_slice(&mac);
        self.key().complete_message(message, &variables, mac)
    }

    /// Returns a reference to the transaction’s key.
    pub fn key(&self) -> &Key {
        self.context.key()
    }
}

//------------ SigningContext ------------------------------------------------

/// A TSIG signing context.
///
/// This is a thin wrapper around a ring signing context and a key providing
/// all the signing needs.
///
/// When signing answers, the signature of previous messages is being digested
/// as the first element. This type allows to do that right after having
/// generated or received the signature so that it doesn’t need to be kept
/// around.
///
/// The type is generic over a representation of a key so that you can use
/// arcs and whatnots here.
#[derive(Clone, Debug)]
struct SigningContext<K> {
    /// The ring signing context.
    context: hmac::Context,

    /// The key.
    ///
    /// It will be used as part of the complete TSIG variables as well as
    /// for creating new signing contexts.
    key: K,
}

impl<K: AsRef<Key>> SigningContext<K> {
    /// Checks the a request received by a server.
    ///
    /// This is the code that is shared by `ServerTransaction` and
    /// `ServerSequence`. It checks for a TSIG record and, if it is present,
    /// checks that the record signs the message with a key known to the
    /// store.
    ///
    /// Returns a signing context if there was a TSIG record and it was
    /// correctly signed with a known key. Returns `Ok(None)` if there was
    /// no TSIG record at all. Returns an error with a message to be returned
    /// to the client otherwise.
    #[allow(clippy::result_large_err)]
    fn server_request<Store, Octs>(
        store: &Store,
        message: &mut Message<Octs>,
        now: Time48,
    ) -> Result<Option<Self>, ServerError<Store::Key>>
    where
        Store: KeyStore<Key = K>,
        Octs: Octets + AsMut<[u8]>,
    {
        // 4.5 Server TSIG checks
        //
        // First, do we have a valid TSIG?
        let tsig = match MessageTsig::from_message(message) {
            Some(tsig) => tsig,
            None => return Ok(None),
        };

        // 4.5.1. KEY check and error handling
        let algorithm =
            match Algorithm::from_dname(tsig.record.data().algorithm()) {
                Some(algorithm) => algorithm,
                None => return Err(ServerError::unsigned(TsigRcode::BadKey)),
            };
        let key = match store.get_key(tsig.record.owner(), algorithm) {
            Some(key) => key,
            None => return Err(ServerError::unsigned(TsigRcode::BadKey)),
        };
        let variables = tsig.variables();

        // 4.5.3 MAC check
        //
        // Contrary to RFC 2845, this must be done before the time check.
        let mut header = message.header_section();
        header.header_mut().set_id(tsig.record.data().original_id());
        header.counts_mut().dec_arcount();
        let (mut context, signature) = Self::request(
            key,
            header.as_slice(),
            Some(
                &message.as_slice()
                    [mem::size_of::<HeaderSection>()..tsig.start],
            ),
            &variables,
        );
        let res = context.key.as_ref().compare_signatures(
            &signature,
            tsig.record.data().mac().as_ref(),
        );
        if let Err(err) = res {
            return Err(ServerError::unsigned(match err {
                ValidationError::BadTrunc => TsigRcode::BadTrunc,
                ValidationError::BadKey => TsigRcode::BadKey,
                _ => TsigRcode::FormErr,
            }));
        }

        // The signature is fine. Add it to the context for later.
        context.apply_signature(tsig.record.data().mac().as_ref());

        // 4.5.2 Time check
        //
        // Note that we are not doing the caching of the most recent
        // time_signed because, well, that’ll require mutexes and stuff.
        if !tsig.record.data().is_valid_at(now) {
            return Err(ServerError::signed(
                context,
                Variables::new(
                    variables.time_signed,
                    variables.fudge,
                    TsigRcode::BadTime,
                    Some(now),
                ),
            ));
        }
        remove_tsig(tsig.into_original_id(), message);
        Ok(Some(context))
    }

    /// Extracts the TSIG record from an anwer.
    ///
    /// This is the first part of the code shared by the various answer
    /// functions of `ClientTransaction` and `ClientSequence`. It does
    /// everything that needs to be done before actually verifying the
    /// signature: Find the TSIG record, handle unsigned errors, check
    /// that the key and algorithm correspond to our key and algorithm.
    ///
    /// Since there may be unsigned messages in client sequences, returns
    /// `Ok(None)` if there is no TSIG at all. Otherwise, if all steps
    /// succeed, returns the TSIG variables and the TSIG record. If there
    /// is an error, returns that.
    ///
    /// Because the returned TSIG record references the message, so it will
    /// later have to have the TSIG record stripped off and the ID updated.
    fn get_answer_tsig<'a, Octs>(
        &self,
        message: &'a Message<Octs>,
    ) -> Result<Option<MessageTsig<'a, Octs>>, ValidationError>
    where
        Octs: Octets,
    {
        // Extract TSIG or bail out.
        let tsig = match MessageTsig::from_message(message) {
            Some(tsig) => tsig,
            None => return Ok(None),
        };

        // Check for unsigned errors.
        if message.header().rcode() == Rcode::NotAuth {
            if tsig.record.data().error() == TsigRcode::BadKey {
                return Err(ValidationError::ServerBadKey);
            }
            if tsig.record.data().error() == TsigRcode::BadSig {
                return Err(ValidationError::ServerBadSig);
            }
        }

        // Check that the server used the correct key and algorithm.
        self.key().check_tsig(&tsig)?;

        Ok(Some(tsig))
    }

    /// Checks the timing values of an answer TSIG.
    ///
    /// This is the second part of the code shared between the various
    /// answer methods of `ClientTransaction` and `ClientSequence`. It
    /// checks for timing errors reported by the server as well as the
    /// time signed in the signature.
    fn check_answer_time<'a, Octs>(
        &self,
        message: &'a Message<Octs>,
        tsig: &MessageTsig<'a, Octs>,
        now: Time48,
    ) -> Result<(), ValidationError>
    where
        Octs: Octets,
    {
        if message.header().rcode() == Rcode::NotAuth
            && tsig.record.data().error() == TsigRcode::BadTime
        {
            let server = match tsig.record.data().other_time() {
                Some(time) => time,
                None => return Err(ValidationError::FormErr),
            };
            return Err(ValidationError::ServerBadTime {
                client: tsig.record.data().time_signed(),
                server,
            });
        }

        // Check the time.
        if !tsig.record.data().is_valid_at(now) {
            return Err(ValidationError::BadTime);
        }

        Ok(())
    }
}

impl<K: AsRef<Key>> SigningContext<K> {
    /// Creates a new signing context for the given key.
    fn new(key: K) -> Self {
        SigningContext {
            context: key.as_ref().signing_context(),
            key,
        }
    }

    /// Returns a references to the key that was used to create the context.
    fn key(&self) -> &Key {
        self.key.as_ref()
    }

    /// Applies a signature to the signing context.
    ///
    /// The `data` argument must be the actual signature that has already been
    /// truncated if that is required.
    ///
    /// Applies the length as a 16 bit big-endian unsigned followed by the
    /// actual octets.
    fn apply_signature(&mut self, data: &[u8]) {
        self.context.update(&(data.len() as u16).to_be_bytes());
        self.context.update(data);
    }

    /// Creates a signing context for a request.
    ///
    /// Takes a key, the octets of the message with the TSIG record already
    /// removed and the ID reset if necessary, and the TSIG variables from the
    /// TSIG record.
    ///
    /// Returns both a signing context and the full signature for this
    /// message.
    fn request(
        key: K,
        first: &[u8],
        second: Option<&[u8]>,
        variables: &Variables,
    ) -> (Self, hmac::Tag) {
        let mut context = key.as_ref().signing_context();
        context.update(first);
        if let Some(second) = second {
            context.update(second)
        }
        variables.sign(key.as_ref(), &mut context);
        let signature = context.sign();
        (Self::new(key), signature)
    }

    /// Signs an answer.
    ///
    /// Applies the message and variables only. The request signature has to
    /// have been applied already. Returns the signature for the answer.
    ///
    /// This happens on a clone of the original signing context. The context
    /// itself will _not_ change.
    fn answer(
        &self,
        first: &[u8],
        second: Option<&[u8]>,
        variables: &Variables,
    ) -> hmac::Tag {
        let mut context = self.context.clone();
        context.update(first);
        if let Some(second) = second {
            context.update(second)
        }
        variables.sign(self.key.as_ref(), &mut context);
        context.sign()
    }

    /// Signs an answer and drops the context.
    ///
    /// This is like `answer` above but it doesn’t need to clone the context.
    fn final_answer(
        mut self,
        first: &[u8],
        second: Option<&[u8]>,
        variables: &Variables,
    ) -> (hmac::Tag, K) {
        self.context.update(first);
        if let Some(second) = second {
            self.context.update(second)
        }
        variables.sign(self.key.as_ref(), &mut self.context);
        (self.context.sign(), self.key)
    }

    /// Signs the first answer in a sequence.
    ///
    /// This is like `answer` but it resets the context.
    fn first_answer(
        &mut self,
        first: &[u8],
        second: Option<&[u8]>,
        variables: &Variables,
    ) -> hmac::Tag {
        // Replace current context with new context.
        let mut context = self.key().signing_context();
        mem::swap(&mut self.context, &mut context);

        // Update the old context with message and variables, return signature
        context.update(first);
        if let Some(second) = second {
            context.update(second)
        }
        variables.sign(self.key.as_ref(), &mut context);
        context.sign()
    }

    /// Applies the content of an unsigned message to the context.
    fn unsigned_subsequent(&mut self, message: &[u8]) {
        self.context.update(message)
    }

    /// Signs a subsequent message.
    ///
    /// Resets the context.
    fn signed_subsequent(
        &mut self,
        first: &[u8],
        second: Option<&[u8]>,
        variables: &Variables,
    ) -> hmac::Tag {
        // Replace current context with new context.
        let mut context = self.key().signing_context();
        mem::swap(&mut self.context, &mut context);

        // Update the old context with message and timers, return signature
        context.update(first);
        if let Some(second) = second {
            context.update(second)
        }
        variables.sign_timers(&mut context);
        context.sign()
    }
}

//------------ MessageTsig ---------------------------------------------------

/// The TSIG record of a message.
struct MessageTsig<'a, Octs: Octets + 'a> {
    /// The actual record.
    #[allow(clippy::type_complexity)]
    record: Record<
        ParsedDname<Octs::Range<'a>>,
        Tsig<Octs::Range<'a>, ParsedDname<Octs::Range<'a>>>,
    >,

    /// The index of the start of the record.
    start: usize,
}

impl<'a, Octs: Octets> MessageTsig<'a, Octs> {
    /// Get the TSIG record from a message.
    ///
    /// Checks that there is exactly one TSIG record in the additional
    /// section, that it is the last record in this section. If that is true,
    /// returns the parsed TSIG records.
    fn from_message(msg: &'a Message<Octs>) -> Option<Self> {
        let mut section = msg.additional().ok()?;
        let mut start = section.pos();
        let mut record = section.next()?;
        loop {
            record = match section.next() {
                Some(record) => record,
                None => break,
            };
            start = section.pos();
        }
        record
            .ok()?
            .into_record::<Tsig<_, _>>()
            .ok()?
            .map(|record| MessageTsig { record, start })
    }

    fn variables(&self) -> Variables {
        Variables::new(
            self.record.data().time_signed(),
            self.record.data().fudge(),
            self.record.data().error(),
            self.record.data().other_time(),
        )
    }

    fn into_original_id(self) -> u16 {
        self.record.data().original_id()
    }
}

//------------ Variables -----------------------------------------------------

/// The TSIG Variables.
///
/// This type keeps some of the variables that are added when calculating the
/// signature. This isn’t all the variables used, though. The remaining ones
/// are related to the key and are kept with the signing context.
#[derive(Clone, Debug)]
struct Variables {
    /// The time the signature in question was created.
    time_signed: Time48,

    /// The infamous fudge.
    fudge: u16,

    /// The TSIG error code.
    error: TsigRcode,

    /// The content of the ‘other’ field.
    ///
    /// According to the RFC, the only allowed value for this field is a
    /// time stamp. So we keep this as an optional time value.
    other: Option<Time48>,
}

impl Variables {
    /// Creates a new value from the parts.
    fn new(
        time_signed: Time48,
        fudge: u16,
        error: TsigRcode,
        other: Option<Time48>,
    ) -> Self {
        Variables {
            time_signed,
            fudge,
            error,
            other,
        }
    }

    /// Produces a TSIG record from this value and some more data.
    fn push_tsig<Target: Composer>(
        &self,
        key: &Key,
        hmac: &[u8],
        original_id: u16,
        builder: &mut AdditionalBuilder<Target>,
    ) -> Result<(), PushError> {
        let other = self.other.map(Time48::into_octets);
        let other = match other {
            Some(ref time) => time.as_ref(),
            None => b"",
        };
        builder.push((
            key.name.clone(),
            Class::Any,
            0,
            // The only reason creating TSIG record data can fail here is
            // that the hmac is unreasonable large. Since we control its
            // creation, panicing in this case is fine.
            Tsig::new(
                key.algorithm().to_dname(),
                self.time_signed,
                self.fudge,
                hmac,
                original_id,
                self.error,
                other,
            )
            .expect("long MAC"),
        ))
    }

    /// Applies the variables to a signing context.
    ///
    /// This applies the full variables including key information.
    fn sign(&self, key: &Key, context: &mut hmac::Context) {
        // Key name, in canonical wire format
        for label in key.name.iter_labels().map(Label::to_canonical) {
            context.update(label.as_wire_slice());
        }
        // CLASS (Always ANY in the current specification)
        context.update(&Class::Any.to_int().to_be_bytes());
        // TTL (Always 0 in the current specification)
        context.update(&0u32.to_be_bytes());
        // Algorithm Name (in canonical wire format)
        context.update(key.algorithm().into_wire_slice());
        // Time Signed
        context.update(&self.time_signed.into_octets());
        // Fudge
        context.update(&self.fudge.to_be_bytes());
        // Error
        context.update(&self.error.to_int().to_be_bytes());
        // Other Len
        if self.other.is_some() {
            context.update(&6u16.to_be_bytes());
        } else {
            context.update(&0u16.to_be_bytes());
        }
        // Other
        if let Some(time) = self.other {
            context.update(&u64::from(time).to_be_bytes());
        }
    }

    /// Applies only the timing values to the signing context.
    fn sign_timers(&self, context: &mut hmac::Context) {
        // Time Signed
        context.update(&self.time_signed.into_octets());

        // Fudge
        context.update(&self.fudge.to_be_bytes());
    }
}

//------------ Algorithm -----------------------------------------------------

/// The supported TSIG algorithms.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    /// Creates a value from its domain name representation.
    ///
    /// Returns `None` if the name doesn’t represent a known algorithm.
    pub fn from_dname<N: ToDname>(name: &N) -> Option<Self> {
        let mut labels = name.iter_labels();
        let first = match labels.next() {
            Some(label) => label,
            None => return None,
        };
        match labels.next() {
            Some(label) if label.is_root() => {}
            _ => return None,
        }
        match first.as_slice() {
            b"hmac-sha1" => Some(Algorithm::Sha1),
            b"hmac-sha256" => Some(Algorithm::Sha256),
            b"hmac-sha384" => Some(Algorithm::Sha384),
            b"hmac-sha512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }

    /// Creates a value from a HMAC algorithm.
    ///
    /// This will panic if `alg` is not one of the recognized algorithms.
    fn from_hmac_algorithm(alg: hmac::Algorithm) -> Self {
        if alg == hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY {
            Algorithm::Sha1
        } else if alg == hmac::HMAC_SHA256 {
            Algorithm::Sha256
        } else if alg == hmac::HMAC_SHA384 {
            Algorithm::Sha384
        } else if alg == hmac::HMAC_SHA512 {
            Algorithm::Sha512
        } else {
            panic!("Unknown TSIG key algorithm.")
        }
    }

    /// Returns the ring HMAC algorithm for this TSIG algorithm.
    fn into_hmac_algorithm(self) -> hmac::Algorithm {
        match self {
            Algorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::Sha256 => hmac::HMAC_SHA256,
            Algorithm::Sha384 => hmac::HMAC_SHA384,
            Algorithm::Sha512 => hmac::HMAC_SHA512,
        }
    }

    /// Returns a octet slice with the wire-format domain name for this value.
    fn into_wire_slice(self) -> &'static [u8] {
        match self {
            Algorithm::Sha1 => b"\x09hmac-sha1\0",
            Algorithm::Sha256 => b"\x0Bhmac-sha256\0",
            Algorithm::Sha384 => b"\x0Bhmac-sha384\0",
            Algorithm::Sha512 => b"\x0Bhmac-sha512\0",
        }
    }

    /// Returns a domain name for this value.
    pub fn to_dname(self) -> Dname<&'static [u8]> {
        unsafe { Dname::from_octets_unchecked(self.into_wire_slice()) }
    }

    /// Returns the native length of a signature created with this algorithm.
    pub fn native_len(self) -> usize {
        self.into_hmac_algorithm().len()
    }

    /// Returns the bounds for the allowed signature size.
    pub fn within_len_bounds(self, len: usize) -> bool {
        len >= cmp::max(10, self.native_len() / 2) && len <= self.native_len()
    }
}

//--- FromStr

impl str::FromStr for Algorithm {
    type Err = AlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hmac-sha1" => Ok(Algorithm::Sha1),
            "hmac-sha256" => Ok(Algorithm::Sha256),
            "hmac-sha384" => Ok(Algorithm::Sha384),
            "hmac-sha512" => Ok(Algorithm::Sha512),
            _ => Err(AlgorithmError),
        }
    }
}

//--- Display

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Algorithm::Sha1 => "hmac-sha1",
                Algorithm::Sha256 => "hmac-sha256",
                Algorithm::Sha384 => "hmac-sha384",
                Algorithm::Sha512 => "hmac-sha512",
            }
        )
    }
}

//------------ Helper Functions ----------------------------------------------

fn remove_tsig<Octs>(original_id: u16, message: &mut Message<Octs>)
where
    Octs: Octets + AsMut<[u8]>,
{
    message.header_mut().set_id(original_id);
    message.remove_last_additional();
}

//============ Error Types ===================================================

//------------ ServerError ---------------------------------------------------

/// A TSIG record of a received request couldn’t be validated.
///
/// A value of this type carries all information necessary to produce the
/// error response to be send back to the client.
#[derive(Clone)]
pub struct ServerError<K>(ServerErrorInner<K>);

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum ServerErrorInner<K> {
    /// Return an unsigned error message.
    ///
    /// To crate the actual message, we need the original message with the
    /// TSIG intact as the last additional record.
    Unsigned { error: TsigRcode },

    /// Return a signed error message.
    Signed {
        context: SigningContext<K>,
        variables: Variables,
    },
}

impl<K> ServerError<K> {
    fn unsigned(error: TsigRcode) -> Self {
        ServerError(ServerErrorInner::Unsigned { error })
    }

    fn signed(context: SigningContext<K>, variables: Variables) -> Self {
        ServerError(ServerErrorInner::Signed { context, variables })
    }

    pub fn error(&self) -> TsigRcode {
        match self.0 {
            ServerErrorInner::Unsigned { error } => error,
            ServerErrorInner::Signed { ref variables, .. } => variables.error,
        }
    }
}

impl<K: AsRef<Key>> ServerError<K> {
    pub fn build_message<Octs, Target>(
        self,
        msg: &Message<Octs>,
        builder: MessageBuilder<Target>,
    ) -> Result<AdditionalBuilder<Target>, PushError>
    where
        Octs: Octets,
        Target: Composer,
    {
        let builder = builder.start_answer(msg, Rcode::NotAuth)?;
        let mut builder = builder.additional();
        match self.0 {
            ServerErrorInner::Unsigned { error } => {
                let tsig = {
                    MessageTsig::from_message(msg)
                        .expect("missing or malformed TSIG record")
                };
                builder.push((
                    tsig.record.owner(),
                    tsig.record.class(),
                    tsig.record.ttl(),
                    // The TSIG record data can never ever be to long.
                    Tsig::new(
                        tsig.record.data().algorithm(),
                        tsig.record.data().time_signed(),
                        tsig.record.data().fudge(),
                        b"",
                        msg.header().id(),
                        error,
                        b"",
                    )
                    .expect("long record data"),
                ))?;
            }
            ServerErrorInner::Signed { context, variables } => {
                let (mac, key) = context.final_answer(
                    builder.as_slice(),
                    None,
                    &variables,
                );
                let mac = key.as_ref().signature_slice(&mac);
                key.as_ref().complete_message(
                    &mut builder,
                    &variables,
                    mac,
                )?;
            }
        }
        Ok(builder)
    }
}

//--- Debug, Display, and Error

impl<K> fmt::Debug for ServerError<K> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ServerError").field(&self.0).finish()
    }
}

impl<K> fmt::Debug for ServerErrorInner<K> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ServerErrorInner::Unsigned { error } => {
                f.debug_struct("Unsigned").field("error", &error).finish()
            }
            ServerErrorInner::Signed { ref variables, .. } => f
                .debug_struct("Signed")
                .field("variables", variables)
                .finish(),
        }
    }
}

impl<K> fmt::Display for ServerError<K> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.error().fmt(f)
    }
}

#[cfg(feature = "std")]
impl<K> std::error::Error for ServerError<K> {}

//------------ NewKeyError ---------------------------------------------------

/// A key couldn’t be created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NewKeyError {
    BadMinMacLen,
    BadSigningLen,
}

//--- Display and Error

impl fmt::Display for NewKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NewKeyError::BadMinMacLen => {
                f.write_str("minimum signature length out of bounds")
            }
            NewKeyError::BadSigningLen => {
                f.write_str("created signature length out of bounds")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NewKeyError {}

//------------ GenerateKeyError ----------------------------------------------

/// A key couldn’t be created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerateKeyError {
    BadMinMacLen,
    BadSigningLen,
    GenerationFailed,
}

//--- From

impl From<NewKeyError> for GenerateKeyError {
    fn from(err: NewKeyError) -> Self {
        match err {
            NewKeyError::BadMinMacLen => GenerateKeyError::BadMinMacLen,
            NewKeyError::BadSigningLen => GenerateKeyError::BadSigningLen,
        }
    }
}

impl From<ring::error::Unspecified> for GenerateKeyError {
    fn from(_: ring::error::Unspecified) -> Self {
        GenerateKeyError::GenerationFailed
    }
}

//--- Display and Error

impl fmt::Display for GenerateKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GenerateKeyError::BadMinMacLen => {
                f.write_str("minimum signature length out of bounds")
            }
            GenerateKeyError::BadSigningLen => {
                f.write_str("created signature length out of bounds")
            }
            GenerateKeyError::GenerationFailed => {
                f.write_str("generating key failed")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GenerateKeyError {}

//------------ AlgorithmError ------------------------------------------------

/// An invalid algorithm was provided.
#[derive(Clone, Copy, Debug)]
pub struct AlgorithmError;

//--- Display and Error

impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid algorithm")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AlgorithmError {}

//------------ ValidationError -----------------------------------------------

/// An error happened while validating a TSIG-signed message.
#[derive(Clone, Copy, Debug)]
pub enum ValidationError {
    BadAlg,
    BadOther,
    BadSig,
    BadTrunc,
    BadKey,
    BadTime,
    FormErr,
    ServerUnsigned,
    ServerBadKey,
    ServerBadSig,
    ServerBadTime { client: Time48, server: Time48 },
    TooManyUnsigned,
}

//--- From

impl From<ParseError> for ValidationError {
    fn from(_: ParseError) -> Self {
        ValidationError::FormErr
    }
}

//--- Display and Error

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ValidationError::BadAlg => f.write_str("unknown algorithm"),
            ValidationError::BadOther => {
                f.write_str("bad content of 'other' field")
            }
            ValidationError::BadSig => f.write_str("bad signature"),
            ValidationError::BadTrunc => f.write_str("short signature"),
            ValidationError::BadKey => f.write_str("unknown key"),
            ValidationError::BadTime => f.write_str("bad time"),
            ValidationError::FormErr => f.write_str("format error"),
            ValidationError::ServerUnsigned => f.write_str("unsigned answer"),
            ValidationError::ServerBadKey => {
                f.write_str("unknown key on server")
            }
            ValidationError::ServerBadSig => {
                f.write_str("server failed to verify MAC")
            }
            ValidationError::ServerBadTime { .. } => {
                f.write_str("server reported bad time")
            }
            ValidationError::TooManyUnsigned => {
                f.write_str("too many unsigned messages")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {}
