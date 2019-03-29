//! Support for TSIG.

use std::{cmp, fmt, mem, str};
use std::collections::HashMap;
use std::sync::Arc;
use bytes::{BigEndian, ByteOrder, Bytes, BytesMut};
use ring::{constant_time, digest, hmac, rand};
use crate::bits::message::Message;
use crate::bits::message_builder::{
    AdditionalBuilder, MessageBuilder, SectionBuilder, RecordSectionBuilder
};
use crate::bits::name::{
    Dname, Label, ParsedDname, ParsedDnameError, ToDname, ToLabelIter
};
use crate::bits::parse::ShortBuf;
use crate::bits::record::Record;
use crate::iana::{Class, Rcode, TsigRcode};
use crate::rdata::rfc2845::{Time48, Tsig};


//------------ Key -----------------------------------------------------------

/// A key for creating TSIG signatures.
#[derive(Debug)]
pub struct Key {
    /// The key’s bits and algorithm.
    key: hmac::SigningKey,

    /// The name of the key as a domain name.
    name: Dname,

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
        name: Dname,
        min_mac_len: Option<usize>,
        signing_len: Option<usize>
    ) -> Result<Self, NewKeyError> {
        let (min_mac_len, signing_len) = Self::calculate_bounds(
            algorithm, min_mac_len, signing_len
        )?;
        Ok(Key {
            key: hmac::SigningKey::new(algorithm.into_digest_algorithm(), key),
            name,
            min_mac_len,
            signing_len
        })
    }

    /// Generates a new signing key.
    ///
    /// This is similar to [`new`] but generates the bits for the key from the
    /// given `rng`. It returns both the key and bits for storage.
    ///
    /// [`new`]: #method.new
    pub fn generate(
        algorithm: Algorithm,
        rng: &dyn rand::SecureRandom,
        name: Dname,
        min_mac_len: Option<usize>,
        signing_len: Option<usize>
    ) -> Result<(Self, Bytes), GenerateKeyError> {
        let (min_mac_len, signing_len) = Self::calculate_bounds(
            algorithm, min_mac_len, signing_len
        )?;
        let algorithm = algorithm.into_digest_algorithm();
        let key_len = hmac::recommended_key_len(algorithm);
        let mut bytes = BytesMut::with_capacity(key_len);
        bytes.resize(key_len, 0);
        let key = Key {
            key: hmac::SigningKey::generate_serializable(
                algorithm, rng, bytes.as_mut()
            )?,
            name,
            min_mac_len,
            signing_len
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
        signing_len: Option<usize>
    ) -> Result<(usize, usize), NewKeyError> {
        let min_mac_len = match min_mac_len {
            Some(len) => {
                if !algorithm.within_len_bounds(len) {
                    return Err(NewKeyError::BadMinMacLen)
                }
                len
            }
            None => algorithm.native_len()
        };
        let signing_len = match signing_len {
            Some(len) => {
                if !algorithm.within_len_bounds(len) {
                    return Err(NewKeyError::BadSigningLen)
                }
                len
            }
            None => algorithm.native_len()
        };
        Ok((min_mac_len, signing_len))
    }

    /// Creates a signing context for this key.
    fn signing_context(&self) -> hmac::SigningContext {
        hmac::SigningContext::with_key(&self.key)
    }

    /// Returns a the possibly truncated slice of the signature.
    fn signature_slice<'a>(&self, signature: &'a hmac::Signature) -> &'a [u8] {
        &signature.as_ref()[..self.signing_len]
    }
}


/// # Access to Properties
///
impl Key {
    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::from_digest_algorithm(self.key.digest_algorithm())
    }

    /// Returns a reference to the name of this key.
    pub fn name(&self) -> &Dname {
        &self.name
    }

    /// Returns the native length of the signature from this key.
    pub fn native_len(&self) -> usize {
        self.key.digest_algorithm().output_len
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
    fn check_tsig(
        &self, tsig: &Record<ParsedDname, Tsig<Dname>>
    ) -> Result<(), ValidationError> {
        if *tsig.owner() != self.name
            || *tsig.data().algorithm() != self.algorithm().to_dname() 
        {
            Err(ValidationError::BadKey)
        }
        else {
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
        expected: &hmac::Signature,
        provided: &[u8],
    ) -> Result<(), ValidationError> {
        if provided.len() < self.min_mac_len {
            return Err(ValidationError::BadTrunc)
        }
        let expected = if provided.len() < expected.as_ref().len() {
            &expected.as_ref()[..provided.len()]
        }
        else {
            expected.as_ref()
        };
        constant_time::verify_slices_are_equal(expected, provided.as_ref())
            .map_err(|_| ValidationError::BadSig)
    }

    fn complete_message(
        &self,
        mut message: AdditionalBuilder,
        variables: &Variables,
        mac: &[u8],
    ) -> Result<Message, AdditionalBuilder> {
        let id = message.header().id();
        match message.push(variables.to_tsig(self, mac, id)) {
            Ok(()) => Ok(message.freeze()),
            Err(_) => Err(message)
        }
    }

}


//--- AsRef

impl AsRef<Key> for Key {
    fn as_ref(&self) -> &Self {
        self
    }
}


//------------ KeyStore ------------------------------------------------------

/// A type that stores TSIG secrets.
pub trait KeyStore {
    type Key: AsRef<Key>;

    fn get_key<N: ToDname>(
        &self, name: &N, algorithm: Algorithm
    ) -> Option<Self::Key>;
}

impl<'a> KeyStore for &'a Key {
    type Key = &'a Key;

    fn get_key<N: ToDname>(
        &self, name: &N, algorithm: Algorithm
    ) -> Option<Self::Key> {
        if self.name() == name && self.algorithm() == algorithm {
            Some(*self)
        }
        else {
            None
        }
    }
}

impl KeyStore for HashMap<(Dname, Algorithm), Arc<Key>> {
    type Key = Arc<Key>;

    fn get_key<N: ToDname>(
        &self, name: &N, algorithm: Algorithm
    ) -> Option<Self::Key> {
        let name = name.to_name(); // XXX This seems a bit wasteful.
        self.get(&(name, algorithm)).cloned()
    }
}


//------------ ClientTransaction ---------------------------------------------

/// TSIG Client Transaction State.
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
    pub fn request(
        key: K, message: AdditionalBuilder
    ) -> Result<(Message, Self), AdditionalBuilder> {
        Self::request_with_fudge(key, message, 300)
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
    pub fn request_with_fudge(
        key: K, message: AdditionalBuilder, fudge: u16
    ) -> Result<(Message, Self), AdditionalBuilder> {
        let variables = Variables::new(
            Time48::now(), fudge, TsigRcode::NoError, None
        );
        let (mut context, mac) = SigningContext::request(
            key, message.so_far(), &variables
        );
        let mac = context.key().signature_slice(&mac);
        context.apply_signature(mac);
        context.key().complete_message(message, &variables, mac).map(|message| {
            (message, ClientTransaction { context })
        })
    }

    /// Validates an answer.
    ///
    /// Takes a message and checks whether it was correctly signed for the
    /// original request. If that is indeed the case, takes the TSIG record
    /// out of the message. Otherwise, returns a validation error.
    pub fn answer(
        &self, message: &mut Message
    ) -> Result<(), ValidationError> {
        let (variables, tsig) = match self.context.extract_answer_tsig(
                                                                   message)? {
            Some(some) => some,
            None => return Err(ValidationError::ServerUnsigned)
        };

        let signature = self.context.answer(
            message.as_slice(), &variables
        );
        self.context.key().compare_signatures(
            &signature, tsig.data().mac().as_ref()
        )?;
        self.context.check_answer_time(message, &tsig)?;
        Ok(())
    }

    /// Returns a reference to the transaction’s key.
    pub fn key(&self) -> &Key {
        self.context.key()
    }
}


//------------ ServerTransaction ---------------------------------------------

/// TSIG Server Transaction State.
#[derive(Clone, Debug)]
pub struct ServerTransaction<K> {
    context: SigningContext<K>,
}

impl<K: AsRef<Key>> ServerTransaction<K> {
    /// Creates a transaction for a request.
    ///
    pub fn request<S: KeyStore<Key=K>>(
        store: &S,
        message: Message
    ) -> Result<(Message, Option<Self>), Message> {
        SigningContext::server_request(
            store, message
        ).map(|(message, context)| {
            (message, context.map(|context| ServerTransaction { context }))
        })
    }

    /// Produces a signed answer.
    pub fn answer(
        self, message: AdditionalBuilder
    ) -> Result<Message, ShortBuf> {
        self.answer_with_fudge(message, 300)
    }

    /// Produces a signed answer with a given fudge.
    pub fn answer_with_fudge(
        self,
        message: AdditionalBuilder,
        fudge: u16
    ) -> Result<Message, ShortBuf> {
        let variables = Variables::new(
            Time48::now(), fudge, TsigRcode::NoError, None
        );
        let (mac, key) = self.context.final_answer(
            message.so_far(), &variables
        );
        let mac = key.as_ref().signature_slice(&mac);
        key.as_ref().complete_message(message, &variables, mac)
            .map_err(|_| ShortBuf)
    }

    /// Returns a reference to the transaction’s key.
    pub fn key(&self) -> &Key {
        self.context.key()
    }
}


//------------ ClientSequence ------------------------------------------------

/// TSIG client sequence state.
#[derive(Clone, Debug)]
pub struct ClientSequence<K> {
    /// A signing context to be used for the next signed answer.
    context: SigningContext<K>,

    /// Are we still waiting for the first answer?
    first: bool,

    /// How many unsigned answers have we seen yet?
    unsigned: usize,
}

impl<K: AsRef<Key>> ClientSequence<K> {
    /// Creates a sequence for a request.
    pub fn request(
        key: K, message: AdditionalBuilder
    ) -> Result<(Message, Self), AdditionalBuilder> {
        Self::request_with_fudge(key, message, 300)
    }

    /// Creates a sequence for a request with a specific fudge.
    pub fn request_with_fudge(
        key: K, message: AdditionalBuilder, fudge: u16
    ) -> Result<(Message, Self), AdditionalBuilder> {
        let variables = Variables::new(
            Time48::now(), fudge, TsigRcode::NoError, None
        );
        let (mut context, mac) = SigningContext::request(
            key, message.so_far(), &variables
        );
        let mac = context.key().signature_slice(&mac);
        context.apply_signature(mac);
        context.key().complete_message(message, &variables, mac).map(|message| {
            (message, ClientSequence { context, first: true, unsigned: 0 })
        })
    }

    /// Validates an answer.
    pub fn answer(
        &mut self,
        message: &mut Message
    ) -> Result<(), ValidationError> {
        if self.first {
            self.answer_first(message)
        }
        else {
            self.answer_subsequent(message)
        }
    }

    /// Validates the end of the sequence
    pub fn done(self) -> Result<(), ValidationError> {
        // The last message must be signed, so the counter must be 0 here.
        if self.unsigned != 0 {
            Err(ValidationError::TooManyUnsigned)
        }
        else {
            Ok(())
        }
    }

    fn answer_first(
        &mut self,
        message: &mut Message
    ) -> Result<(), ValidationError> {
        let (variables, tsig) = match self.context.extract_answer_tsig(
                                                                   message)? {
            Some(some) => some,
            None => return Err(ValidationError::ServerUnsigned)
        };

        let signature = self.context.first_answer(
            message.as_slice(), &variables
        );
        self.context.key().compare_signatures(
            &signature, tsig.data().mac().as_ref()
        )?;
        self.context.apply_signature(tsig.data().mac().as_ref());
        self.context.check_answer_time(message, &tsig)?;
        self.first = false;
        Ok(())
    }

    fn answer_subsequent(
        &mut self,
        message: &mut Message,
    ) -> Result<(), ValidationError> {
        match self.context.extract_answer_tsig(message)? {
            Some((variables, tsig)) => {
                // Check the MAC.
                let signature = self.context.signed_subsequent(
                    message.as_slice(), &variables
                );
                self.context.key().compare_signatures(
                    &signature, tsig.data().mac().as_ref()
                )?;
                self.context.apply_signature(tsig.data().mac().as_ref());
                self.context.check_answer_time(message, &tsig)?;
                self.unsigned = 0;
                Ok(())
            }
            None => {
                if self.unsigned < 99 {
                    self.context.unsigned_subsequent(message.as_slice());
                    self.unsigned += 1;
                    Ok(())
                }
                else {
                    Err(ValidationError::TooManyUnsigned)
                }
            }
        }
    }

    /// Returns a reference to the transaction’s key.
    pub fn key(&self) -> &Key {
        self.context.key()
    }
}


//------------ ServerSequence ------------------------------------------------

/// TSIG server sequence state.
///
/// As requested by the updated RFC, we sign each and every message.
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
    pub fn request<S: KeyStore<Key=K>>(
        store: &S,
        message: Message
    ) -> Result<(Message, Option<Self>), Message> {
        SigningContext::server_request(
            store, message
        ).map(|(message, context)| {
            (message, context.map(|context| {
                ServerSequence { context, first: false }
            }))
        })
    }

    /// Produces a signed answer.
    pub fn answer(
        &mut self, message: AdditionalBuilder
    ) -> Result<Message, ShortBuf> {
        self.answer_with_fudge(message, 300)
    }

    /// Produces a signed answer with a given fudge.
    pub fn answer_with_fudge(
        &mut self,
        message: AdditionalBuilder,
        fudge: u16
    ) -> Result<Message, ShortBuf> {
        let variables = Variables::new(
            Time48::now(), fudge, TsigRcode::NoError, None
        );
        let mac = if self.first {
            self.first = false;
            self.context.first_answer(message.so_far(), &variables)
        }
        else {
            self.context.signed_subsequent(message.so_far(), &variables)
        };
        let mac = self.key().signature_slice(&mac);
        self.key().complete_message(message, &variables, mac)
            .map_err(|_| ShortBuf)
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
#[derive(Clone, Debug)]
struct SigningContext<K> {
    /// The ring signing context.
    context: hmac::SigningContext,

    /// The key.
    ///
    /// It will be used as part of the complete TSIG variables as well as
    /// for creating new signing contexts.
    key: K,
}

impl<K: AsRef<Key>> SigningContext<K> {
    fn server_request<S: KeyStore<Key=K>>(
        store: &S,
        mut message: Message
    ) -> Result<(Message, Option<Self>), Message> {
        // 4.5 Server TSIG checks
        //
        // First, do we have a valid TSIG?
        let tsig = match extract_tsig(&mut message) {
            Some(tsig) => tsig,
            None => return Ok((message, None))
        };

        // 4.5.1. KEY check and error handling
        let algorithm = match Algorithm::from_dname(tsig.data().algorithm()) {
            Some(algorithm) => algorithm,
            None => {
                return Err(
                    Self::unsigned_error(&message, &tsig, TsigRcode::BadKey)
                )
            }
        };
        let key = match store.get_key(tsig.owner(), algorithm) {
            Some(key) => key,
            None => {
                return Err(
                    Self::unsigned_error(&message, &tsig, TsigRcode::BadKey)
                )
            }
        };
        let variables = Variables::from_tsig(&tsig);

        // 4.5.3 MAC check
        //
        // Contrary to RFC 2845, this must be done before the time check.
        update_id(&mut message, &tsig);
        let (mut context, signature) = Self::request(
            key, message.as_slice(), &variables
        );
        let res = context.key.as_ref().compare_signatures(
            &signature,
            tsig.data().mac().as_ref()
        );
        if let Err(err) = res {
            return Err(Self::unsigned_error(&message, &tsig, match err {
                ValidationError::BadTrunc => TsigRcode::BadTrunc,
                ValidationError::BadKey => TsigRcode::BadKey,
                _ => TsigRcode::FormErr,
            }))
        }

        // The signature is fine. Add it to the context for later.
        context.apply_signature(tsig.data().mac().as_ref());

        // 4.5.2 Time check
        //
        // Note that we are not doing the caching of the most recent
        // time_signed because, well, that’ll require mutexes and stuff.
        if !tsig.data().is_valid_now() {
            let mut response = MessageBuilder::new_udp();
            response.start_answer(&message, Rcode::NotAuth);
            return Err(
                // unwrap: answer should always fit.
                context.signed_error(
                    response.additional(),
                    &Variables::new(
                        variables.time_signed,
                        variables.fudge,
                        TsigRcode::BadTime,
                        Some(Time48::now())
                    )
                )
            )
        }

        Ok((message, Some(context)))
    }

    fn extract_answer_tsig(
        &self,
        message: &mut Message
    ) -> Result<
            Option<(Variables, Record<ParsedDname, Tsig<Dname>>)>,
            ValidationError
         >
    {
        // Extact TSIG or bail out.
        let tsig = match extract_tsig(message) {
            Some(tsig) => tsig,
            None => return Ok(None)
        };

        // Check for unsigned errors.
        if message.header().rcode() == Rcode::NotAuth {
            if tsig.data().error() == TsigRcode::BadKey {
                return Err(ValidationError::ServerBadKey)
            }
            if tsig.data().error() == TsigRcode::BadSig {
                return Err(ValidationError::ServerBadSig)
            }
        }

        // Check that the server used the correct key and algorithm.
        self.key().check_tsig(&tsig)?;

        // Fix up message and return.
        update_id(message, &tsig);
        Ok(Some((Variables::from_tsig(&tsig), tsig)))
    }

    fn check_answer_time(
        &self,
        message: &Message,
        tsig: &Record<ParsedDname, Tsig<Dname>>
    ) -> Result<(), ValidationError> {
        if message.header().rcode() == Rcode::NotAuth
            && tsig.data().error() == TsigRcode::BadTime
        {
            let server = match tsig.data().other_time() {
                Some(time) => time,
                None => return Err(ValidationError::FormErr)
            };
            return Err(ValidationError::ServerBadTime {
                client: tsig.data().time_signed(), server
            })
        }

        // Check the time.
        if !tsig.data().is_valid_now() {
            return Err(ValidationError::BadTime)
        }

        Ok(())
    }
}

impl<K: AsRef<Key>> SigningContext<K> {
    fn new(key: K) -> Self {
        SigningContext {
            context: key.as_ref().signing_context(),
            key
        }
    }

    fn key(&self) -> &Key {
        self.key.as_ref()
    }

    fn apply_signature(&mut self, data: &[u8]) {
        let mut buf = [0u8; 2];
        BigEndian::write_u16(&mut buf, data.len() as u16);
        self.context.update(&buf);
        self.context.update(data);
    }

    fn request(
        key: K,
        message: &[u8],
        variables: &Variables
    ) -> (Self, hmac::Signature) {
        let mut context = key.as_ref().signing_context();
        context.update(message);
        variables.sign(key.as_ref(), &mut context);
        let signature = context.sign();
        (Self::new(key), signature)
    }

    fn answer(
        &self,
        message: &[u8],
        variables: &Variables
    ) -> hmac::Signature {
        let mut context = self.context.clone();
        context.update(message);
        variables.sign(self.key.as_ref(), &mut context);
        context.sign()
    }

    fn final_answer(
        mut self,
        message: &[u8],
        variables: &Variables
    ) -> (hmac::Signature, K) {
        self.context.update(message);
        variables.sign(self.key.as_ref(), &mut self.context);
        (self.context.sign(), self.key)
    }

    fn first_answer(
        &mut self,
        message: &[u8],
        variables: &Variables
    ) -> hmac::Signature {
        // Replace current context with new context.
        let mut context = self.key().signing_context();
        mem::swap(&mut self.context, &mut context);

        // Update the old context with message and variables, create signature
        context.update(message);
        variables.sign(self.key.as_ref(), &mut context);
        let signature = context.sign();

        // Update new context with the signature and then return it.
        //self.context.update(signature.as_ref());
        signature
    }

    fn unsigned_subsequent(
        &mut self,
        message: &[u8]
    ) {
        self.context.update(message)
    }

    fn signed_subsequent(
        &mut self,
        message: &[u8],
        variables: &Variables
    ) -> hmac::Signature {
        // Replace current context with new context.
        let mut context = self.key().signing_context();
        mem::swap(&mut self.context, &mut context);

        // Update the old context with message and timers, create signature
        context.update(message);
        variables.sign_timers(&mut context);
        let signature = context.sign();

        // Update new context with the signature and then return it.
        //self.context.update(signature.as_ref());
        signature
    }

    fn unsigned_error(
        msg: &Message,
        tsig: &Record<ParsedDname, Tsig<Dname>>,
        error: TsigRcode
    ) -> Message {
        let mut res = MessageBuilder::new_udp();
        res.start_answer(msg, Rcode::NotAuth);
        let mut res = res.additional();
        res.push((
            tsig.owner(), tsig.class(), tsig.ttl(),
            Tsig::new(
                tsig.data().algorithm(),
                tsig.data().time_signed(),
                tsig.data().fudge(),
                Bytes::new(),
                msg.header().id(),
                error,
                Bytes::new()
            )
        )).unwrap();
        res.freeze()
    }

    fn signed_error(
        self,
        message: AdditionalBuilder,
        variables: &Variables,
    ) -> Message {
        let (mac, key) = self.final_answer(message.so_far(), variables);
        let mac = key.as_ref().signature_slice(&mac);
        key.as_ref().complete_message(message, variables, mac).unwrap()
    }
}


//------------ Variables -----------------------------------------------------

/// The TSIG Variables.
///
/// All parts of the future TSIG record that are not the actual MAC are used
/// as input for MAC generation. This type keeps those that are indeed
/// variable.
#[derive(Clone, Debug)]
struct Variables {
    time_signed: Time48,
    fudge: u16,
    error: TsigRcode,
    other: Option<Time48>,
}

impl Variables {
    fn new(
        time_signed: Time48,
        fudge: u16,
        error: TsigRcode,
        other: Option<Time48>
    ) -> Self {
        Variables {
            time_signed, fudge, error, other
        }
    }

    fn from_tsig(record: &Record<ParsedDname, Tsig<Dname>>) -> Self {
        Variables::new(
            record.data().time_signed(),
            record.data().fudge(),
            record.data().error(),
            record.data().other_time(),
        )
    }

    fn to_tsig<S: Into<Bytes>>(
        &self,
        key: &Key,
        hmac: S,
        original_id: u16
    ) -> Record<Dname, Tsig<Dname>> {
        let other = match self.other {
            Some(time) => time.into_bytes(),
            None => Bytes::new()
        };
        Record::new(
            key.name.clone(),
            Class::Any,
            0,
            Tsig::new(
                key.algorithm().to_dname(),
                self.time_signed,
                self.fudge,
                hmac.into(),
                original_id,
                self.error,
                other,
            )
        )
    }

    fn sign(&self, key: &Key, context: &mut hmac::SigningContext) {
        let mut buf = [0u8; 8];

        // Key name, in canonical wire format
        for label in key.name.iter_labels().map(Label::to_canonical) {
            context.update(label.as_wire_slice());
        }
        // CLASS (Always ANY in the current specification)
        BigEndian::write_u16(&mut buf, Class::Any.to_int());
        context.update(&buf[..2]);
        // TTL (Always 0 in the current specification)
        BigEndian::write_u32(&mut buf, 0);
        context.update(&buf[..4]);
        // Algorithm Name (in canonical wire format)
        context.update(key.algorithm().into_wire_slice());
        // Time Signed
        context.update(&self.time_signed.into_octets());
        // Fudge
        BigEndian::write_u16(&mut buf, self.fudge);
        context.update(&buf[..2]);
        // Error
        BigEndian::write_u16(&mut buf, self.error.to_int());
        context.update(&buf[..2]);
        // Other Len
        BigEndian::write_u16(
            &mut buf,
            if self.other.is_some() { 6 }
            else { 0 }
        );
        context.update(&buf[..2]);
        // Other
        if let Some(time) = self.other {
            BigEndian::write_u64(&mut buf, time.into());
            context.update(&buf[2..]);
        }
    }

    fn sign_timers(&self, context: &mut hmac::SigningContext) {
        // Time Signed
        context.update(&self.time_signed.into_octets());

        // Fudge
        let mut buf = [0u8; 2];
        BigEndian::write_u16(&mut buf, self.fudge);
        context.update(&buf[..2]);
    }
}


//------------ Algorithm -----------------------------------------------------

/// The supported TSIG algorithms.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512
}

impl Algorithm {
    /// Creates a value from its domain name representation.
    ///
    /// Returns `None` if the name doesn’t represent a known algorithm.
    pub fn from_dname<N: ToDname>(name: &N) -> Option<Self> {
        let mut labels = name.iter_labels();
        let first = match labels.next() {
            Some(label) => label,
            None => return None
        };
        match labels.next() {
            Some(label) if label.is_root() => {},
            _ => return None
        }
        match first.as_slice() {
            b"hmac-sha1" => Some(Algorithm::Sha1),
            b"hmac-sha256" => Some(Algorithm::Sha256),
            b"hmac-sha384" => Some(Algorithm::Sha384),
            b"hmac-sha512" => Some(Algorithm::Sha512),
            _ => None
        }
    }

    /// Creates a value from a digest algorithm.
    ///
    /// This will panic if `alg` is not one of the recognized algorithms.
    fn from_digest_algorithm(alg: &'static digest::Algorithm) -> Self {
        if *alg == digest::SHA1 {
            Algorithm::Sha1
        }
        else if *alg == digest::SHA256 {
            Algorithm::Sha256
        }
        else if *alg == digest::SHA384 {
            Algorithm::Sha256
        }
        else if *alg == digest::SHA512 {
            Algorithm::Sha512
        }
        else {
            panic!("Unknown TSIG key algorithm.")
        }
    }

    /// Returns the ring digest algorithm for this TSIG algorithm.
    fn into_digest_algorithm(self) -> &'static digest::Algorithm {
        match self {
            Algorithm::Sha1 => &digest::SHA1,
            Algorithm::Sha256 => &digest::SHA256,
            Algorithm::Sha384 => &digest::SHA384,
            Algorithm::Sha512 => &digest::SHA512,
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
    pub fn to_dname(self) -> Dname {
        unsafe {
            Dname::from_bytes_unchecked(
                Bytes::from_static(self.into_wire_slice())
            )
        }
    }

    /// Returns the native length of a signature created with this algorithm.
    pub fn native_len(self) -> usize {
        self.into_digest_algorithm().output_len
    }

    /// Returns the bounds for the allowed signature size.
    pub fn within_len_bounds(self, len: usize) -> bool {
        len >= cmp::max(10, self.native_len() / 2)
        && len <= self.native_len()
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
        write!(f, "{}", match *self {
            Algorithm::Sha1 => "hmac-sha1",
            Algorithm::Sha256 => "hmac-sha256",
            Algorithm::Sha384 => "hmac-sha384",
            Algorithm::Sha512 => "hmac-sha512",
        })
    }
}


//------------ Helper Functions ----------------------------------------------

/// Extracts the TSIG record from a message.
///
/// Checks that there is exactly one TSIG record in the additional
/// section, that it is the last record in this section. If that is true,
/// returns both the message without that TSIG record and the TSIG record
/// itself.
/// 
/// Note that the function does _not_ update the message ID.
fn extract_tsig(
    msg: &mut Message
) -> Option<Record<ParsedDname, Tsig<Dname>>> {
    let additional = match msg.additional() {
        Ok(additional) => additional,
        Err(_) => return None,
    };
    let mut seen = false;
    for record in additional.limit_to::<Tsig<Dname>>() {
        if seen || record.is_err() {
            return None
        }
        seen = true
    }
    let tsig = match msg.extract_last() {
        Some(tsig) => tsig,
        None => return None
    };
    Some(tsig)
}


/// Updates message’s ID to tsig’s original ID.
fn update_id(
    message: &mut Message,
    tsig: &Record<ParsedDname, Tsig<Dname>>
) {
    if message.header().id() != tsig.data().original_id() {
        message.update_header(|header| {
            header.set_id(tsig.data().original_id())
        })
    }
}


//------------ NewKeyError ---------------------------------------------------

/// A key couldn’t be created.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum NewKeyError {
    #[fail(display="minimum signature length out of bounds")]
    BadMinMacLen,

    #[fail(display="created signature length out of bounds")]
    BadSigningLen,
}


//------------ GenerateKeyError ----------------------------------------------

/// A key couldn’t be created.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum GenerateKeyError {
    #[fail(display="minimum signature length out of bounds")]
    BadMinMacLen,

    #[fail(display="created signature length out of bounds")]
    BadSigningLen,

    #[fail(display="generating key failed")]
    GenerationFailed,
}

impl From<NewKeyError> for GenerateKeyError {
    fn from(err: NewKeyError) -> Self {
        match err {
            NewKeyError::BadMinMacLen => GenerateKeyError::BadMinMacLen,
            NewKeyError::BadSigningLen => GenerateKeyError::BadSigningLen
        }
    }
}

impl From<ring::error::Unspecified> for GenerateKeyError {
    fn from(_: ring::error::Unspecified) -> Self {
        GenerateKeyError::GenerationFailed
    }
}


//------------ AlgorithmError ------------------------------------------------

/// An invalid algorithm was provided.
#[derive(Clone, Copy, Debug, Fail)]
#[fail(display="invalid algorithm")]
pub struct AlgorithmError;


//------------ ValidationError -----------------------------------------------

#[derive(Clone, Debug, Fail)]
pub enum ValidationError {
    #[fail(display="unknown algorithm")]
    BadAlg,

    #[fail(display="bad content of other")]
    BadOther,

    #[fail(display="bad signatures")]
    BadSig,

    #[fail(display="short signature")]
    BadTrunc,

    #[fail(display="unknown key")]
    BadKey,

    #[fail(display="bad time")]
    BadTime,

    #[fail(display="format error")]
    FormErr,

    #[fail(display="unsigned answer")]
    ServerUnsigned,

    #[fail(display="unknown key on server")]
    ServerBadKey,

    #[fail(display="server failed to verify MAC")]
    ServerBadSig,

    #[fail(display="server reported bad time")]
    ServerBadTime {
        client: Time48,
        server: Time48
    },

    #[fail(display="too many unsigned messages")]
    TooManyUnsigned,
}

impl From<ParsedDnameError> for ValidationError {
    fn from(_: ParsedDnameError) -> Self {
        ValidationError::FormErr
    }
}

