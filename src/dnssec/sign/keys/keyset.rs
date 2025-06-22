//! Maintain the state of a collection keys used to sign a zone.
//!
//! A key set is a collection of keys used to sign a sigle zone. This module
//! supports the management of key sets including key rollover.
//!
//! # Example
//!
//! ```no_run
//! use domain::base::iana::SecurityAlgorithm;
//! use domain::base::Name;
//! use domain::dnssec::sign::keys::keyset::{KeySet, RollType, UnixTime};
//! use std::fs::File;
//! use std::io::Write;
//! use std::str::FromStr;
//! use std::thread::sleep;
//! use std::time::Duration;
//!
//! // Create new KeySet for example.com
//! let mut ks = KeySet::new(Name::from_str("example.com").unwrap());
//!
//! // Add two keys.
//! ks.add_key_ksk("first KSK.key".to_string(), None, SecurityAlgorithm::ECDSAP256SHA256, 0, UnixTime::now());
//! ks.add_key_zsk("first ZSK.key".to_string(),
//!     Some("first ZSK.private".to_string()), SecurityAlgorithm::ECDSAP256SHA256, 0, UnixTime::now());
//!
//! // Save the state.
//! let json = serde_json::to_string(&ks).unwrap();
//! let mut file = File::create("example.com-keyset.json").unwrap();
//! write!(file, "{json}").unwrap();
//!
//! // Load the state from a file.
//! let file = File::open("example.com-keyset.json").unwrap();
//! let mut ks: KeySet = serde_json::from_reader(file).unwrap();
//!
//! // Start CSK roll.
//! let actions = ks.start_roll(RollType::CskRoll, &[], &["first KSK.key",
//!     "first ZSK.key"]);
//! // Handle actions.
//! // Report first propagation complete and ttl.
//! let actions = ks.propagation1_complete(RollType::CskRoll, 3600);
//! sleep(Duration::from_secs(3600));
//! // Report that cached entries have expired.
//! let actions = ks.cache_expired1(RollType::CskRoll);
//! // Report second propagation complete and ttl.
//! let actions = ks.propagation2_complete(RollType::CskRoll, 3600);
//! sleep(Duration::from_secs(3600));
//! // Report that cached entries have expired.
//! let actions = ks.cache_expired1(RollType::CskRoll);
//! // And we are done!
//! let actions = ks.roll_done(RollType::CskRoll);
//! ```

#![warn(missing_docs)]

// TODO:
// - add support for undo/abort.

use crate::base::iana::SecurityAlgorithm;
use crate::base::Name;
use crate::rdata::dnssec::Timestamp;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map, HashMap, HashSet};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Add;
use std::str::FromStr;
use std::string::{String, ToString};
use std::time::Duration;
use std::vec::Vec;
use time::format_description;
use time::OffsetDateTime;

#[cfg(test)]
use mock_instant::global::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use mock_instant::SystemTimeError;

#[cfg(not(test))]
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

/// This type maintains a collection keys used to sign a zone.
///
/// The state of this type can be serialized and deserialized. The state
/// includes the state of any key rollovers going on.
#[derive(Deserialize, Serialize)]
pub struct KeySet {
    name: Name<Vec<u8>>,
    keys: HashMap<String, Key>,

    rollstates: HashMap<RollType, RollState>,
}

impl KeySet {
    /// Create a new key set for a give zone name.
    pub fn new(name: Name<Vec<u8>>) -> Self {
        Self {
            name,
            keys: HashMap::new(),
            rollstates: HashMap::new(),
        }
    }

    /// Add a KSK.
    pub fn add_key_ksk(
        &mut self,
        pubref: String,
        privref: Option<String>,
        algorithm: SecurityAlgorithm,
        key_tag: u16,
        creation_ts: UnixTime,
    ) -> Result<(), Error> {
        if !self.unique_key_tag(key_tag) {
            return Err(Error::DuplicateKeyTag);
        }
        let keystate: KeyState = Default::default();
        let key = Key::new(
            privref,
            KeyType::Ksk(keystate),
            algorithm,
            key_tag,
            creation_ts,
        );
        if let hash_map::Entry::Vacant(e) = self.keys.entry(pubref) {
            e.insert(key);
            Ok(())
        } else {
            Err(Error::KeyExists)
        }
    }

    /// Add a ZSK.
    pub fn add_key_zsk(
        &mut self,
        pubref: String,
        privref: Option<String>,
        algorithm: SecurityAlgorithm,
        key_tag: u16,
        creation_ts: UnixTime,
    ) -> Result<(), Error> {
        if !self.unique_key_tag(key_tag) {
            return Err(Error::DuplicateKeyTag);
        }
        let keystate: KeyState = Default::default();
        let key = Key::new(
            privref,
            KeyType::Zsk(keystate),
            algorithm,
            key_tag,
            creation_ts,
        );
        if let hash_map::Entry::Vacant(e) = self.keys.entry(pubref) {
            e.insert(key);
            Ok(())
        } else {
            Err(Error::KeyExists)
        }
    }

    /// Add a CSK.
    pub fn add_key_csk(
        &mut self,
        pubref: String,
        privref: Option<String>,
        algorithm: SecurityAlgorithm,
        key_tag: u16,
        creation_ts: UnixTime,
    ) -> Result<(), Error> {
        if !self.unique_key_tag(key_tag) {
            return Err(Error::DuplicateKeyTag);
        }
        let keystate: KeyState = Default::default();
        let key = Key::new(
            privref,
            KeyType::Csk(keystate.clone(), keystate),
            algorithm,
            key_tag,
            creation_ts,
        );
        if let hash_map::Entry::Vacant(e) = self.keys.entry(pubref) {
            e.insert(key);
            Ok(())
        } else {
            Err(Error::KeyExists)
        }
    }

    fn unique_key_tag(&self, key_tag: u16) -> bool {
        !self.keys.iter().any(|(_, k)| k.key_tag == key_tag)
    }

    /// Delete a key.
    pub fn delete_key(&mut self, pubref: &str) -> Result<(), Error> {
        match self.keys.get(pubref) {
            None => return Err(Error::KeyNotFound),
            Some(key) => match &key.keytype {
                KeyType::Ksk(keystate)
                | KeyType::Zsk(keystate)
                | KeyType::Include(keystate) => {
                    if !keystate.old
                        || keystate.signer
                        || keystate.present
                        || keystate.at_parent
                    {
                        return Err(Error::KeyNotOld);
                    }
                }
                KeyType::Csk(ksk_keystate, zsk_keystate) => {
                    if !ksk_keystate.old
                        || ksk_keystate.signer
                        || ksk_keystate.present
                        || ksk_keystate.at_parent
                    {
                        return Err(Error::KeyNotOld);
                    }
                    if !zsk_keystate.old
                        || zsk_keystate.signer
                        || zsk_keystate.present
                        || zsk_keystate.at_parent
                    {
                        return Err(Error::KeyNotOld);
                    }
                }
            },
        }

        // The state of the key is checked, now remove the key.
        self.keys.remove(pubref).expect("key should exist");
        Ok(())
    }

    /// Return the zone name this key set belongs to.
    pub fn name(&self) -> &Name<Vec<u8>> {
        &self.name
    }

    /// Return the list of keys in the key set.
    pub fn keys(&self) -> &HashMap<String, Key> {
        &self.keys
    }

    /// Return the current active rolls and their states.
    pub fn rollstates(&self) -> &HashMap<RollType, RollState> {
        &self.rollstates
    }

    /// Start a key roll.
    ///
    /// The parameters are the type of key roll, a list of old keys that need
    /// to be rolled out and a list of new keys that on their way in.
    /// A list of actions is returned. The caller is responsible for
    /// performing the actions.
    pub fn start_roll(
        &mut self,
        rolltype: RollType,
        old: &[&str],
        new: &[&str],
    ) -> Result<Vec<Action>, Error> {
        let next_state = RollState::Propagation1;
        rolltype.rollfn()(RollOp::Start(old, new), self)?;

        self.rollstates.insert(rolltype.clone(), next_state.clone());

        Ok(rolltype.roll_actions_fn()(next_state))
    }

    /// A report that the propagation of the first change has completed.
    ///
    /// The user reports that the changes have propagated and provides the
    /// required ttl value. The actual changes to monitor were specified as
    /// an action in the previous state (start_roll). A list of actions is
    /// returned.
    pub fn propagation1_complete(
        &mut self,
        rolltype: RollType,
        ttl: u32,
    ) -> Result<Vec<Action>, Error> {
        // First check if the current roll state is Propagation1.
        let Some(RollState::Propagation1) = self.rollstates.get(&rolltype)
        else {
            return Err(Error::WrongStateForRollOperation);
        };
        let next_state = RollState::CacheExpire1(ttl);
        rolltype.rollfn()(RollOp::Propagation1, self)?;

        self.rollstates.insert(rolltype.clone(), next_state.clone());

        Ok(rolltype.roll_actions_fn()(next_state))
    }

    /// A report that any cached values should have expired by now.
    ///
    /// This method should be called at least ttl seconds after the call to
    /// propagation1_complete where ttl is the value of the ttl parameter
    /// passed to the propagation1_complete method. A list of actions is
    /// returned.
    pub fn cache_expired1(
        &mut self,
        rolltype: RollType,
    ) -> Result<Vec<Action>, Error> {
        // First check if the current roll state is CacheExpire1.
        let Some(RollState::CacheExpire1(ttl)) =
            self.rollstates.get(&rolltype)
        else {
            return Err(Error::WrongStateForRollOperation);
        };
        let next_state = RollState::Propagation2;
        rolltype.rollfn()(RollOp::CacheExpire1(*ttl), self)?;
        self.rollstates.insert(rolltype.clone(), next_state.clone());

        Ok(rolltype.roll_actions_fn()(next_state))
    }

    /// A report that the propagation of the second change has completed.
    ///
    /// The user reports that the changes have propagated and provides the
    /// required ttl value. The actual changes to monitor were specified as on
    /// action in the previous state (cache_expired1). A list of actions is
    /// returned.
    pub fn propagation2_complete(
        &mut self,
        rolltype: RollType,
        ttl: u32,
    ) -> Result<Vec<Action>, Error> {
        // First check if the current roll state is Propagation2.
        let Some(RollState::Propagation2) = self.rollstates.get(&rolltype)
        else {
            return Err(Error::WrongStateForRollOperation);
        };
        let next_state = RollState::CacheExpire2(ttl);
        rolltype.rollfn()(RollOp::Propagation2, self)?;
        self.rollstates.insert(rolltype.clone(), next_state.clone());
        Ok(rolltype.roll_actions_fn()(next_state))
    }

    /// A report that any cached values should have expired by now.
    ///
    /// This method should be called at least ttl seconds after the call to
    /// propagation2_complete where ttl is the value of the ttl parameter
    /// passed to the propagation2_complete method. A list of actions is
    /// returned.
    pub fn cache_expired2(
        &mut self,
        rolltype: RollType,
    ) -> Result<Vec<Action>, Error> {
        // First check if the current roll state is CacheExpire2.
        let Some(RollState::CacheExpire2(ttl)) =
            self.rollstates.get(&rolltype)
        else {
            return Err(Error::WrongStateForRollOperation);
        };
        let next_state = RollState::Done;
        rolltype.rollfn()(RollOp::CacheExpire2(*ttl), self)?;
        self.rollstates.insert(rolltype.clone(), next_state.clone());

        Ok(rolltype.roll_actions_fn()(next_state))
    }

    /// The user reports that all actions have been performed and that the
    /// key roll is now complete.
    pub fn roll_done(
        &mut self,
        rolltype: RollType,
    ) -> Result<Vec<Action>, Error> {
        // First check if the current roll state is Done.
        let Some(RollState::Done) = self.rollstates.get(&rolltype) else {
            return Err(Error::WrongStateForRollOperation);
        };
        rolltype.rollfn()(RollOp::Done, self)?;
        self.rollstates.remove(&rolltype);
        Ok(Vec::new())
    }

    /// Return the actions that need to be performed for the current
    /// roll state.
    pub fn actions(&self, rolltype: RollType) -> Vec<Action> {
        if let Some(rollstate) = self.rollstates.get(&rolltype) {
            rolltype.roll_actions_fn()(rollstate.clone())
        } else {
            Vec::new()
        }
    }

    fn update_ksk(
        &mut self,
        mode: Mode,
        old: &[&str],
        new: &[&str],
    ) -> Result<(), Error> {
        let mut tmpkeys = self.keys.clone();
        let keys: &mut HashMap<String, Key> = match mode {
            Mode::DryRun => &mut tmpkeys,
            Mode::ForReal => &mut self.keys,
        };
        let mut algs_old = HashSet::new();
        for k in old {
            let Some(ref mut key) = keys.get_mut(&(*k).to_string()) else {
                return Err(Error::KeyNotFound);
            };
            let KeyType::Ksk(ref mut keystate) = key.keytype else {
                return Err(Error::WrongKeyType);
            };

            // Set old for any key we find.
            keystate.old = true;

            // Add algorithm
            algs_old.insert(key.algorithm);
        }
        let now = UnixTime::now();
        let mut algs_new = HashSet::new();
        for k in new {
            let Some(ref mut key) = keys.get_mut(&(*k).to_string()) else {
                return Err(Error::KeyNotFound);
            };
            let KeyType::Ksk(ref mut keystate) = key.keytype else {
                return Err(Error::WrongKeyType);
            };
            if *keystate
                != (KeyState {
                    old: false,
                    signer: false,
                    present: false,
                    at_parent: false,
                })
            {
                return Err(Error::WrongKeyState);
            }

            // Move key state to Incoming.
            keystate.present = true;
            keystate.signer = true;
            key.timestamps.published = Some(now.clone());

            // Add algorithm
            algs_new.insert(key.algorithm);
        }

        // Make sure the sets of algorithms are the same.
        if algs_old != algs_new {
            return Err(Error::AlgorithmSetsMismatch);
        }

        // Make sure we have at least one key in incoming state.
        if !keys.iter().any(|(_, k)| {
            if let KeyType::Ksk(keystate) = &k.keytype {
                !keystate.old && keystate.present
            } else {
                false
            }
        }) {
            return Err(Error::NoSuitableKeyPresent);
        }
        Ok(())
    }

    fn update_zsk(
        &mut self,
        mode: Mode,
        old: &[&str],
        new: &[&str],
    ) -> Result<(), Error> {
        let mut tmpkeys = self.keys.clone();
        let keys: &mut HashMap<String, Key> = match mode {
            Mode::DryRun => &mut tmpkeys,
            Mode::ForReal => &mut self.keys,
        };
        let mut algs_old = HashSet::new();
        for k in old {
            let Some(ref mut key) = keys.get_mut(&(*k).to_string()) else {
                return Err(Error::KeyNotFound);
            };
            let KeyType::Zsk(ref mut keystate) = key.keytype else {
                return Err(Error::WrongKeyType);
            };

            // Set old for any key we find.
            keystate.old = true;

            // Add algorithm
            algs_old.insert(key.algorithm);
        }
        let now = UnixTime::now();
        let mut algs_new = HashSet::new();
        for k in new {
            let Some(key) = keys.get_mut(&(*k).to_string()) else {
                return Err(Error::KeyNotFound);
            };
            let KeyType::Zsk(ref mut keystate) = key.keytype else {
                return Err(Error::WrongKeyType);
            };
            if *keystate
                != (KeyState {
                    old: false,
                    signer: false,
                    present: false,
                    at_parent: false,
                })
            {
                return Err(Error::WrongKeyState);
            }

            // Move key state to Incoming.
            keystate.present = true;
            key.timestamps.published = Some(now.clone());

            // Add algorithm
            algs_new.insert(key.algorithm);
        }

        // Make sure the sets of algorithms are the same.
        if algs_old != algs_new {
            return Err(Error::AlgorithmSetsMismatch);
        }

        // Make sure we have at least one key in incoming state.
        if !keys.iter().any(|(_, k)| {
            if let KeyType::Zsk(keystate) = &k.keytype {
                !keystate.old || keystate.present
            } else {
                false
            }
        }) {
            return Err(Error::NoSuitableKeyPresent);
        }
        Ok(())
    }

    fn update_csk(
        &mut self,
        mode: Mode,
        old: &[&str],
        new: &[&str],
    ) -> Result<(), Error> {
        let mut tmpkeys = self.keys.clone();
        let keys: &mut HashMap<String, Key> = match mode {
            Mode::DryRun => &mut tmpkeys,
            Mode::ForReal => &mut self.keys,
        };
        let mut algs_old = HashSet::new();
        for k in old {
            let Some(key) = keys.get_mut(&(*k).to_string()) else {
                return Err(Error::KeyNotFound);
            };
            match key.keytype {
                KeyType::Ksk(ref mut keystate)
                | KeyType::Zsk(ref mut keystate) => {
                    keystate.old = true;
                }
                KeyType::Csk(ref mut ksk_keystate, ref mut zsk_keystate) => {
                    ksk_keystate.old = true;
                    zsk_keystate.old = true;
                }
                KeyType::Include(_) => {
                    return Err(Error::WrongKeyType);
                }
            }

            // Add algorithm
            algs_old.insert(key.algorithm);
        }
        let now = UnixTime::now();
        let mut algs_new = HashSet::new();
        for k in new {
            let Some(key) = keys.get_mut(&(*k).to_string()) else {
                return Err(Error::KeyNotFound);
            };
            match key.keytype {
                KeyType::Ksk(ref mut keystate) => {
                    if *keystate
                        != (KeyState {
                            old: false,
                            signer: false,
                            present: false,
                            at_parent: false,
                        })
                    {
                        return Err(Error::WrongKeyState);
                    }

                    // Move key state to Active.
                    keystate.present = true;
                    keystate.signer = true;
                    key.timestamps.published = Some(now.clone());
                }
                KeyType::Zsk(ref mut keystate) => {
                    if *keystate
                        != (KeyState {
                            old: false,
                            signer: false,
                            present: false,
                            at_parent: false,
                        })
                    {
                        return Err(Error::WrongKeyState);
                    }

                    // Move key state to Incoming.
                    keystate.present = true;
                    key.timestamps.published = Some(now.clone());
                }
                KeyType::Csk(ref mut ksk_keystate, ref mut zsk_keystate) => {
                    if *ksk_keystate
                        != (KeyState {
                            old: false,
                            signer: false,
                            present: false,
                            at_parent: false,
                        })
                    {
                        return Err(Error::WrongKeyState);
                    }

                    // Move key state to Active.
                    ksk_keystate.present = true;
                    ksk_keystate.signer = true;

                    if *zsk_keystate
                        != (KeyState {
                            old: false,
                            signer: false,
                            present: false,
                            at_parent: false,
                        })
                    {
                        return Err(Error::WrongKeyState);
                    }

                    // Move key state to Incoming.
                    zsk_keystate.present = true;

                    key.timestamps.published = Some(now.clone());
                }
                _ => {
                    return Err(Error::WrongKeyType);
                }
            }

            // Add algorithm
            algs_new.insert(key.algorithm);
        }

        // Make sure the sets of algorithms are the same.
        if algs_old != algs_new {
            return Err(Error::AlgorithmSetsMismatch);
        }

        // Make sure we have at least one KSK key in incoming state.
        if !keys.iter().any(|(_, k)| match &k.keytype {
            KeyType::Ksk(keystate) | KeyType::Csk(keystate, _) => {
                !keystate.old && keystate.present
            }
            _ => false,
        }) {
            return Err(Error::NoSuitableKeyPresent);
        }
        // Make sure we have at least one ZSK key in incoming state.
        if !keys.iter().any(|(_, k)| match &k.keytype {
            KeyType::Zsk(keystate) | KeyType::Csk(_, keystate) => {
                !keystate.old && keystate.present
            }
            _ => false,
        }) {
            return Err(Error::NoSuitableKeyPresent);
        }
        Ok(())
    }

    fn update_algorithm(
        &mut self,
        mode: Mode,
        old: &[&str],
        new: &[&str],
    ) -> Result<(), Error> {
        let mut tmpkeys = self.keys.clone();
        let keys: &mut HashMap<String, Key> = match mode {
            Mode::DryRun => &mut tmpkeys,
            Mode::ForReal => &mut self.keys,
        };
        for k in old {
            let Some(key) = keys.get_mut(&(*k).to_string()) else {
                return Err(Error::KeyNotFound);
            };
            match key.keytype {
                KeyType::Ksk(ref mut keystate)
                | KeyType::Zsk(ref mut keystate) => {
                    keystate.old = true;
                }
                KeyType::Csk(ref mut ksk_keystate, ref mut zsk_keystate) => {
                    ksk_keystate.old = true;
                    zsk_keystate.old = true;
                }
                KeyType::Include(_) => {
                    return Err(Error::WrongKeyType);
                }
            }
        }
        let now = UnixTime::now();
        for k in new {
            let Some(key) = keys.get_mut(&(*k).to_string()) else {
                return Err(Error::KeyNotFound);
            };
            match key.keytype {
                KeyType::Ksk(ref mut keystate)
                | KeyType::Zsk(ref mut keystate) => {
                    if *keystate
                        != (KeyState {
                            old: false,
                            signer: false,
                            present: false,
                            at_parent: false,
                        })
                    {
                        return Err(Error::WrongKeyState);
                    }

                    // Move key state to Active.
                    keystate.present = true;
                    keystate.signer = true;
                    key.timestamps.published = Some(now.clone());
                }
                KeyType::Csk(ref mut ksk_keystate, ref mut zsk_keystate) => {
                    if *ksk_keystate
                        != (KeyState {
                            old: false,
                            signer: false,
                            present: false,
                            at_parent: false,
                        })
                    {
                        return Err(Error::WrongKeyState);
                    }

                    // Move key state to Active.
                    ksk_keystate.present = true;
                    ksk_keystate.signer = true;

                    if *zsk_keystate
                        != (KeyState {
                            old: false,
                            signer: false,
                            present: false,
                            at_parent: false,
                        })
                    {
                        return Err(Error::WrongKeyState);
                    }

                    // Move key state to Incoming.
                    zsk_keystate.present = true;
                    zsk_keystate.signer = true;

                    key.timestamps.published = Some(now.clone());
                }
                _ => {
                    return Err(Error::WrongKeyType);
                }
            }
        }

        // Make sure we have at least one KSK key in incoming state.
        if !keys.iter().any(|(_, k)| match &k.keytype {
            KeyType::Ksk(keystate) | KeyType::Csk(keystate, _) => {
                !keystate.old && keystate.present
            }
            _ => false,
        }) {
            return Err(Error::NoSuitableKeyPresent);
        }
        // Make sure we have at least one ZSK key in incoming state.
        if !keys.iter().any(|(_, k)| match &k.keytype {
            KeyType::Zsk(keystate) | KeyType::Csk(_, keystate) => {
                !keystate.old && keystate.present
            }
            _ => false,
        }) {
            return Err(Error::NoSuitableKeyPresent);
        }
        Ok(())
    }
}

/// The state of a single key.
///
/// The state includes a way to refer to the public key and optionally a
/// way to refer to the provate key. The state includes the type of the
/// key (which in itself includes the key state) and a list of timestamps
/// that mark the various stages in the life of a key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Key {
    privref: Option<String>,
    keytype: KeyType,
    algorithm: SecurityAlgorithm,
    key_tag: u16,
    timestamps: KeyTimestamps,
}

impl Key {
    /// Return the 'reference' to the private key (if present).
    pub fn privref(&self) -> Option<&str> {
        self.privref.as_deref()
    }

    /// Return the key type (which includes the state of the key).
    pub fn keytype(&self) -> KeyType {
        self.keytype.clone()
    }

    /// Return the public key algorithm.
    pub fn algorithm(&self) -> SecurityAlgorithm {
        self.algorithm
    }

    /// Return the key tag.
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Return the timestamps.
    pub fn timestamps(&self) -> &KeyTimestamps {
        &self.timestamps
    }

    fn new(
        privref: Option<String>,
        keytype: KeyType,
        algorithm: SecurityAlgorithm,
        key_tag: u16,
        creation_ts: UnixTime,
    ) -> Self {
        let timestamps = KeyTimestamps {
            creation: Some(creation_ts),
            ..Default::default()
        };
        Self {
            privref,
            keytype,
            algorithm,
            key_tag,
            timestamps,
        }
    }
}

/// The different types of keys.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum KeyType {
    /// Key signing key (KSK).
    Ksk(KeyState),

    /// Zone signing key (ZSK).
    Zsk(KeyState),

    /// Combined signing key (CSK).
    ///
    /// Note that this key has two states, one for its KSK role and one for
    /// the ZSK role.
    Csk(KeyState, KeyState),

    /// Included key that belongs to another signer in a nulti-signer setup.
    Include(KeyState),
}

/// State of a key.
///
/// The state is expressed as four booleans:
/// * old. Set if the key is on its way out.
/// * signer. Set if the key either signes the DNSKEY RRset or the rest of the
///   zone.
/// * present. If the key is present in the DNSKEY RRset.
/// * at_parent. If the key has a DS record at the parent.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct KeyState {
    old: bool,
    signer: bool,
    present: bool,
    at_parent: bool,
}

impl KeyState {
    /// Return whether the key is old, i.e. on its way out.
    pub fn old(&self) -> bool {
        self.old
    }

    /// Return whether the key is a signer, i.e. signs the DNSKEY RRset or
    /// the zone.
    pub fn signer(&self) -> bool {
        self.signer
    }

    /// Return whether the key is present in the DNSKEY RRset.
    pub fn present(&self) -> bool {
        self.present
    }

    /// Return whether the key needs to have a DS record at the parent.
    pub fn at_parent(&self) -> bool {
        self.at_parent
    }
}

impl Display for KeyState {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        let mut first = true;
        if self.old {
            write!(f, "Old")?;
            first = false;
        }
        if self.signer {
            write!(f, "{}Signer", if first { "" } else { ", " })?;
            first = false;
        }
        if self.present {
            write!(f, "{}Present", if first { "" } else { ", " })?;
            first = false;
        }
        if self.at_parent {
            write!(f, "{}At Parent", if first { "" } else { ", " })?;
        }
        match (self.old, self.signer, self.present) {
            (false, false, false) => write!(f, "(Future)")?,
            (false, false, true) => write!(f, " (Incoming)")?,
            (false, true, true) => write!(f, " (Active)")?,
            (true, true, true) => write!(f, " (Leaving)")?,
            (true, false, true) => write!(f, " (Retired)")?,
            (true, false, false) => write!(f, " (Old)")?,
            (_, _, _) => (),
        }
        Ok(())
    }
}

/// This type contains the various timestamps in the life of a key.
///
/// All timestamps are optional. The following timestamps are supported:
/// * when the key was created,
/// * when the key was first published in the DNSKEY RRset,
/// * when the DNSKEY RRset with the key was first visible,
/// * when the DS record for the key was first visible,
/// * when RRSIG records signed by the key were first visible,
/// * when the key was withdrawn from the DNSKEY RRset.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KeyTimestamps {
    creation: Option<UnixTime>,
    published: Option<UnixTime>,
    visible: Option<UnixTime>,
    ds_visible: Option<UnixTime>,
    rrsig_visible: Option<UnixTime>,
    withdrawn: Option<UnixTime>,
}

impl KeyTimestamps {
    /// Return the creation time of a key.
    pub fn creation(&self) -> Option<UnixTime> {
        self.creation.clone()
    }

    /// Return the time when a key was first published in the DNSKEY RRset.
    pub fn published(&self) -> Option<UnixTime> {
        self.published.clone()
    }

    /// Return the time when DNSKEY RRset with a key was first visible.
    pub fn visible(&self) -> Option<UnixTime> {
        self.visible.clone()
    }

    /// Return the time when a DS record for a key was first visible.
    pub fn ds_visible(&self) -> Option<UnixTime> {
        self.ds_visible.clone()
    }

    /// Return the time when an RRSIG record signed by the key was first
    /// visible.
    pub fn rrsig_visible(&self) -> Option<UnixTime> {
        self.rrsig_visible.clone()
    }

    /// Return the time when the key was removed from the DNSKEY RRset.
    pub fn withdrawn(&self) -> Option<UnixTime> {
        self.withdrawn.clone()
    }
}

/// A type that contains Unix time.
///
/// Unix time is the number of seconds since midnight January first
/// 1970 GMT.
#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct UnixTime(Duration);

impl UnixTime {
    /// Create a value for the current time.
    pub fn now() -> Self {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time is expected to be after UNIX_EPOCH");
        UnixTime(dur)
    }

    /// Return how much time has elapsed since the current timestamp.
    pub fn elapsed(&self) -> Duration {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time is expected to be after UNIX_EPOCH");
        if dur < self.0 {
            // Clamp elapsed to zero.
            Duration::ZERO
        } else {
            dur - self.0
        }
    }
}

impl TryFrom<SystemTime> for UnixTime {
    type Error = SystemTimeError;
    fn try_from(t: SystemTime) -> Result<Self, SystemTimeError> {
        Ok(Self(t.duration_since(UNIX_EPOCH)?))
    }
}

impl From<Timestamp> for UnixTime {
    fn from(t: Timestamp) -> Self {
        Self(Duration::from_secs(t.into_int() as u64))
    }
}

impl From<UnixTime> for Duration {
    fn from(t: UnixTime) -> Self {
        t.0
    }
}

impl Add<Duration> for UnixTime {
    type Output = UnixTime;
    fn add(self, d: Duration) -> Self {
        Self(self.0 + d)
    }
}

impl Display for UnixTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        let nanos = self.0.as_nanos();
        let dt = OffsetDateTime::from_unix_timestamp_nanos(
            nanos.try_into().expect("bad time value"),
        )
        .expect("bad time value");
        let format = format_description::parse(
            "[year]-[month]-[day]T[hour]:[minute]:[second]",
        )
        .expect("");
        write!(f, "{}", dt.format(&format).expect(""))
    }
}

/// States of a key roll.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RollState {
    /// Waiting for the first change (actions that result in DNSKEY, CDS, DS,
    /// RRSIG, etc. updates) to propagate.
    Propagation1,
    /// Waiting for old data to expire from caches.
    ///
    /// This is data that prevents the first change from getting loaded in the
    /// cache. The TTL of the old data is a parameter.
    CacheExpire1(u32),
    /// Waiting for the second change (actions that result in DNSKEY, CDS, DS,
    /// RRSIG, etc. updates) to propagate.
    Propagation2,
    /// Waiting for old data to expire from caches.
    ///
    /// This is data that prevents the second change from getting loaded in the
    /// cache. The TTL of the old data is a parameter.
    CacheExpire2(u32),

    /// The key roll is done.
    ///
    /// This state gives the user the chance to execute the remaining actions.
    Done,
}

impl FromStr for RollType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "ksk-roll" {
            Ok(RollType::KskRoll)
        } else if s == "zsk-roll" {
            Ok(RollType::ZskRoll)
        } else if s == "csk-roll" {
            Ok(RollType::CskRoll)
        } else {
            Err(Error::UnknownRollType)
        }
    }
}

enum Mode {
    DryRun,
    ForReal,
}

/// Actions that have to be performed by the user.
///
/// Note that if a list contains multiple report actions then the user
/// has to wait until all action have completed and has to report the
/// highest TTL value among the values to report.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Action {
    /// Generate a new version of the zone with an updated DNSKEY RRset.
    UpdateDnskeyRrset,

    /// Generate a new version of the zone with CDS and CDNSKEY RRsets.
    CreateCdsRrset,

    /// Generate a new version of the zone without CDS and CDNSKEY RRsets.
    RemoveCdsRrset,

    /// Update the DS RRset at the parent.
    UpdateDsRrset,

    /// Generate a new version of the zone with updated RRSIG records.
    UpdateRrsig,

    /// Report whether an updated DNSKEY RRset has propagated to all
    /// secondaries that serve the zone. Also report the TTL of the
    /// DNSKEY RRset.
    ReportDnskeyPropagated,

    /// Wait for the DNSKEY RRset to propagate before moving to the next
    /// state. Waiting is not needed for the correctness of the key roll
    /// algorithm. However without waiting, the state of keyset may not reflect
    /// reality.
    WaitDnskeyPropagated,

    /// Report whether updated DS records have propagated to all
    /// secondaries that serve the parent zone. Also report the TTL of
    /// the DS records.
    ReportDsPropagated,

    /// Report whether updated RRSIG records have propagated to all
    /// secondaries that the serve the zone. For propagation it is
    /// sufficient to track the signatures on the SOA record. Report the
    /// highest TTL among all signatures.
    ReportRrsigPropagated,

    /// Wait for updated RRSIG records to propagate before moving to the next
    /// state. Waiting is not needed for the correctness of the key roll
    /// algorithm. However without waiting, the state of keyset may not reflect
    /// reality.
    WaitRrsigPropagated,
}

/// The type of key roll to perform.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum RollType {
    /// A KSK roll.
    KskRoll,

    /// A ZSK roll.
    ZskRoll,

    /// A CSK roll.
    CskRoll,

    /// An algorithm roll.
    AlgorithmRoll,
}

impl RollType {
    fn rollfn(&self) -> fn(RollOp, &mut KeySet) -> Result<(), Error> {
        match self {
            RollType::KskRoll => ksk_roll,
            RollType::ZskRoll => zsk_roll,
            RollType::CskRoll => csk_roll,
            RollType::AlgorithmRoll => algorithm_roll,
        }
    }
    fn roll_actions_fn(&self) -> fn(RollState) -> Vec<Action> {
        match self {
            RollType::KskRoll => ksk_roll_actions,
            RollType::ZskRoll => zsk_roll_actions,
            RollType::CskRoll => csk_roll_actions,
            RollType::AlgorithmRoll => algorithm_roll_actions,
        }
    }
}

enum RollOp<'a> {
    Start(&'a [&'a str], &'a [&'a str]),
    Propagation1,
    CacheExpire1(u32),
    Propagation2,
    CacheExpire2(u32),
    Done,
}

/// The various errors that can be returned.
#[derive(Debug)]
pub enum Error {
    /// The listed key already exists in the key set.
    KeyExists,

    /// The listed key cannot be found in the key set.
    KeyNotFound,

    /// The key cannot be deleted because it is not old.
    KeyNotOld,

    /// Attempt to add key with a key tag that already exists in the KeySet.
    DuplicateKeyTag,

    /// The key has to wrong type.
    WrongKeyType,

    /// The key is in the wrong state.
    WrongKeyState,

    /// The operation would cause no suitable key to be present.
    NoSuitableKeyPresent,

    /// The key set is in the wrong state for the requested key roll operation.
    WrongStateForRollOperation,

    /// A conflicting key roll is currently in progress.
    ConflictingRollInProgress,

    /// Algorithm set mismatch in non-algorithm key-roll.
    AlgorithmSetsMismatch,

    /// The operation is too early. The Duration parameter specifies how long
    /// to wait.
    Wait(Duration),

    /// Unable to parse a string as a roll type.
    UnknownRollType,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::KeyExists => write!(f, "key already exists"),
            Error::KeyNotFound => write!(f, "key not found"),
            Error::KeyNotOld => write!(f, "key is still in use, not old"),
            Error::DuplicateKeyTag => write!(f, "Key tag already present"),
            Error::WrongKeyType => write!(f, "key has the wrong type"),
            Error::WrongKeyState => write!(f, "key is in the wrong state"),
            Error::NoSuitableKeyPresent => {
                write!(f, "no suitable key present after key roll")
            }
            Error::WrongStateForRollOperation => {
                write!(f, "wrong roll state for operation")
            }
            Error::ConflictingRollInProgress => {
                write!(f, "conflicting roll is in progress")
            }
            Error::AlgorithmSetsMismatch => {
                write!(f, "algorithm set mismatch for non-algorithm key roll")
            }
            Error::Wait(d) => write!(f, "wait for duration {d:?}"),
            Error::UnknownRollType => {
                write!(f, "unable to parse string as roll type")
            }
        }
    }
}

fn ksk_roll(rollop: RollOp, ks: &mut KeySet) -> Result<(), Error> {
    match rollop {
        RollOp::Start(old, new) => {
            // First check if the current KSK-roll state is idle. We need to
            // check all conflicting key rolls as well. The way we check is
            // to allow specified non-conflicting rolls and consider
            // everything else as a conflict.
            if let Some(rolltype) =
                ks.rollstates.keys().find(|k| **k != RollType::ZskRoll)
            {
                if *rolltype == RollType::KskRoll {
                    return Err(Error::WrongStateForRollOperation);
                } else {
                    return Err(Error::ConflictingRollInProgress);
                }
            }
            // Check if we can move the states of the keys
            ks.update_ksk(Mode::DryRun, old, new)?;
            // Move the states of the keys
            ks.update_ksk(Mode::ForReal, old, new)
                .expect("Should have been checked by DryRun");
        }
        RollOp::Propagation1 => {
            // Set the visible time of new KSKs to the current time.
            let now = UnixTime::now();
            for k in ks.keys.values_mut() {
                let KeyType::Ksk(ref keystate) = k.keytype else {
                    continue;
                };
                if keystate.old || !keystate.present {
                    continue;
                }

                k.timestamps.visible = Some(now.clone());
            }
        }
        RollOp::CacheExpire1(ttl) => {
            for k in ks.keys.values_mut() {
                let KeyType::Ksk(ref keystate) = k.keytype else {
                    continue;
                };
                if keystate.old || !keystate.present {
                    continue;
                }

                let visible = k
                    .timestamps
                    .visible
                    .as_ref()
                    .expect("Should have been set in Propagation1");
                let elapsed = visible.elapsed();
                let ttl = Duration::from_secs(ttl.into());
                if elapsed < ttl {
                    return Err(Error::Wait(ttl - elapsed));
                }
            }

            for k in &mut ks.keys.values_mut() {
                if let KeyType::Ksk(ref mut keystate) = k.keytype {
                    if keystate.old && keystate.present {
                        keystate.at_parent = false;
                    }

                    if !keystate.old && keystate.present {
                        keystate.at_parent = true;
                    }
                }
            }
        }
        RollOp::Propagation2 => {
            // Set the published time of new DS records to the current time.
            let now = UnixTime::now();
            for k in ks.keys.values_mut() {
                let KeyType::Ksk(ref keystate) = k.keytype else {
                    continue;
                };
                if keystate.old || !keystate.present {
                    continue;
                }

                k.timestamps.ds_visible = Some(now.clone());
            }
        }
        RollOp::CacheExpire2(ttl) => {
            for k in ks.keys.values_mut() {
                let KeyType::Ksk(ref keystate) = k.keytype else {
                    continue;
                };
                if keystate.old || !keystate.present {
                    continue;
                }

                let ds_visible = k
                    .timestamps
                    .ds_visible
                    .as_ref()
                    .expect("Should have been set in Propagation2");
                let elapsed = ds_visible.elapsed();
                let ttl = Duration::from_secs(ttl.into());
                if elapsed < ttl {
                    return Err(Error::Wait(ttl - elapsed));
                }
            }

            // Move old keys out
            for k in ks.keys.values_mut() {
                let KeyType::Ksk(ref mut keystate) = k.keytype else {
                    continue;
                };
                if keystate.old && keystate.present {
                    keystate.signer = false;
                    keystate.present = false;
                    k.timestamps.withdrawn = Some(UnixTime::now());
                }
            }
        }
        RollOp::Done => (),
    }
    Ok(())
}

fn ksk_roll_actions(rollstate: RollState) -> Vec<Action> {
    let mut actions = Vec::new();
    match rollstate {
        RollState::Propagation1 => {
            actions.push(Action::UpdateDnskeyRrset);
            actions.push(Action::ReportDnskeyPropagated);
        }
        RollState::CacheExpire1(_) => (),
        RollState::Propagation2 => {
            actions.push(Action::CreateCdsRrset);
            actions.push(Action::UpdateDsRrset);
            actions.push(Action::ReportDsPropagated);
        }
        RollState::CacheExpire2(_) => (),
        RollState::Done => {
            actions.push(Action::RemoveCdsRrset);
            actions.push(Action::UpdateDnskeyRrset);
        }
    }
    actions
}

fn zsk_roll(rollop: RollOp, ks: &mut KeySet) -> Result<(), Error> {
    match rollop {
        RollOp::Start(old, new) => {
            // First check if the current ZSK-roll state is idle. We need
            // to check all conflicting key rolls as well. The way we check
            // is to allow specified non-conflicting rolls and consider
            // everything else as a conflict.
            if let Some(rolltype) =
                ks.rollstates.keys().find(|k| **k != RollType::KskRoll)
            {
                if *rolltype == RollType::ZskRoll {
                    return Err(Error::WrongStateForRollOperation);
                } else {
                    return Err(Error::ConflictingRollInProgress);
                }
            }
            // Check if we can move the states of the keys
            ks.update_zsk(Mode::DryRun, old, new)?;
            // Move the states of the keys
            ks.update_zsk(Mode::ForReal, old, new)
                .expect("Should have been checked with DryRun");
        }
        RollOp::Propagation1 => {
            // Set the visiable time of new ZSKs to the current time.
            let now = UnixTime::now();
            for k in ks.keys.values_mut() {
                let KeyType::Zsk(ref keystate) = k.keytype else {
                    continue;
                };
                if keystate.old || !keystate.present {
                    continue;
                }

                k.timestamps.visible = Some(now.clone());
            }
        }
        RollOp::CacheExpire1(ttl) => {
            for k in ks.keys.values_mut() {
                let KeyType::Zsk(ref keystate) = k.keytype else {
                    continue;
                };
                if keystate.old || !keystate.present {
                    continue;
                }

                let visible = k
                    .timestamps
                    .visible
                    .as_ref()
                    .expect("Should have been set in Propagation1");
                let elapsed = visible.elapsed();
                let ttl = Duration::from_secs(ttl.into());
                if elapsed < ttl {
                    return Err(Error::Wait(ttl - elapsed));
                }
            }

            // Move the Incoming keys to Active. Move the Leaving keys to
            // Retired.
            for k in ks.keys.values_mut() {
                let KeyType::Zsk(ref mut keystate) = k.keytype else {
                    continue;
                };
                if !keystate.old && keystate.present {
                    keystate.signer = true;
                }
                if keystate.old {
                    keystate.signer = false;
                }
            }
        }
        RollOp::Propagation2 => {
            // Set the published time of new RRSIG records to the current time.
            let now = UnixTime::now();
            for k in ks.keys.values_mut() {
                let KeyType::Zsk(ref keystate) = k.keytype else {
                    continue;
                };
                if keystate.old || !keystate.signer {
                    continue;
                }

                k.timestamps.rrsig_visible = Some(now.clone());
            }
        }
        RollOp::CacheExpire2(ttl) => {
            for k in ks.keys.values_mut() {
                let KeyType::Zsk(ref keystate) = k.keytype else {
                    continue;
                };
                if keystate.old || !keystate.signer {
                    continue;
                }

                let rrsig_visible = k
                    .timestamps
                    .rrsig_visible
                    .as_ref()
                    .expect("Should have been set in Propagation2");
                let elapsed = rrsig_visible.elapsed();
                let ttl = Duration::from_secs(ttl.into());
                if elapsed < ttl {
                    return Err(Error::Wait(ttl - elapsed));
                }
            }

            // Move old keys out
            for k in ks.keys.values_mut() {
                let KeyType::Zsk(ref mut keystate) = k.keytype else {
                    continue;
                };
                if keystate.old && !keystate.signer {
                    keystate.present = false;
                    k.timestamps.withdrawn = Some(UnixTime::now());
                }
            }
        }
        RollOp::Done => (),
    }
    Ok(())
}

fn zsk_roll_actions(rollstate: RollState) -> Vec<Action> {
    let mut actions = Vec::new();
    match rollstate {
        RollState::Propagation1 => {
            actions.push(Action::UpdateDnskeyRrset);
            actions.push(Action::ReportDnskeyPropagated);
        }
        RollState::CacheExpire1(_) => (),
        RollState::Propagation2 => {
            actions.push(Action::UpdateRrsig);
            actions.push(Action::ReportRrsigPropagated);
        }
        RollState::CacheExpire2(_) => (),
        RollState::Done => {
            actions.push(Action::UpdateDnskeyRrset);
        }
    }
    actions
}

fn csk_roll(rollop: RollOp, ks: &mut KeySet) -> Result<(), Error> {
    match rollop {
        RollOp::Start(old, new) => {
            // First check if the current CSK-roll state is idle. We need
            // to check all conflicting key rolls as well. The way we check
            // is to allow specified non-conflicting rolls and consider
            // everything else as a conflict.
            if let Some(rolltype) = ks.rollstates.keys().next() {
                if *rolltype == RollType::CskRoll {
                    return Err(Error::WrongStateForRollOperation);
                } else {
                    return Err(Error::ConflictingRollInProgress);
                }
            }
            // Check if we can move the states of the keys
            ks.update_csk(Mode::DryRun, old, new)?;
            // Move the states of the keys
            ks.update_csk(Mode::ForReal, old, new)
                .expect("Should have been check with DryRun");
        }
        RollOp::Propagation1 => {
            // Set the visiable time of new KSKs, ZSKs and CSKs to the current
            // time.
            let now = UnixTime::now();
            for k in ks.keys.values_mut() {
                match &k.keytype {
                    KeyType::Ksk(keystate)
                    | KeyType::Zsk(keystate)
                    | KeyType::Csk(keystate, _) => {
                        if keystate.old || !keystate.present {
                            continue;
                        }

                        k.timestamps.visible = Some(now.clone());
                    }
                    KeyType::Include(_) => (),
                }
            }
        }
        RollOp::CacheExpire1(ttl) => {
            for k in ks.keys.values_mut() {
                let keystate = match &k.keytype {
                    KeyType::Ksk(keystate)
                    | KeyType::Zsk(keystate)
                    | KeyType::Csk(keystate, _) => keystate,
                    KeyType::Include(_) => continue,
                };
                if keystate.old || !keystate.present {
                    continue;
                }

                let visible = k
                    .timestamps
                    .visible
                    .as_ref()
                    .expect("Should have been set in Propagation1");
                let elapsed = visible.elapsed();
                let ttl = Duration::from_secs(ttl.into());
                if elapsed < ttl {
                    return Err(Error::Wait(ttl - elapsed));
                }
            }

            for k in ks.keys.values_mut() {
                match k.keytype {
                    KeyType::Ksk(ref mut keystate) => {
                        if keystate.old && keystate.present {
                            keystate.at_parent = false;
                        }

                        // Put Active keys at parent.
                        if !keystate.old && keystate.present {
                            keystate.at_parent = true;
                        }
                    }
                    KeyType::Zsk(ref mut keystate) => {
                        // Move the Incoming keys to Active.
                        if !keystate.old && keystate.present {
                            keystate.signer = true;
                        }
                        if keystate.old {
                            keystate.signer = false;
                        }
                    }
                    KeyType::Csk(
                        ref mut ksk_keystate,
                        ref mut zsk_keystate,
                    ) => {
                        if ksk_keystate.old && ksk_keystate.present {
                            ksk_keystate.at_parent = false;
                        }

                        // Put Active keys at parent.
                        if !ksk_keystate.old && ksk_keystate.present {
                            ksk_keystate.at_parent = true;
                        }

                        // Move the Incoming keys to Active.
                        if !zsk_keystate.old && zsk_keystate.present {
                            zsk_keystate.signer = true;
                        }
                        if zsk_keystate.old {
                            zsk_keystate.signer = false;
                        }
                    }
                    _ => (),
                }
            }
        }
        RollOp::Propagation2 => {
            // Set the published time of new DS records to the current time.
            let now = UnixTime::now();
            for k in ks.keys.values_mut() {
                match &k.keytype {
                    KeyType::Ksk(keystate) | KeyType::Csk(keystate, _) => {
                        if keystate.old || !keystate.present {
                            continue;
                        }

                        k.timestamps.ds_visible = Some(now.clone());
                    }
                    KeyType::Zsk(_) | KeyType::Include(_) => (),
                }
            }

            // Set the published time of new RRSIG records to the current time.
            for k in ks.keys.values_mut() {
                let keystate = match &k.keytype {
                    KeyType::Zsk(keystate) | KeyType::Csk(_, keystate) => {
                        keystate
                    }
                    KeyType::Ksk(_) | KeyType::Include(_) => continue,
                };
                if keystate.old || !keystate.signer {
                    continue;
                }

                k.timestamps.rrsig_visible = Some(now.clone());
            }
        }
        RollOp::CacheExpire2(ttl) => {
            for k in ks.keys.values_mut() {
                let keystate = match &k.keytype {
                    KeyType::Zsk(keystate) | KeyType::Csk(_, keystate) => {
                        keystate
                    }
                    KeyType::Ksk(_) | KeyType::Include(_) => continue,
                };
                if keystate.old || !keystate.signer {
                    continue;
                }

                let rrsig_visible = k
                    .timestamps
                    .rrsig_visible
                    .as_ref()
                    .expect("Should have been set in Propagation1");
                let elapsed = rrsig_visible.elapsed();
                let ttl = Duration::from_secs(ttl.into());
                if elapsed < ttl {
                    return Err(Error::Wait(ttl - elapsed));
                }
            }

            // Move old keys out
            for k in ks.keys.values_mut() {
                match k.keytype {
                    KeyType::Ksk(ref mut keystate)
                    | KeyType::Csk(ref mut keystate, _) => {
                        if keystate.old && keystate.present {
                            keystate.signer = false;
                            keystate.present = false;
                            k.timestamps.withdrawn = Some(UnixTime::now());
                        }
                    }
                    KeyType::Zsk(_) | KeyType::Include(_) => (),
                }
            }
            for k in ks.keys.values_mut() {
                match k.keytype {
                    KeyType::Zsk(ref mut keystate)
                    | KeyType::Csk(_, ref mut keystate) => {
                        if keystate.old && !keystate.signer {
                            keystate.present = false;
                            k.timestamps.withdrawn = Some(UnixTime::now());
                        }
                    }
                    KeyType::Ksk(_) | KeyType::Include(_) => (),
                }
            }
        }
        RollOp::Done => (),
    }
    Ok(())
}

fn csk_roll_actions(rollstate: RollState) -> Vec<Action> {
    let mut actions = Vec::new();
    match rollstate {
        RollState::Propagation1 => {
            actions.push(Action::UpdateDnskeyRrset);
            actions.push(Action::ReportDnskeyPropagated);
        }
        RollState::CacheExpire1(_) => (),
        RollState::Propagation2 => {
            actions.push(Action::CreateCdsRrset);
            actions.push(Action::UpdateDsRrset);
            actions.push(Action::UpdateRrsig);
            actions.push(Action::ReportDsPropagated);
            actions.push(Action::ReportRrsigPropagated);
        }
        RollState::CacheExpire2(_) => (),
        RollState::Done => {
            actions.push(Action::RemoveCdsRrset);
            actions.push(Action::UpdateDnskeyRrset);
        }
    }
    actions
}

// An algorithm roll is similar to a CSK roll. The main difference is that
// to zone is signed with all keys before introducing the DS records for
// the new KSKs or CSKs.
fn algorithm_roll(rollop: RollOp, ks: &mut KeySet) -> Result<(), Error> {
    match rollop {
        RollOp::Start(old, new) => {
            // First check if the current algorithm-roll state is idle. We need
            // to check all conflicting key rolls as well. The way we check
            // is to allow specified non-conflicting rolls and consider
            // everything else as a conflict.
            if let Some(rolltype) = ks.rollstates.keys().next() {
                if *rolltype == RollType::AlgorithmRoll {
                    return Err(Error::WrongStateForRollOperation);
                } else {
                    return Err(Error::ConflictingRollInProgress);
                }
            }
            // Check if we can move the states of the keys
            ks.update_algorithm(Mode::DryRun, old, new)?;
            // Move the states of the keys
            ks.update_algorithm(Mode::ForReal, old, new)
                .expect("Should have been check with DryRun");
        }
        RollOp::Propagation1 => {
            // Set the visible time of new KSKs, ZSKs and CSKs to the current
            // time. Set signer and for new KSKs, ZSKs and CSKs.
            // Set RRSIG visible for new ZSKs and CSKs.
            let now = UnixTime::now();
            for k in ks.keys.values_mut() {
                match &mut k.keytype {
                    KeyType::Ksk(keystate) => {
                        if keystate.old || !keystate.present {
                            continue;
                        }

                        k.timestamps.visible = Some(now.clone());
                    }
                    KeyType::Zsk(keystate) | KeyType::Csk(keystate, _) => {
                        if keystate.old || !keystate.present {
                            continue;
                        }

                        k.timestamps.visible = Some(now.clone());
                        k.timestamps.rrsig_visible = Some(now.clone());
                    }
                    KeyType::Include(_) => (),
                }
            }
        }
        RollOp::CacheExpire1(ttl) => {
            for k in ks.keys.values_mut() {
                let keystate = match &k.keytype {
                    KeyType::Ksk(keystate)
                    | KeyType::Zsk(keystate)
                    | KeyType::Csk(keystate, _) => keystate,
                    KeyType::Include(_) => continue,
                };
                if keystate.old || !keystate.present {
                    continue;
                }

                let visible = k
                    .timestamps
                    .visible
                    .as_ref()
                    .expect("Should have been set in Propagation1");
                let elapsed = visible.elapsed();
                let ttl = Duration::from_secs(ttl.into());
                if elapsed < ttl {
                    return Err(Error::Wait(ttl - elapsed));
                }
            }

            for k in ks.keys.values_mut() {
                match k.keytype {
                    KeyType::Ksk(ref mut keystate)
                    | KeyType::Csk(ref mut keystate, _) => {
                        if keystate.old && keystate.present {
                            keystate.at_parent = false;
                        }

                        // Put Active keys at parent.
                        if !keystate.old && keystate.present {
                            keystate.at_parent = true;
                        }
                    }
                    KeyType::Zsk(_) | KeyType::Include(_) => (),
                }
            }
        }
        RollOp::Propagation2 => {
            // Set the published time of new DS records to the current time.
            let now = UnixTime::now();
            for k in ks.keys.values_mut() {
                match &k.keytype {
                    KeyType::Ksk(keystate) | KeyType::Csk(keystate, _) => {
                        if keystate.old || !keystate.present {
                            continue;
                        }

                        k.timestamps.ds_visible = Some(now.clone());
                    }
                    KeyType::Zsk(_) | KeyType::Include(_) => (),
                }
            }
        }
        RollOp::CacheExpire2(ttl) => {
            for k in ks.keys.values_mut() {
                let keystate = match &k.keytype {
                    KeyType::Ksk(keystate) | KeyType::Csk(keystate, _) => {
                        keystate
                    }
                    KeyType::Zsk(_) | KeyType::Include(_) => continue,
                };
                if keystate.old || !keystate.signer {
                    continue;
                }

                let ds_visible = k
                    .timestamps
                    .ds_visible
                    .as_ref()
                    .expect("Should have been set in Propagation2");
                let elapsed = ds_visible.elapsed();
                let ttl = Duration::from_secs(ttl.into());
                if elapsed < ttl {
                    return Err(Error::Wait(ttl - elapsed));
                }
            }

            // Move old keys out
            for k in ks.keys.values_mut() {
                match k.keytype {
                    KeyType::Ksk(ref mut keystate)
                    | KeyType::Zsk(ref mut keystate) => {
                        if keystate.old && keystate.present {
                            keystate.signer = false;
                            keystate.present = false;
                            k.timestamps.withdrawn = Some(UnixTime::now());
                        }
                    }
                    KeyType::Csk(
                        ref mut ksk_keystate,
                        ref mut zsk_keystate,
                    ) => {
                        if ksk_keystate.old && ksk_keystate.present {
                            ksk_keystate.signer = false;
                            ksk_keystate.present = false;
                            zsk_keystate.signer = false;
                            zsk_keystate.present = false;
                            k.timestamps.withdrawn = Some(UnixTime::now());
                        }
                    }
                    KeyType::Include(_) => (),
                }
            }
        }
        RollOp::Done => (),
    }
    Ok(())
}

fn algorithm_roll_actions(rollstate: RollState) -> Vec<Action> {
    let mut actions = Vec::new();
    match rollstate {
        RollState::Propagation1 => {
            actions.push(Action::UpdateDnskeyRrset);
            actions.push(Action::UpdateRrsig);
            actions.push(Action::ReportDnskeyPropagated);
            actions.push(Action::ReportRrsigPropagated);
        }
        RollState::CacheExpire1(_) => (),
        RollState::Propagation2 => {
            actions.push(Action::CreateCdsRrset);
            actions.push(Action::UpdateDsRrset);
            actions.push(Action::ReportDsPropagated);
        }
        RollState::CacheExpire2(_) => (),
        RollState::Done => {
            actions.push(Action::RemoveCdsRrset);
            actions.push(Action::UpdateDnskeyRrset);
            actions.push(Action::UpdateRrsig);
            actions.push(Action::WaitDnskeyPropagated);
            actions.push(Action::WaitRrsigPropagated);
        }
    }
    actions
}

#[cfg(test)]
mod tests {
    use crate::base::Name;
    use crate::dnssec::sign::keys::keyset::SecurityAlgorithm;
    use crate::dnssec::sign::keys::keyset::{
        Action, KeySet, KeyType, RollType, UnixTime,
    };
    use crate::std::string::ToString;
    use mock_instant::global::MockClock;
    use std::str::FromStr;
    use std::string::String;
    use std::time::Duration;
    use std::vec::Vec;

    #[test]
    fn test_name() {
        let ks = KeySet::new(Name::from_str("example.com").unwrap());

        assert_eq!(ks.name().to_string(), "example.com");
    }

    #[test]
    fn test_rolls() {
        let mut ks = KeySet::new(Name::from_str("example.com").unwrap());

        ks.add_key_ksk(
            "first KSK".to_string(),
            None,
            SecurityAlgorithm::ECDSAP256SHA256,
            0,
            UnixTime::now(),
        )
        .unwrap();
        ks.add_key_zsk(
            "first ZSK".to_string(),
            None,
            SecurityAlgorithm::ECDSAP256SHA256,
            1,
            UnixTime::now(),
        )
        .unwrap();

        let actions = ks
            .start_roll(
                RollType::AlgorithmRoll,
                &[],
                &["first KSK", "first ZSK"],
            )
            .unwrap();
        assert_eq!(
            actions,
            [
                Action::UpdateDnskeyRrset,
                Action::UpdateRrsig,
                Action::ReportDnskeyPropagated,
                Action::ReportRrsigPropagated
            ]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first KSK", "first ZSK"]);
        assert_eq!(dnskey_sigs(&ks), ["first KSK"]);
        assert_eq!(zone_sigs(&ks), ["first ZSK"]);
        assert_eq!(ds_keys(&ks), Vec::<String>::new());

        let actions = ks
            .propagation1_complete(RollType::AlgorithmRoll, 3600)
            .unwrap();
        assert_eq!(actions, []);

        MockClock::advance_system_time(Duration::from_secs(3600));

        let actions = ks.cache_expired1(RollType::AlgorithmRoll).unwrap();
        assert_eq!(
            actions,
            [
                Action::CreateCdsRrset,
                Action::UpdateDsRrset,
                Action::ReportDsPropagated,
            ]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first KSK", "first ZSK"]);
        assert_eq!(dnskey_sigs(&ks), ["first KSK"]);
        assert_eq!(zone_sigs(&ks), ["first ZSK"]);
        assert_eq!(ds_keys(&ks), ["first KSK"]);

        let actions = ks
            .propagation2_complete(RollType::AlgorithmRoll, 3600)
            .unwrap();
        assert_eq!(actions, []);

        MockClock::advance_system_time(Duration::from_secs(3600));

        let actions = ks.cache_expired2(RollType::AlgorithmRoll).unwrap();
        assert_eq!(
            actions,
            [
                Action::RemoveCdsRrset,
                Action::UpdateDnskeyRrset,
                Action::UpdateRrsig,
                Action::WaitDnskeyPropagated,
                Action::WaitRrsigPropagated,
            ]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first KSK", "first ZSK"]);
        assert_eq!(dnskey_sigs(&ks), ["first KSK"]);
        assert_eq!(zone_sigs(&ks), ["first ZSK"]);
        assert_eq!(ds_keys(&ks), ["first KSK"]);

        let actions = ks.roll_done(RollType::AlgorithmRoll).unwrap();
        assert_eq!(actions, []);

        ks.add_key_ksk(
            "second KSK".to_string(),
            None,
            SecurityAlgorithm::ECDSAP256SHA256,
            2,
            UnixTime::now(),
        )
        .unwrap();
        ks.add_key_zsk(
            "second ZSK".to_string(),
            None,
            SecurityAlgorithm::ECDSAP256SHA256,
            3,
            UnixTime::now(),
        )
        .unwrap();

        println!("line {} = {:?}", line!(), ks.keys().get("second ZSK"));
        let actions = ks
            .start_roll(RollType::ZskRoll, &["first ZSK"], &["second ZSK"])
            .unwrap();
        println!("line {} = {:?}", line!(), ks.keys().get("second ZSK"));
        assert_eq!(
            actions,
            [Action::UpdateDnskeyRrset, Action::ReportDnskeyPropagated]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first KSK", "first ZSK", "second ZSK"]);
        assert_eq!(dnskey_sigs(&ks), ["first KSK"]);
        println!("keys = {:?}", ks.keys());
        assert_eq!(zone_sigs(&ks), ["first ZSK"]);
        assert_eq!(ds_keys(&ks), ["first KSK"]);

        let actions =
            ks.propagation1_complete(RollType::ZskRoll, 3600).unwrap();
        assert_eq!(actions, []);

        MockClock::advance_system_time(Duration::from_secs(3600));

        let actions = ks.cache_expired1(RollType::ZskRoll).unwrap();
        assert_eq!(
            actions,
            [Action::UpdateRrsig, Action::ReportRrsigPropagated]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first KSK", "first ZSK", "second ZSK"]);
        assert_eq!(dnskey_sigs(&ks), ["first KSK"]);
        assert_eq!(zone_sigs(&ks), ["second ZSK"]);
        assert_eq!(ds_keys(&ks), ["first KSK"]);

        let actions =
            ks.propagation2_complete(RollType::ZskRoll, 3600).unwrap();
        assert_eq!(actions, []);

        MockClock::advance_system_time(Duration::from_secs(3600));

        let actions = ks.cache_expired2(RollType::ZskRoll).unwrap();
        assert_eq!(actions, [Action::UpdateDnskeyRrset]);
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first KSK", "second ZSK"]);
        assert_eq!(dnskey_sigs(&ks), ["first KSK"]);
        assert_eq!(zone_sigs(&ks), ["second ZSK"]);
        assert_eq!(ds_keys(&ks), ["first KSK"]);

        let actions = ks.roll_done(RollType::ZskRoll).unwrap();
        assert_eq!(actions, []);
        ks.delete_key("first ZSK").unwrap();

        let actions = ks
            .start_roll(RollType::KskRoll, &["first KSK"], &["second KSK"])
            .unwrap();
        assert_eq!(
            actions,
            [Action::UpdateDnskeyRrset, Action::ReportDnskeyPropagated]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first KSK", "second KSK", "second ZSK"]);
        let mut dks = dnskey_sigs(&ks);
        dks.sort();
        assert_eq!(dks, ["first KSK", "second KSK"]);
        assert_eq!(zone_sigs(&ks), ["second ZSK"]);
        assert_eq!(ds_keys(&ks), ["first KSK"]);

        let actions =
            ks.propagation1_complete(RollType::KskRoll, 3600).unwrap();
        assert_eq!(actions, []);

        MockClock::advance_system_time(Duration::from_secs(3600));

        let actions = ks.cache_expired1(RollType::KskRoll).unwrap();
        assert_eq!(
            actions,
            [
                Action::CreateCdsRrset,
                Action::UpdateDsRrset,
                Action::ReportDsPropagated
            ]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first KSK", "second KSK", "second ZSK"]);
        let mut dks = dnskey_sigs(&ks);
        dks.sort();
        assert_eq!(dks, ["first KSK", "second KSK"]);
        assert_eq!(zone_sigs(&ks), ["second ZSK"]);
        assert_eq!(ds_keys(&ks), ["second KSK"]);

        let actions =
            ks.propagation2_complete(RollType::KskRoll, 3600).unwrap();
        assert_eq!(actions, []);

        MockClock::advance_system_time(Duration::from_secs(3600));

        let actions = ks.cache_expired2(RollType::KskRoll).unwrap();
        assert_eq!(
            actions,
            [Action::RemoveCdsRrset, Action::UpdateDnskeyRrset]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["second KSK", "second ZSK"]);
        assert_eq!(dnskey_sigs(&ks), ["second KSK"]);
        assert_eq!(zone_sigs(&ks), ["second ZSK"]);
        assert_eq!(ds_keys(&ks), ["second KSK"]);

        let actions = ks.roll_done(RollType::KskRoll).unwrap();
        assert_eq!(actions, []);
        ks.delete_key("first KSK").unwrap();

        ks.add_key_csk(
            "first CSK".to_string(),
            None,
            SecurityAlgorithm::ECDSAP256SHA256,
            0,
            UnixTime::now(),
        )
        .unwrap();

        let actions = ks
            .start_roll(
                RollType::CskRoll,
                &["second KSK", "second ZSK"],
                &["first CSK"],
            )
            .unwrap();
        assert_eq!(
            actions,
            [Action::UpdateDnskeyRrset, Action::ReportDnskeyPropagated]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first CSK", "second KSK", "second ZSK"]);
        let mut dks = dnskey_sigs(&ks);
        dks.sort();
        assert_eq!(dks, ["first CSK", "second KSK"]);
        assert_eq!(zone_sigs(&ks), ["second ZSK"]);
        assert_eq!(ds_keys(&ks), ["second KSK"]);

        let actions =
            ks.propagation1_complete(RollType::CskRoll, 3600).unwrap();
        assert_eq!(actions, []);

        MockClock::advance_system_time(Duration::from_secs(3600));

        let actions = ks.cache_expired1(RollType::CskRoll).unwrap();
        assert_eq!(
            actions,
            [
                Action::CreateCdsRrset,
                Action::UpdateDsRrset,
                Action::UpdateRrsig,
                Action::ReportDsPropagated,
                Action::ReportRrsigPropagated
            ]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first CSK", "second KSK", "second ZSK"]);
        let mut dks = dnskey_sigs(&ks);
        dks.sort();
        assert_eq!(dks, ["first CSK", "second KSK"]);
        assert_eq!(zone_sigs(&ks), ["first CSK"]);
        assert_eq!(ds_keys(&ks), ["first CSK"]);

        let actions =
            ks.propagation2_complete(RollType::CskRoll, 3600).unwrap();
        assert_eq!(actions, []);

        MockClock::advance_system_time(Duration::from_secs(3600));

        let actions = ks.cache_expired2(RollType::CskRoll).unwrap();
        assert_eq!(
            actions,
            [Action::RemoveCdsRrset, Action::UpdateDnskeyRrset]
        );
        assert_eq!(dnskey(&ks), ["first CSK"]);
        assert_eq!(dnskey_sigs(&ks), ["first CSK"]);
        assert_eq!(zone_sigs(&ks), ["first CSK"]);
        assert_eq!(ds_keys(&ks), ["first CSK"]);

        let actions = ks.roll_done(RollType::CskRoll).unwrap();
        assert_eq!(actions, []);
        ks.delete_key("second KSK").unwrap();
        ks.delete_key("second ZSK").unwrap();

        ks.add_key_csk(
            "second CSK".to_string(),
            None,
            SecurityAlgorithm::ECDSAP256SHA256,
            4,
            UnixTime::now(),
        )
        .unwrap();

        let actions = ks
            .start_roll(RollType::CskRoll, &["first CSK"], &["second CSK"])
            .unwrap();
        assert_eq!(
            actions,
            [Action::UpdateDnskeyRrset, Action::ReportDnskeyPropagated]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first CSK", "second CSK"]);
        let mut dks = dnskey_sigs(&ks);
        dks.sort();
        assert_eq!(dks, ["first CSK", "second CSK"]);
        assert_eq!(zone_sigs(&ks), ["first CSK"]);
        assert_eq!(ds_keys(&ks), ["first CSK"]);

        let actions =
            ks.propagation1_complete(RollType::CskRoll, 3600).unwrap();
        assert_eq!(actions, []);

        MockClock::advance_system_time(Duration::from_secs(3600));

        println!("CSK roll cache expired1");
        let actions = ks.cache_expired1(RollType::CskRoll).unwrap();
        assert_eq!(
            actions,
            [
                Action::CreateCdsRrset,
                Action::UpdateDsRrset,
                Action::UpdateRrsig,
                Action::ReportDsPropagated,
                Action::ReportRrsigPropagated
            ]
        );
        let mut dk = dnskey(&ks);
        dk.sort();
        assert_eq!(dk, ["first CSK", "second CSK"]);
        let mut dks = dnskey_sigs(&ks);
        dks.sort();
        assert_eq!(dks, ["first CSK", "second CSK"]);
        assert_eq!(zone_sigs(&ks), ["second CSK"]);
        assert_eq!(ds_keys(&ks), ["second CSK"]);

        let actions =
            ks.propagation2_complete(RollType::CskRoll, 3600).unwrap();
        assert_eq!(actions, []);

        MockClock::advance_system_time(Duration::from_secs(3600));

        let actions = ks.cache_expired2(RollType::CskRoll).unwrap();
        assert_eq!(
            actions,
            [Action::RemoveCdsRrset, Action::UpdateDnskeyRrset]
        );
        assert_eq!(dnskey(&ks), ["second CSK"]);
        assert_eq!(dnskey_sigs(&ks), ["second CSK"]);
        assert_eq!(zone_sigs(&ks), ["second CSK"]);
        assert_eq!(ds_keys(&ks), ["second CSK"]);

        let actions = ks.roll_done(RollType::CskRoll).unwrap();
        assert_eq!(actions, []);
        ks.delete_key("first CSK").unwrap();
    }

    fn dnskey(ks: &KeySet) -> Vec<String> {
        ks.keys()
            .iter()
            .filter(|(_, k)| {
                let status = match k.keytype() {
                    KeyType::Ksk(keystate)
                    | KeyType::Zsk(keystate)
                    | KeyType::Csk(keystate, _)
                    | KeyType::Include(keystate) => keystate,
                };
                status.present()
            })
            .map(|(pr, _)| pr.to_string())
            .collect()
    }

    fn dnskey_sigs(ks: &KeySet) -> Vec<String> {
        let keys = ks.keys();
        let mut vec = Vec::new();
        for (pubref, key) in keys {
            match key.keytype() {
                KeyType::Ksk(keystate) | KeyType::Csk(keystate, _) => {
                    if keystate.signer() {
                        vec.push(pubref.to_string());
                    }
                }
                KeyType::Zsk(_) | KeyType::Include(_) => (),
            }
        }
        vec
    }
    fn zone_sigs(ks: &KeySet) -> Vec<String> {
        let keys = ks.keys();
        let mut vec = Vec::new();
        for (pubref, key) in keys {
            match key.keytype() {
                KeyType::Zsk(keystate) | KeyType::Csk(_, keystate) => {
                    if keystate.signer() {
                        vec.push(pubref.to_string());
                    }
                }
                KeyType::Ksk(_) | KeyType::Include(_) => (),
            }
        }
        vec
    }
    fn ds_keys(ks: &KeySet) -> Vec<String> {
        let keys = ks.keys();
        let mut vec = Vec::new();
        for (pubref, key) in keys {
            let status = match key.keytype() {
                KeyType::Ksk(keystate)
                | KeyType::Zsk(keystate)
                | KeyType::Csk(keystate, _)
                | KeyType::Include(keystate) => keystate,
            };
            if status.at_parent() {
                vec.push(pubref.to_string());
            }
        }
        vec
    }
}
