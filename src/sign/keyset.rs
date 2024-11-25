/// A key set is a collection of key used to sign a zone. The module
/// support the management of key sets including key rollover.

use crate::base::Name;
use std::vec::Vec;
use std::string::String;
//use std::time::Instant;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::string::ToString;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::fmt::Debug;
use time::OffsetDateTime;
use time::format_description;

#[derive(Deserialize, Serialize)]
pub struct KeySet {
    name: Name<Vec<u8>>,
    keys: Vec<Key>,

    ksk_roll: RollState,
    zsk_roll: RollState,
}

impl KeySet {
    pub fn new(name: Name<Vec<u8>>) -> Self {
	Self { name, keys: Vec::new(), ksk_roll: RollState::Idle,
		zsk_roll: RollState::Idle }
    }

    pub fn add_key(&mut self, pubref: String, privref: Option<String>, keytype: KeyType, keystate: KeyState, creation_ts: UnixTime) {
	let key = Key::new(pubref, privref, keytype, keystate, creation_ts);
	self.keys.push(key);
    }

    pub fn name(&self) -> String {
	self.name.to_string()
    }

    pub fn keys(&self) -> &[Key] {
	&self.keys
    }

    pub fn start_ksk_roll(&mut self, old: &[&str], new: &[&str]) -> Vec<Action> {
	// First check if the current KSK-roll state is idle. We need to check
	// all conflicting key rolls as well.
	if let RollState::Idle = self.ksk_roll {
	    // this is fine.
	} else {
	    // Should return an error.
	    todo!();
	}
	// Check if we can move the states of the keys
	self.update_ksk(Mode::DryRun, old, new);
	// Move the states of the keys
	self.update_ksk(Mode::ForReal, old, new);
	// Move to the next state.
	// Return actions that need to be performed by the caller.

	self.ksk_roll = RollState::Propagation1;
	let mut actions = Vec::new();
	actions.push(Action::UpdateDnskeyRrset);
	actions.push(Action::ReportDnskeyPropagated);
	actions
    }

    pub fn ksk_roll_propagation1_complete(&mut self, ttl: u32) -> Vec<Action> {
	// First check if the current KSK-roll state is propagation1.
	if let RollState::Propagation1 = self.ksk_roll {
	    // this is fine.
	} else {
	    // Should return an error.
	    todo!();
	}
	// Set the visible time of new KSKs to the current time.
	let now = UnixTime::now();
	for k in &mut self.keys {
	    if let KeyType::Ksk = k.keytype {
		// Fine.
	    }
	    else {
		continue;
	    }
	    if let KeyState::Incoming = k.keystate {
		// Fine.
	    }
	    else {
		continue;
	    }

	    k.timestamps.visible = Some(now.clone());
	}

	self.ksk_roll = RollState::CacheExpire1(ttl);
	let actions = Vec::new();
	actions
    }

    pub fn ksk_roll_cache_expired1(&mut self) -> Vec<Action> {
	// First check if the current KSK-roll state is CacheExpire1.
	let RollState::CacheExpire1(ttl) = self.ksk_roll 
	else {
	    // Should return an error.
	    todo!();
	};

	for k in &mut self.keys {
	    if let KeyType::Ksk = k.keytype {
		// Fine.
	    }
	    else {
		continue;
	    }
	    if let KeyState::Incoming = k.keystate {
		// Fine.
	    }
	    else {
		continue;
	    }

	    let visible = k.timestamps.visible.as_ref().unwrap();
	    if visible.elapsed() < Duration::from_secs(ttl.into()) {
		// Should report error.
		println!("ksk_roll_cache_expired1: elapsed {:?}, waiting for {ttl}", visible.elapsed());
		todo!();
	    }
	}

	self.ksk_roll = RollState::Propagation2;
	let mut actions = Vec::new();
	actions.push(Action::CreateCdsRrset);
	actions.push(Action::UpdateDsRrset);
	actions.push(Action::ReportDsPropagated);
	actions
    }

    pub fn ksk_roll_propagation2_complete(&mut self, ttl: u32) -> Vec<Action> {
	// First check if the current KSK-roll state is propagation2.
	if let RollState::Propagation2 = self.ksk_roll {
	    // this is fine.
	} else {
	    // Should return an error.
	    todo!();
	}
	// Set the published time of new DS records to the current time.
	let now = UnixTime::now();
	for k in &mut self.keys {
	    if let KeyType::Ksk = k.keytype {
		// Fine.
	    }
	    else {
		continue;
	    }
	    if let KeyState::Incoming = k.keystate {
		// Fine.
	    }
	    else {
		continue;
	    }

	    k.timestamps.ds_visible = Some(now.clone());
	}

	self.ksk_roll = RollState::CacheExpire2(ttl);
	let actions = Vec::new();
	actions
    }

    pub fn ksk_roll_cache_expired2(&mut self) -> Vec<Action> {
	// First check if the current KSK-roll state is CacheExpire2.
	let RollState::CacheExpire2(ttl) = self.ksk_roll 
	else {
	    // Should return an error.
	    todo!();
	};

	for k in &mut self.keys {
	    if let KeyType::Ksk = k.keytype {
		// Fine.
	    }
	    else {
		continue;
	    }
	    if let KeyState::Incoming = k.keystate {
		// Fine.
	    }
	    else {
		continue;
	    }

	    let ds_visible = k.timestamps.ds_visible.as_ref().unwrap();
	    if ds_visible.elapsed() < Duration::from_secs(ttl.into()) {
		// Should report error.
		println!("ksk_roll_cache_expired2: elapsed {:?}, waiting for {ttl}", ds_visible.elapsed());
		todo!();
	    }
	}

	// Move the Incoming keys to Active.
	for k in &mut self.keys {
	    if let KeyType::Ksk = k.keytype {
		// Fine.
	    }
	    else {
		continue;
	    }
	    if let KeyState::Incoming = k.keystate {
		// Fine.
	    }
	    else {
		continue;
	    }

	    k.keystate = KeyState::Active;
	}


	self.ksk_roll = RollState::Done;
	let mut actions = Vec::new();
	actions.push(Action::RemoveCdsRrset);
	actions.push(Action::UpdateDnskeyRrset);
	actions
    }

    pub fn ksk_roll_done(&mut self) -> Vec<Action> {
	// First check if the current KSK-roll state is Done.
	let RollState::Done = self.ksk_roll 
	else {
	    // Should return an error.
	    todo!();
	};

	self.ksk_roll = RollState::Idle;
	let actions = Vec::new();
	actions
    }

    pub fn start_zsk_roll(&mut self, old: &[&str], new: &[&str]) -> Vec<Action> {
	// First check if the current ZSK-roll state is idle. We need to check
	// all conflicting key rolls as well.
	if let RollState::Idle = self.zsk_roll {
	    // this is fine.
	} else {
	    // Should return an error.
	    todo!();
	}
	// Check if we can move the states of the keys
	self.update_zsk(Mode::DryRun, old, new);
	// Move the states of the keys
	self.update_zsk(Mode::ForReal, old, new);
	// Move to the next state.
	// Return actions that need to be performed by the caller.
	self.zsk_roll = RollState::Propagation1;
	let mut actions = Vec::new();
	actions.push(Action::UpdateDnskeyRrset);
	actions.push(Action::ReportDnskeyPropagated);
	actions
    }

    pub fn zsk_roll_propagation1_complete(&mut self, ttl: u32) -> Vec<Action> {
	// First check if the current ZSK-roll state is propagation1.
	if let RollState::Propagation1 = self.zsk_roll {
	    // this is fine.
	} else {
	    // Should return an error.
	    todo!();
	}
	// Set the visiable time of new ZSKs to the current time.
	let now = UnixTime::now();
	for k in &mut self.keys {
	    if let KeyType::Zsk = k.keytype {
		// Fine.
	    }
	    else {
		continue;
	    }
	    if let KeyState::Incoming = k.keystate {
		// Fine.
	    }
	    else {
		continue;
	    }

	    k.timestamps.visible = Some(now.clone());
	}

	self.zsk_roll = RollState::CacheExpire1(ttl);
	let actions = Vec::new();
	actions
    }

    pub fn zsk_roll_cache_expired1(&mut self) -> Vec<Action> {
	// First check if the current ZSK-roll state is CacheExpire1.
	let RollState::CacheExpire1(ttl) = self.zsk_roll 
	else {
	    // Should return an error.
	    todo!();
	};

	for k in &mut self.keys {
	    if let KeyType::Zsk = k.keytype {
		// Fine.
	    }
	    else {
		continue;
	    }
	    if let KeyState::Incoming = k.keystate {
		// Fine.
	    }
	    else {
		continue;
	    }

	    let visible = k.timestamps.visible.as_ref().unwrap();
	    if visible.elapsed() < Duration::from_secs(ttl.into()) {
		// Should report error.
		println!("zsk_roll_cache_expired1: elapsed {:?}, waiting for {ttl}", visible.elapsed());
		todo!();
	    }
	}

	// Move the Incoming keys to Active.
	for k in &mut self.keys {
	    if let KeyType::Zsk = k.keytype {
		// Fine.
	    }
	    else {
		continue;
	    }
	    if let KeyState::Incoming = k.keystate {
		// Fine.
	    }
	    else {
		continue;
	    }

	    k.keystate = KeyState::Active;
	}

	self.zsk_roll = RollState::Propagation2;
	let mut actions = Vec::new();
	actions.push(Action::UpdateRrsig);
	actions.push(Action::ReportRrsigPropagated);
	actions
    }

    pub fn zsk_roll_propagation2_complete(&mut self, ttl: u32) -> Vec<Action> {
	// First check if the current ZSK-roll state is propagation2.
	if let RollState::Propagation2 = self.zsk_roll {
	    // this is fine.
	} else {
	    // Should return an error.
	    todo!();
	}

	// Set the published time of new RRSIG records to the current time.
	let now = UnixTime::now();
	for k in &mut self.keys {
	    if let KeyType::Zsk = k.keytype {
		// Fine.
	    }
	    else {
		continue;
	    }
	    if let KeyState::Active = k.keystate {
		// Fine.
	    }
	    else {
		continue;
	    }

	    k.timestamps.rrsig_visible = Some(now.clone());
	}


	self.zsk_roll = RollState::CacheExpire2(ttl);
	let actions = Vec::new();
	actions
    }

    pub fn zsk_roll_cache_expired2(&mut self) -> Vec<Action> {
	// First check if the current ZSK-roll state is CacheExpire2.
	let RollState::CacheExpire2(ttl) = self.zsk_roll 
	else {
	    // Should return an error.
	    todo!();
	};

	for k in &mut self.keys {
	    if let KeyType::Zsk = k.keytype {
		// Fine.
	    }
	    else {
		continue;
	    }
	    if let KeyState::Active = k.keystate {
		// Fine.
	    }
	    else {
		continue;
	    }

	    let rrsig_visible = k.timestamps.rrsig_visible.as_ref().unwrap();
	    if rrsig_visible.elapsed() < Duration::from_secs(ttl.into()) {
		// Should report error.
		println!("zsk_roll_cache_expired2: elapsed {:?}, waiting for {ttl}", rrsig_visible.elapsed());
		todo!();
	    }
	}

	// Move old keys out

	self.zsk_roll = RollState::Done;
	let mut actions = Vec::new();
	actions.push(Action::UpdateDnskeyRrset);
	actions
    }

    pub fn zsk_roll_done(&mut self) -> Vec<Action> {
	// First check if the current ZSK-roll state is Done.
	let RollState::Done = self.zsk_roll 
	else {
	    // Should return an error.
	    todo!();
	};

	self.zsk_roll = RollState::Idle;
	let actions = Vec::new();
	actions
    }


    fn update_ksk(&mut self, mode: Mode, old: &[&str], new: &[&str]) {
	let keys: &mut Vec<Key> = match mode {
	    Mode::DryRun => &mut self.keys.clone(),
	    Mode::ForReal => &mut self.keys,
	};
	for k in old {
	    for i in 0..keys.len() {
		if keys[i].pubref != *k {
		    continue;
		}
		todo!();
	    }

	    // Should return error for unknown pubref.
	    todo!();
	}
	let now = UnixTime::now();
	'outer:
	for k in new {
	    for i in 0..keys.len() {
		if keys[i].pubref != *k {
		    continue;
		}
		if let KeyType::Ksk = keys[i].keytype {
		    // Fine.
		}
		else {
		    // Should return error for wrong key type.
		    todo!();
		}
		if let KeyState::Future = keys[i].keystate {
		    // Fine.
		}
		else {
		    // Should return error for wrong key state.
		    todo!();
		}

		// Move key state to Incoming.
		keys[i].keystate = KeyState::Incoming;
		keys[i].timestamps.published = Some(now.clone());
		continue 'outer;
	    }

	    // Should return error for unknown pubref.
	    todo!();
	}

	// Make sure we have at least one key in incoming state.
	if keys.into_iter().filter(|k| if let KeyType::Ksk = k.keytype { true } else { false }).
	    filter(|k| if let KeyState::Incoming = k.keystate { true } else { false }).next().is_none() {
	    // Should return error.
	    todo!();
	}
    }

    fn update_zsk(&mut self, mode: Mode, old: &[&str], new: &[&str]) {
	let keys: &mut Vec<Key> = match mode {
	    Mode::DryRun => &mut self.keys.clone(),
	    Mode::ForReal => &mut self.keys,
	};
	for k in old {
	    for i in 0..keys.len() {
		if keys[i].pubref != *k {
		    continue;
		}
		todo!();
	    }

	    // Should return error for unknown pubref.
	    todo!();
	}
	let now = UnixTime::now();
	'outer:
	for k in new {
	    for i in 0..keys.len() {
		if keys[i].pubref != *k {
		    continue;
		}
		if let KeyType::Zsk = keys[i].keytype {
		    // Fine.
		}
		else {
		    // Should return error for wrong key type.
		    todo!();
		}
		if let KeyState::Future = keys[i].keystate {
		    // Fine.
		}
		else {
		    // Should return error for wrong key state.
		    todo!();
		}

		// Move key state to Incoming.
		keys[i].keystate = KeyState::Incoming;
		keys[i].timestamps.published = Some(now.clone());
		continue 'outer;
	    }

	    // Should return error for unknown pubref.
	    todo!();
	}

	// Make sure we have at least one key in incoming state.
	if keys.into_iter().filter(|k| if let KeyType::Zsk = k.keytype { true } else { false }).
	    filter(|k| if let KeyState::Incoming = k.keystate { true } else { false }).next().is_none() {
	    // Should return error.
	    todo!();
	}
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Key {
    pubref: String,
    privref: Option<String>,
    keytype: KeyType,
    keystate: KeyState,
    timestamps: KeyTimestamps,
}

impl Key {
    pub fn pubref(&self) -> &str {
	&self.pubref
    }

    pub fn privref(&self) -> Option<&str> {
	self.privref.as_ref().map(|x| x.as_str())
    }

    pub fn status(&self) -> KeyState {
	self.keystate.clone()
    }

    pub fn timestamps(&self) -> &KeyTimestamps {
	&self.timestamps
    }

    fn new(pubref: String, privref: Option<String>,
	keytype: KeyType, keystate: KeyState, creation_ts: UnixTime) -> Self {
	let mut timestamps: KeyTimestamps = Default::default();
	timestamps.creation = Some(creation_ts);
	Self { pubref, privref, keytype, keystate,
	   timestamps }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum KeyType {
    Ksk,
    Zsk,
    Csk,
    Include,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum KeyState {
    // KeyState idea: 4 booleans
    // 1) old. Set if the key is on its way out
    // 2) signer. Set if the key signs the DNSKEY RRset or the zone.
    // 3) present. Set if the key is present in the DNSKET RRset.
    // 4) ds. Set if a DS record has to be present for the key.
    Future, // !old, !signer, !present, !ds
    Incoming, // !old, !signer, present, (ds || !ds)
    Active, // !old, signer, present, ds (if KSK)
    Leaving, // old, signer, present, ds (if KSK)
    Retired, // old, !signer, present, ds (if KSK)
    Past, // old, !signer, !present, !ds

    // Missing:
    // !old, !signer, !present, ds
    // !old, signer, !present, (ds || !ds)
    // old, signer, !present, (ds || !ds)
    // old, !signer, !present, ds
}

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
    pub fn creation(&self) -> Option<UnixTime> {
	self.creation.clone()
    }

    pub fn published(&self) -> Option<UnixTime> {
	self.published.clone()
    }

    pub fn visible(&self) -> Option<UnixTime> {
	self.visible.clone()
    }

    pub fn ds_visible(&self) -> Option<UnixTime> {
	self.ds_visible.clone()
    }

    pub fn rrsig_visible(&self) -> Option<UnixTime> {
	self.rrsig_visible.clone()
    }

    pub fn withdrawn(&self) -> Option<UnixTime> {
	self.withdrawn.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnixTime(Duration);

impl UnixTime {
    pub fn now() -> Self {
	let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
	UnixTime(dur)
    }
    pub fn elapsed(&self) -> Duration {
	let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
	if dur < self.0 {
	    // Clamp elapsed to zero.
	    Duration::ZERO
	}
	else {
	    dur - self.0
	}
    }
}

impl Display for UnixTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
	let ts = UNIX_EPOCH + self.0;
	let dt: OffsetDateTime = ts.into();
	let format = format_description::parse(
    "[year]-[month]-[day]T[hour]:[minute]:[second]",).unwrap();
	write!(f, "{}", dt.format(&format).unwrap())
    }
}

#[derive(Deserialize, Serialize)]
enum RollState {
    Idle,
    Propagation1,
    CacheExpire1(u32),
    Propagation2,
    CacheExpire2(u32),
    Done,
}

enum Mode {
    DryRun,
    ForReal
}

#[derive(Debug)]
pub enum Action {
    UpdateDnskeyRrset,
    CreateCdsRrset,
    RemoveCdsRrset,
    UpdateDsRrset,
    UpdateRrsig,
    ReportDnskeyPropagated,
    ReportDsPropagated,
    ReportRrsigPropagated,
}
