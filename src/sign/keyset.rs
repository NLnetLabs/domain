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
    csk_roll: RollState,
}

impl KeySet {
    pub fn new(name: Name<Vec<u8>>) -> Self {
	Self { name, keys: Vec::new(), ksk_roll: RollState::Idle,
		zsk_roll: RollState::Idle,
		csk_roll: RollState::Idle }
    }

    pub fn add_key_ksk(&mut self, pubref: String, privref: Option<String>, creation_ts: UnixTime) {
	let keystate: KeyState = Default::default();
	let key = Key::new(pubref, privref, KeyType::Ksk(keystate), creation_ts);
	self.keys.push(key);
    }

    pub fn add_key_zsk(&mut self, pubref: String, privref: Option<String>, creation_ts: UnixTime) {
	let keystate: KeyState = Default::default();
	let key = Key::new(pubref, privref, KeyType::Zsk(keystate), creation_ts);
	self.keys.push(key);
    }

    pub fn add_key_csk(&mut self, pubref: String, privref: Option<String>, creation_ts: UnixTime) {
	let keystate: KeyState = Default::default();
	let key = Key::new(pubref, privref, KeyType::Csk(keystate.clone(), keystate), creation_ts);
	self.keys.push(key);
    }

    pub fn delete_key(&mut self, pubref: &str) {
	// Assume no duplicate keys.
	for i in 0..self.keys.len() {
	    if self.keys[i].pubref != pubref {
		continue;
	    }
	    match &self.keys[i].keytype {
		KeyType::Ksk(keystate)
		| KeyType::Zsk(keystate)
		| KeyType::Include(keystate)
			=> {
		    if !keystate.old || keystate.signer || keystate.present ||
			keystate.at_parent {
			// Should return error.
			todo!();
		    }
		    self.keys.remove(i);
		    return;
		}
		KeyType::Csk(ksk_keystate, zsk_keystate) => {
		    if !ksk_keystate.old || ksk_keystate.signer || ksk_keystate.present ||
			ksk_keystate.at_parent {
			// Should return error.
			todo!();
		    }
		    if !zsk_keystate.old || zsk_keystate.signer || zsk_keystate.present ||
			zsk_keystate.at_parent {
			// Should return error.
			todo!();
		    }
		    self.keys.remove(i);
		    return;
		}
	    }
	    
	}
	todo!();
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
	    let KeyType::Ksk(ref keystate) = k.keytype 
	    else {
		continue;
	    };
	    if keystate.old || !keystate.present {
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
	    let KeyType::Ksk(ref keystate) = k.keytype 
	    else {
		continue;
	    };
	    if keystate.old || !keystate.present {
		continue;
	    }

	    let visible = k.timestamps.visible.as_ref().unwrap();
	    if visible.elapsed() < Duration::from_secs(ttl.into()) {
		// Should report error.
		println!("ksk_roll_cache_expired1: elapsed {:?}, waiting for {ttl}", visible.elapsed());
		todo!();
	    }
	}

	for k in &mut self.keys {
	    match k.keytype {	    
		KeyType::Ksk(ref mut keystate) => {
		    if keystate.old && keystate.present {
			keystate.at_parent = false;
		    }

		    if !keystate.old && keystate.present {
			keystate.at_parent = true;
		    }
		}
		_ => ()
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
	    let KeyType::Ksk(ref keystate) = k.keytype 
	    else {
		continue;
	    };
	    if keystate.old || !keystate.present {
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
	    let KeyType::Ksk(ref keystate) = k.keytype 
	    else {
		continue;
	    };
	    if keystate.old || !keystate.present {
		continue;
	    }

	    let ds_visible = k.timestamps.ds_visible.as_ref().unwrap();
	    if ds_visible.elapsed() < Duration::from_secs(ttl.into()) {
		// Should report error.
		println!("ksk_roll_cache_expired2: elapsed {:?}, waiting for {ttl}", ds_visible.elapsed());
		todo!();
	    }
	}

	// Move old keys out
	for k in &mut self.keys {
	    let KeyType::Ksk(ref mut keystate) = k.keytype 
	    else {
		continue;
	    };
	    if keystate.old && keystate.present {
		keystate.signer = false;
		keystate.present = false;
		k.timestamps.withdrawn = Some(UnixTime::now());
	    }

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
	    let KeyType::Zsk(ref keystate) = k.keytype 
	    else {
		continue;
	    };
	    if keystate.old || !keystate.present {
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
	    let KeyType::Zsk(ref keystate) = k.keytype 
	    else {
		continue;
	    };
	    if keystate.old || !keystate.present {
		continue;
	    }

	    let visible = k.timestamps.visible.as_ref().unwrap();
	    if visible.elapsed() < Duration::from_secs(ttl.into()) {
		// Should report error.
		println!("zsk_roll_cache_expired1: elapsed {:?}, waiting for {ttl}", visible.elapsed());
		todo!();
	    }
	}

	// Move the Incoming keys to Active. Move the Leaving keys to
	// Retired.
	for k in &mut self.keys {
	    let KeyType::Zsk(ref mut keystate) = k.keytype 
	    else {
		continue;
	    };
	    if !keystate.old && keystate.present {
		keystate.signer = true;
	    }
	    if keystate.old {
		keystate.signer = false;
	    }

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
	    let KeyType::Zsk(ref keystate) = k.keytype
	    else {
		continue;
	    };
	    if keystate.old || !keystate.signer {
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
	    let KeyType::Zsk(ref keystate) = k.keytype 
	    else {
		continue;
	    };
	    if keystate.old || !keystate.signer {
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
	for k in &mut self.keys {
	    let KeyType::Zsk(ref mut keystate) = k.keytype 
	    else {
		continue;
	    };
	    if keystate.old && !keystate.signer {
		keystate.present = false;
		k.timestamps.withdrawn = Some(UnixTime::now());
	    }

	}

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

    pub fn start_csk_roll(&mut self, old: &[&str], new: &[&str]) -> Vec<Action> {
	// First check if the current CSK-roll state is idle. We need to check
	// all conflicting key rolls as well.
	if let RollState::Idle = self.csk_roll {
	    // this is fine.
	} else {
	    // Should return an error.
	    todo!();
	}
	// Check if we can move the states of the keys
	self.update_csk(Mode::DryRun, old, new);
	// Move the states of the keys
	self.update_csk(Mode::ForReal, old, new);
	// Move to the next state.
	// Return actions that need to be performed by the caller.

	self.csk_roll = RollState::Propagation1;
	let mut actions = Vec::new();
	actions.push(Action::UpdateDnskeyRrset);
	actions.push(Action::ReportDnskeyPropagated);
	actions
    }

    pub fn csk_roll_propagation1_complete(&mut self, ttl: u32) -> Vec<Action> {
	// First check if the current CSK-roll state is propagation1.
	if let RollState::Propagation1 = self.csk_roll {
	    // this is fine.
	} else {
	    // Should return an error.
	    todo!();
	}

	// Set the visiable time of new KSKs, ZSKs and CSKs to the current
	// time.
	let now = UnixTime::now();
	for k in &mut self.keys {
	    match &k.keytype {
		KeyType::Ksk(keystate)
		| KeyType::Zsk(keystate)
		| KeyType::Csk(keystate, _)
			=> {
		    if keystate.old || !keystate.present {
			continue;
		    }

		    k.timestamps.visible = Some(now.clone());
		}
		KeyType::Include(_) => ()
	    }
	}

	self.csk_roll = RollState::CacheExpire1(ttl);
	let actions = Vec::new();
	actions
    }

    pub fn csk_roll_cache_expired1(&mut self) -> Vec<Action> {
	// First check if the current CSK-roll state is CacheExpire1.
	let RollState::CacheExpire1(ttl) = self.csk_roll 
	else {
	    // Should return an error.
	    todo!();
	};

	for k in &mut self.keys {
	    let keystate = match &k.keytype {
		KeyType::Ksk(keystate)
		| KeyType::Zsk(keystate)
		| KeyType::Csk(keystate, _)
		=> keystate,
		KeyType::Include(_) => continue
	    };
	    if keystate.old || !keystate.present {
		continue;
	    }

	    let visible = k.timestamps.visible.as_ref().unwrap();
	    if visible.elapsed() < Duration::from_secs(ttl.into()) {
		// Should report error.
		println!("csk_roll_cache_expired1: elapsed {:?}, waiting for {ttl}", visible.elapsed());
		todo!();
	    }
	}

	for k in &mut self.keys {
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
		KeyType::Csk(ref mut ksk_keystate, ref mut zsk_keystate) => {
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
		_ => ()
	    }
	}

	self.csk_roll = RollState::Propagation2;
	let mut actions = Vec::new();
	actions.push(Action::CreateCdsRrset);
	actions.push(Action::UpdateDsRrset);
	actions.push(Action::UpdateRrsig);
	actions.push(Action::ReportDsPropagated);
	actions.push(Action::ReportRrsigPropagated);
	actions
    }

    pub fn csk_roll_propagation2_complete(&mut self, ttl: u32) -> Vec<Action> {
	// First check if the current CSK-roll state is propagation2.
	if let RollState::Propagation2 = self.csk_roll {
	    // this is fine.
	} else {
	    // Should return an error.
	    todo!();
	}

	// Set the published time of new DS records to the current time.
	let now = UnixTime::now();
	for k in &mut self.keys {
	    match &k.keytype {
		KeyType::Ksk(keystate)
		| KeyType::Csk(keystate, _)
		=> {
		    if keystate.old || !keystate.present {
			continue;
		    }

		    k.timestamps.ds_visible = Some(now.clone());
		}
		KeyType::Zsk(_) | KeyType::Include(_) => ()
	    }
	}

	// Set the published time of new RRSIG records to the current time.
	for k in &mut self.keys {
	    let keystate = match &k.keytype {
		KeyType::Zsk(keystate) |
		KeyType::Csk(_, keystate) => keystate,
		KeyType::Ksk(_) | KeyType::Include(_) => continue,

	    };
	    if keystate.old || !keystate.signer {
		continue;
	    }

	    k.timestamps.rrsig_visible = Some(now.clone());
	}


	self.csk_roll = RollState::CacheExpire2(ttl);
	let actions = Vec::new();
	actions
    }

    pub fn csk_roll_cache_expired2(&mut self) -> Vec<Action> {
	// First check if the current CSK-roll state is CacheExpire2.
	let RollState::CacheExpire2(ttl) = self.csk_roll 
	else {
	    // Should return an error.
	    todo!();
	};

	for k in &mut self.keys {
	    let keystate = match &k.keytype {
		KeyType::Zsk(keystate) |
		KeyType::Csk(_, keystate) => keystate,
		KeyType::Ksk(_) | KeyType::Include(_) => continue,
	    };
	    if keystate.old || !keystate.signer {
		continue;
	    }

	    let rrsig_visible = k.timestamps.rrsig_visible.as_ref().unwrap();
	    if rrsig_visible.elapsed() < Duration::from_secs(ttl.into()) {
		// Should report error.
		println!("csk_roll_cache_expired2: elapsed {:?}, waiting for {ttl}", rrsig_visible.elapsed());
		todo!();
	    }
	}

	// Move old keys out
	for k in &mut self.keys {
	    match k.keytype {
		KeyType::Ksk(ref mut keystate)
		| KeyType::Csk(ref mut keystate, _)
		=> {
		    if keystate.old && keystate.present {
			keystate.signer = false;
			keystate.present = false;
			k.timestamps.withdrawn = Some(UnixTime::now());
		    }
		}
		KeyType::Zsk(_) | KeyType::Include(_) => ()
	    }
	}
	for k in &mut self.keys {
	    match k.keytype {
		KeyType::Zsk(ref mut keystate)
		| KeyType::Csk(_, ref mut keystate) => {
		    if keystate.old && !keystate.signer {
			keystate.present = false;
			k.timestamps.withdrawn = Some(UnixTime::now());
		    }
		}
		KeyType::Ksk(_) | KeyType::Include(_) => ()
	    }
	}


	self.csk_roll = RollState::Done;
	let mut actions = Vec::new();
	actions.push(Action::RemoveCdsRrset);
	actions.push(Action::UpdateDnskeyRrset);
	actions
    }

    pub fn csk_roll_done(&mut self) -> Vec<Action> {
	// First check if the current CSK-roll state is Done.
	let RollState::Done = self.csk_roll 
	else {
	    // Should return an error.
	    todo!();
	};

	self.csk_roll = RollState::Idle;
	let actions = Vec::new();
	actions
    }



    fn update_ksk(&mut self, mode: Mode, old: &[&str], new: &[&str]) {
	let keys: &mut Vec<Key> = match mode {
	    Mode::DryRun => &mut self.keys.clone(),
	    Mode::ForReal => &mut self.keys,
	};
	'outer:
	for k in old {
	    for i in 0..keys.len() {
		if keys[i].pubref != *k {
		    continue;
		}
		let KeyType::Ksk(ref mut keystate) = keys[i].keytype
		else {
		    // Should return error for wrong key type.
		    todo!();
		};

		// Set old for any key we find.
		keystate.old = true;
		continue 'outer;
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
		match keys[i].keytype {
		    KeyType::Ksk(ref mut keystate) => {
			if *keystate != (KeyState { old: false,
			    signer: false, present: false, at_parent: false }) {
			    // Should return error for wrong key state.
			    todo!();
			}

			// Move key state to Incoming.
			keystate.present = true;
			keystate.signer = true;
			keys[i].timestamps.published = Some(now.clone());
			continue 'outer;
		    }
		    _ => {
			// Should return error for wrong key type.
			todo!();
		    }
		}
	    }

	    // Should return error for unknown pubref.
	    todo!();
	}

	// Make sure we have at least one key in incoming state.
	if keys.into_iter().filter(|k| if let KeyType::Ksk(keystate) = &k.keytype { !keystate.old && keystate.present } else { false })
		.next()
		.is_none() {
	    // Should return error.
	    todo!();
	}
    }

    fn update_zsk(&mut self, mode: Mode, old: &[&str], new: &[&str]) {
	let keys: &mut Vec<Key> = match mode {
	    Mode::DryRun => &mut self.keys.clone(),
	    Mode::ForReal => &mut self.keys,
	};
	'outer:
	for k in old {
	    for i in 0..keys.len() {
		if keys[i].pubref != *k {
		    continue;
		}
		let KeyType::Zsk(ref mut keystate) = keys[i].keytype
		else {
		    // Should return error for wrong key type.
		    todo!();
		};

		// Set old for any key we find.
		keystate.old = true;
		continue 'outer;
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
		let KeyType::Zsk(ref mut keystate) = keys[i].keytype
		else {
		    // Should return error for wrong key type.
		    todo!();
		};
		if *keystate != (KeyState { old: false,
		    signer: false, present: false, at_parent: false }) {
		    // Should return error for wrong key state.
		    todo!();
		}

		// Move key state to Incoming.
		keystate.present = true;
		keys[i].timestamps.published = Some(now.clone());
		continue 'outer;
	    }

	    // Should return error for unknown pubref.
	    todo!();
	}

	// Make sure we have at least one key in incoming state.
	if keys.into_iter().filter(|k| if let KeyType::Zsk(keystate) = &k.keytype { !keystate.old || keystate.present } else { false })
	    .next().is_none() {
	    // Should return error.
	    todo!();
	}
    }

    fn update_csk(&mut self, mode: Mode, old: &[&str], new: &[&str]) {
	let keys: &mut Vec<Key> = match mode {
	    Mode::DryRun => &mut self.keys.clone(),
	    Mode::ForReal => &mut self.keys,
	};
	'outer:
	for k in old {
	    for i in 0..keys.len() {
		if keys[i].pubref != *k {
		    continue;
		}

		// Set old for any key we find.
		match keys[i].keytype {
		    KeyType::Ksk(ref mut keystate) 
		    | KeyType::Zsk(ref mut keystate)
			=> {
			keystate.old = true;
		    }
		    KeyType::Csk(ref mut ksk_keystate, ref mut zsk_keystate) => { 
			ksk_keystate.old = true;
			zsk_keystate.old = true;
		    }
		    KeyType::Include(_)
		    => {
			// Should return error for wrong key type.
			todo!();
		    }
		}
		continue 'outer;
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
		match keys[i].keytype {
		    KeyType::Ksk(ref mut keystate) => {
			if *keystate != (KeyState { old: false,
			    signer: false, present: false, at_parent: false }) {
			    // Should return error for wrong key state.
			    todo!();
			}

			// Move key state to Active.
			keystate.present = true;
			keystate.signer = true;
			keys[i].timestamps.published = Some(now.clone());
			continue 'outer;
		    }
		    KeyType::Zsk(ref mut keystate) => {
			if *keystate != (KeyState { old: false,
			    signer: false, present: false, at_parent: false }) {
			    // Should return error for wrong key state.
			    todo!();
			}

			// Move key state to Incoming.
			keystate.present = true;
			keys[i].timestamps.published = Some(now.clone());
			continue 'outer;
		    }
		    KeyType::Csk(ref mut ksk_keystate, ref mut zsk_keystate) => {
			if *ksk_keystate != (KeyState { old: false,
			    signer: false, present: false, at_parent: false }) {
			    // Should return error for wrong key state.
			    todo!();
			}

			// Move key state to Active.
			ksk_keystate.present = true;
			ksk_keystate.signer = true;

			if *zsk_keystate != (KeyState { old: false,
			    signer: false, present: false, at_parent: false }) {
			    // Should return error for wrong key state.
			    todo!();
			}

			// Move key state to Incoming.
			zsk_keystate.present = true;

			keys[i].timestamps.published = Some(now.clone());
			continue 'outer;
		    }
		    _ => {
			// Should return error for wrong key type.
			todo!();
		    }
		}
	    }

	    // Should return error for unknown pubref.
	    todo!();
	}

	// Make sure we have at least one KSK key in incoming state.
	if keys.into_iter().filter(|k|
		match &k.keytype {
		    KeyType::Ksk(keystate)
		    | KeyType::Csk(keystate, _)
			=> !keystate.old && keystate.present,
		    _ => false
		}
		)
		.next()
		.is_none() {
	    // Should return error.
	    todo!();
	}
	// Make sure we have at least one ZSK key in incoming state.
	if keys.into_iter().filter(|k|
		match &k.keytype {
		    KeyType::Zsk(keystate)
		    | KeyType::Csk(_, keystate)
			=> !keystate.old && keystate.present,
		    _ => false
		}
		)
		.next()
		.is_none() {
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
    timestamps: KeyTimestamps,
}

impl Key {
    pub fn pubref(&self) -> &str {
	&self.pubref
    }

    pub fn privref(&self) -> Option<&str> {
	self.privref.as_ref().map(|x| x.as_str())
    }

    pub fn keytype(&self) -> KeyType {
	self.keytype.clone()
    }

    pub fn timestamps(&self) -> &KeyTimestamps {
	&self.timestamps
    }

    fn new(pubref: String, privref: Option<String>,
	keytype: KeyType, creation_ts: UnixTime) -> Self {
	let mut timestamps: KeyTimestamps = Default::default();
	timestamps.creation = Some(creation_ts);
	Self { pubref, privref, keytype,
	   timestamps }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum KeyType {
    Ksk(KeyState),
    Zsk(KeyState),
    Csk(KeyState, KeyState),
    Include(KeyState),
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
/*
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
*/
pub struct KeyState {
    old: bool,
    signer: bool,
    present: bool,
    at_parent: bool,
}

impl KeyState {
    pub fn signer(&self) -> bool { self.signer }
    pub fn present(&self) -> bool { self.present }
    pub fn at_parent(&self) -> bool { self.at_parent }
}

impl Display for KeyState {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
	let mut first = true;
	if self.old {
	    write!(f, "Old")?;
	    first= false;
	}
	if self.signer {
	    write!(f, "{}Signer", if first { "" } else { ", " })?;
	    first= false;
	}
	if self.present {
	    write!(f, "{}Present", if first { "" } else { ", " })?;
	    first= false;
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
	    (_, _, _) => ()
	}
	Ok(())
    }
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
