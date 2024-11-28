/// A key set is a collection of key used to sign a zone. The module
/// support the management of key sets including key rollover.
use crate::base::Name;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::string::{String, ToString};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::vec::Vec;
use time::format_description;
use time::OffsetDateTime;

#[derive(Deserialize, Serialize)]
pub struct KeySet {
    name: Name<Vec<u8>>,
    keys: Vec<Key>,

    rollstates: HashMap<RollType, RollState>,
}

impl KeySet {
    pub fn new(name: Name<Vec<u8>>) -> Self {
        Self {
            name,
            keys: Vec::new(),
            rollstates: HashMap::new(),
        }
    }

    pub fn add_key_ksk(
        &mut self,
        pubref: String,
        privref: Option<String>,
        creation_ts: UnixTime,
    ) {
        let keystate: KeyState = Default::default();
        let key =
            Key::new(pubref, privref, KeyType::Ksk(keystate), creation_ts);
        self.keys.push(key);
    }

    pub fn add_key_zsk(
        &mut self,
        pubref: String,
        privref: Option<String>,
        creation_ts: UnixTime,
    ) {
        let keystate: KeyState = Default::default();
        let key =
            Key::new(pubref, privref, KeyType::Zsk(keystate), creation_ts);
        self.keys.push(key);
    }

    pub fn add_key_csk(
        &mut self,
        pubref: String,
        privref: Option<String>,
        creation_ts: UnixTime,
    ) {
        let keystate: KeyState = Default::default();
        let key = Key::new(
            pubref,
            privref,
            KeyType::Csk(keystate.clone(), keystate),
            creation_ts,
        );
        self.keys.push(key);
    }

    pub fn delete_key(&mut self, pubref: &str) -> Result<(), Error> {
        // Assume no duplicate keys.
        for i in 0..self.keys.len() {
            if self.keys[i].pubref != pubref {
                continue;
            }
            match &self.keys[i].keytype {
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
                    self.keys.remove(i);
                    return Ok(());
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
                    self.keys.remove(i);
                    return Ok(());
                }
            }
        }
        Err(Error::KeyNotFound)
    }

    pub fn name(&self) -> String {
        self.name.to_string()
    }

    pub fn keys(&self) -> &[Key] {
        &self.keys
    }

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

    fn update_ksk(
        &mut self,
        mode: Mode,
        old: &[&str],
        new: &[&str],
    ) -> Result<(), Error> {
        println!("update_ksk: for old {old:?}, new {new:?}");
        let keys: &mut Vec<Key> = match mode {
            Mode::DryRun => &mut self.keys.clone(),
            Mode::ForReal => &mut self.keys,
        };
        'outer: for k in old {
            for i in 0..keys.len() {
                if keys[i].pubref != *k {
                    continue;
                }
                let KeyType::Ksk(ref mut keystate) = keys[i].keytype else {
                    return Err(Error::WrongKeyType);
                };

                // Set old for any key we find.
                keystate.old = true;
                continue 'outer;
            }

            // Should return error for unknown pubref.
            return Err(Error::KeyNotFound);
        }
        let now = UnixTime::now();
        'outer: for k in new {
            for i in 0..keys.len() {
                if keys[i].pubref != *k {
                    continue;
                }
                match keys[i].keytype {
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

                        // Move key state to Incoming.
                        keystate.present = true;
                        keystate.signer = true;
                        keys[i].timestamps.published = Some(now.clone());
                        continue 'outer;
                    }
                    _ => {
                        return Err(Error::WrongKeyType);
                    }
                }
            }

            return Err(Error::KeyNotFound);
        }

        // Make sure we have at least one key in incoming state.
        if keys
            .into_iter()
            .filter(|k| {
                if let KeyType::Ksk(keystate) = &k.keytype {
                    !keystate.old && keystate.present
                } else {
                    false
                }
            })
            .next()
            .is_none()
        {
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
        let keys: &mut Vec<Key> = match mode {
            Mode::DryRun => &mut self.keys.clone(),
            Mode::ForReal => &mut self.keys,
        };
        'outer: for k in old {
            for i in 0..keys.len() {
                if keys[i].pubref != *k {
                    continue;
                }
                let KeyType::Zsk(ref mut keystate) = keys[i].keytype else {
                    return Err(Error::WrongKeyType);
                };

                // Set old for any key we find.
                keystate.old = true;
                continue 'outer;
            }

            return Err(Error::KeyNotFound);
        }
        let now = UnixTime::now();
        'outer: for k in new {
            for i in 0..keys.len() {
                if keys[i].pubref != *k {
                    continue;
                }
                let KeyType::Zsk(ref mut keystate) = keys[i].keytype else {
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
                keys[i].timestamps.published = Some(now.clone());
                continue 'outer;
            }

            return Err(Error::KeyNotFound);
        }

        // Make sure we have at least one key in incoming state.
        if keys
            .into_iter()
            .filter(|k| {
                if let KeyType::Zsk(keystate) = &k.keytype {
                    !keystate.old || keystate.present
                } else {
                    false
                }
            })
            .next()
            .is_none()
        {
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
        let keys: &mut Vec<Key> = match mode {
            Mode::DryRun => &mut self.keys.clone(),
            Mode::ForReal => &mut self.keys,
        };
        'outer: for k in old {
            for i in 0..keys.len() {
                if keys[i].pubref != *k {
                    continue;
                }

                // Set old for any key we find.
                match keys[i].keytype {
                    KeyType::Ksk(ref mut keystate)
                    | KeyType::Zsk(ref mut keystate) => {
                        keystate.old = true;
                    }
                    KeyType::Csk(
                        ref mut ksk_keystate,
                        ref mut zsk_keystate,
                    ) => {
                        ksk_keystate.old = true;
                        zsk_keystate.old = true;
                    }
                    KeyType::Include(_) => {
                        return Err(Error::WrongKeyType);
                    }
                }
                continue 'outer;
            }

            return Err(Error::KeyNotFound);
        }
        let now = UnixTime::now();
        'outer: for k in new {
            for i in 0..keys.len() {
                if keys[i].pubref != *k {
                    continue;
                }
                match keys[i].keytype {
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
                        keys[i].timestamps.published = Some(now.clone());
                        continue 'outer;
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
                        keys[i].timestamps.published = Some(now.clone());
                        continue 'outer;
                    }
                    KeyType::Csk(
                        ref mut ksk_keystate,
                        ref mut zsk_keystate,
                    ) => {
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

                        keys[i].timestamps.published = Some(now.clone());
                        continue 'outer;
                    }
                    _ => {
                        return Err(Error::WrongKeyType);
                    }
                }
            }

            return Err(Error::KeyNotFound);
        }

        // Make sure we have at least one KSK key in incoming state.
        if keys
            .into_iter()
            .filter(|k| match &k.keytype {
                KeyType::Ksk(keystate) | KeyType::Csk(keystate, _) => {
                    !keystate.old && keystate.present
                }
                _ => false,
            })
            .next()
            .is_none()
        {
            return Err(Error::NoSuitableKeyPresent);
        }
        // Make sure we have at least one ZSK key in incoming state.
        if keys
            .into_iter()
            .filter(|k| match &k.keytype {
                KeyType::Zsk(keystate) | KeyType::Csk(_, keystate) => {
                    !keystate.old && keystate.present
                }
                _ => false,
            })
            .next()
            .is_none()
        {
            return Err(Error::NoSuitableKeyPresent);
        }
        Ok(())
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

    fn new(
        pubref: String,
        privref: Option<String>,
        keytype: KeyType,
        creation_ts: UnixTime,
    ) -> Self {
        let mut timestamps: KeyTimestamps = Default::default();
        timestamps.creation = Some(creation_ts);
        Self {
            pubref,
            privref,
            keytype,
            timestamps,
        }
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
    pub fn signer(&self) -> bool {
        self.signer
    }
    pub fn present(&self) -> bool {
        self.present
    }
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
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time is expected to be after UNIX_EPOCH");
        UnixTime(dur)
    }
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

impl Display for UnixTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        let ts = UNIX_EPOCH + self.0;
        let dt: OffsetDateTime = ts.into();
        let format = format_description::parse(
            "[year]-[month]-[day]T[hour]:[minute]:[second]",
        )
        .expect("");
        write!(f, "{}", dt.format(&format).expect(""))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum RollState {
    Propagation1,
    CacheExpire1(u32),
    Propagation2,
    CacheExpire2(u32),
    Done,
}

enum Mode {
    DryRun,
    ForReal,
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

#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum RollType {
    KskRoll,
    ZskRoll,
    CskRoll,
}

impl RollType {
    fn rollfn(&self) -> fn(RollOp, &mut KeySet) -> Result<(), Error> {
        match self {
            RollType::KskRoll => ksk_roll,
            RollType::ZskRoll => zsk_roll,
            RollType::CskRoll => csk_roll,
        }
    }
    fn roll_actions_fn(&self) -> fn(RollState) -> Vec<Action> {
        match self {
            RollType::KskRoll => ksk_roll_actions,
            RollType::ZskRoll => zsk_roll_actions,
            RollType::CskRoll => csk_roll_actions,
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

#[derive(Debug)]
pub enum Error {
    KeyNotFound,
    KeyNotOld,
    WrongKeyType,
    WrongKeyState,
    NoSuitableKeyPresent,
    WrongStateForRollOperation,
    ConflictingRollInProgress,
    Wait(Duration),
}

fn ksk_roll(rollop: RollOp, ks: &mut KeySet) -> Result<(), Error> {
    match rollop {
        RollOp::Start(old, new) => {
            // First check if the current KSK-roll state is idle. We need to
            // check all conflicting key rolls as well. The way we check is
            // to allow specified non-conflicting rolls and consider
            // everything else as a conflict.
            if let Some(rolltype) = ks
                .rollstates
                .keys()
                .filter(|k| **k != RollType::ZskRoll)
                .next()
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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

            for k in &mut ks.keys {
                match k.keytype {
                    KeyType::Ksk(ref mut keystate) => {
                        if keystate.old && keystate.present {
                            keystate.at_parent = false;
                        }

                        if !keystate.old && keystate.present {
                            keystate.at_parent = true;
                        }
                    }
                    _ => (),
                }
            }
        }
        RollOp::Propagation2 => {
            // Set the published time of new DS records to the current time.
            let now = UnixTime::now();
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
    println!("ksk_roll_actions: actions for state {rollstate:?}");
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
            if let Some(rolltype) = ks
                .rollstates
                .keys()
                .filter(|k| **k != RollType::KskRoll)
                .next()
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
    println!("zsk_roll_actions: actions for state {rollstate:?}");
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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

            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
            for k in &mut ks.keys {
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
    println!("csk_roll_actions: actions for state {rollstate:?}");
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
