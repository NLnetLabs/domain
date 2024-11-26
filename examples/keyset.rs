/// Demonstrate the use of key sets.

use domain::sign::keyset::KeySet;
use domain::base::Name;
use std::str::FromStr;
use domain::sign::keyset::KeyType;
//use domain::sign::keyset::KeyState;
use std::fs::File;
use std::io::Write;
use domain::sign::keyset::UnixTime;
use domain::sign::keyset::Action;
use std::thread::sleep;
use std::time::Duration;

const ZONE: &str = "example.com";

fn main() {
    init();

    let mut ks = load_keyset(ZONE,);
    print_status(&ks);	    

    println!("CSK roll start");
    let actions = ks.start_csk_roll(&[], &["first KSK", "first ZSK"]);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("CSK roll propagation1 complete");
    let actions = ks.csk_roll_propagation1_complete(1);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    sleep(Duration::from_secs(1));

    println!("CSK roll cache expired1");
    let actions = ks.csk_roll_cache_expired1();
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("CSK roll propagation2 complete");
    let actions = ks.csk_roll_propagation2_complete(1);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    sleep(Duration::from_secs(1));

    println!("CSK roll cache expired2");
    let actions = ks.csk_roll_cache_expired2();
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("CSK roll done");
    let actions = ks.csk_roll_done();
    handle_actions(&actions, &ks);
    save_keyset(&ks);

    println!("");
    ks.add_key_ksk("second KSK".to_string(), None, UnixTime::now());
    ks.add_key_zsk("second ZSK".to_string(), None, UnixTime::now());
    save_keyset(&ks);

    println!("ZSK roll start");
    let actions = ks.start_zsk_roll(&["first ZSK"], &["second ZSK"]);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("ZSK roll propagation1 complete");
    let actions = ks.zsk_roll_propagation1_complete(1);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    sleep(Duration::from_secs(1));

    println!("ZSK roll cache expired1");
    let actions = ks.zsk_roll_cache_expired1();
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("ZSK roll propagation2 complete");
    let actions = ks.zsk_roll_propagation2_complete(1);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    sleep(Duration::from_secs(1));

    println!("ZSK roll cache expired2");
    let actions = ks.zsk_roll_cache_expired2();
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("ZSK roll done");
    let actions = ks.zsk_roll_done();
    handle_actions(&actions, &ks);
    ks.delete_key("first ZSK");
    save_keyset(&ks);

    println!("KSK roll start");
    let actions = ks.start_ksk_roll(&["first KSK"], &["second KSK"]);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("KSK roll propagation1 complete");
    let actions = ks.ksk_roll_propagation1_complete(1);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    sleep(Duration::from_secs(1));

    println!("KSK roll cache expired1");
    let actions = ks.ksk_roll_cache_expired1();
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("KSK roll propagation2 complete");
    let actions = ks.ksk_roll_propagation2_complete(1);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    sleep(Duration::from_secs(1));

    println!("KSK roll cache expired2");
    let actions = ks.ksk_roll_cache_expired2();
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("KSK roll done");
    let actions = ks.ksk_roll_done();
    handle_actions(&actions, &ks);
    ks.delete_key("first KSK");
    save_keyset(&ks);

    ks.add_key_csk("first CSK".to_string(), None, UnixTime::now());

    println!("CSK roll start");
    let actions = ks.start_csk_roll(&["second KSK", "second ZSK"], &["first CSK"]);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("CSK roll propagation1 complete");
    let actions = ks.csk_roll_propagation1_complete(1);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    sleep(Duration::from_secs(1));

    println!("CSK roll cache expired1");
    let actions = ks.csk_roll_cache_expired1();
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("CSK roll propagation2 complete");
    let actions = ks.csk_roll_propagation2_complete(1);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    sleep(Duration::from_secs(1));

    println!("CSK roll cache expired2");
    let actions = ks.csk_roll_cache_expired2();
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("CSK roll done");
    let actions = ks.csk_roll_done();
    handle_actions(&actions, &ks);
    ks.delete_key("second KSK");
    ks.delete_key("second ZSK");
    save_keyset(&ks);

    ks.add_key_csk("second CSK".to_string(), None, UnixTime::now());

    println!("CSK roll start");
    let actions = ks.start_csk_roll(&["first CSK"], &["second CSK"]);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("CSK roll propagation1 complete");
    let actions = ks.csk_roll_propagation1_complete(1);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    sleep(Duration::from_secs(1));

    println!("CSK roll cache expired1");
    let actions = ks.csk_roll_cache_expired1();
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("CSK roll propagation2 complete");
    let actions = ks.csk_roll_propagation2_complete(1);
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    sleep(Duration::from_secs(1));

    println!("CSK roll cache expired2");
    let actions = ks.csk_roll_cache_expired2();
    handle_actions(&actions, &ks);
    save_keyset(&ks);
    print_status(&ks);	    

    println!("CSK roll done");
    let actions = ks.csk_roll_done();
    handle_actions(&actions, &ks);
    ks.delete_key("first CSK");
    save_keyset(&ks);

    todo!();
}

fn init() {
    let mut ks = KeySet::new(Name::from_str(ZONE).unwrap());

    ks.add_key_ksk("first KSK".to_string(), None, UnixTime::now());
    ks.add_key_zsk("first ZSK".to_string(), None, 
	UnixTime::now());

    save_keyset(&ks);
}

fn load_keyset(name: &str) -> KeySet {
    let filename = name.to_owned() + ".keyset";
    let file = File::open(filename).unwrap();
    let ks: KeySet = serde_json::from_reader(file).unwrap();
    ks
}

fn save_keyset(ks: &KeySet) {
    let filename = ks.name().to_string() + ".keyset";

    let json = serde_json::to_string(&ks).unwrap();

    let mut file = File::create(filename).unwrap();
    write!(file, "{json}").unwrap();
}

fn handle_actions(actions: &[Action], ks: &KeySet) {
    for a in actions {
	handle_action(a, ks);
    }
}

fn handle_action(action: &Action, ks: &KeySet) {
    match action {
	Action::UpdateDnskeyRrset => {
	    println!("Should update DNSKEY RRset");
	    let keys = ks.keys();
	    print!("Present in DNSKEY RRset:");
	    for key in keys {
		let status = match key.keytype() {
		    KeyType::Ksk(keystate)
		    | KeyType::Zsk(keystate)
		    | KeyType::Csk(keystate, _)
		    | KeyType::Include(keystate)
			=> keystate,
		};
		if status.present() {
		    print!(" {}", key.pubref());
		}
	    }
	    println!("");
	    print!("DNSKEY RRset is signed by:");
	    for key in keys {
		match key.keytype() {
		    KeyType::Ksk(keystate)
		    | KeyType::Csk(keystate, _)
			=> {
			if keystate.signer() {
			    print!(" {}", key.pubref());
			}
		    }
		    KeyType::Zsk(_) | KeyType::Include(_) => ()
		}
	    }
	    println!("");
	}
	Action::UpdateDsRrset => {
	    println!("Should update DS RRset at the parent");
	    let keys = ks.keys();
	    print!("Present in DS RRset:");
	    for key in keys {
		let status = match key.keytype() {
		    KeyType::Ksk(keystate)
		    | KeyType::Zsk(keystate)
		    | KeyType::Csk(keystate, _)
		    | KeyType::Include(keystate)
			=> keystate,
		};
		if status.at_parent() {
		    print!(" {}", key.pubref());
		}
	    }
	    println!("");
	}
	Action::UpdateRrsig => {
	    println!("Should update RRsig records");
	    let keys = ks.keys();
	    print!("The zone is signed by:");
	    for key in keys {
		match key.keytype() {
		    KeyType::Zsk(keystate)
		    | KeyType::Csk(_, keystate)
			=> {
			if keystate.signer() {
			    print!(" {}", key.pubref());
			}
		    }
		    KeyType::Ksk(_) | KeyType::Include(_) => ()
		}
	    }
	    println!("");
	}
	Action::CreateCdsRrset => {
	    println!("Should create CDS and CDNSKEY RRsets");
	    let keys = ks.keys();
	    print!("Present in CDS/CDNSKEY RRsets:");
	    for key in keys {
		let status = match key.keytype() {
		    KeyType::Ksk(keystate)
		    | KeyType::Zsk(keystate)
		    | KeyType::Csk(keystate, _)
		    | KeyType::Include(keystate)
			=> keystate,
		};
		if status.at_parent() {
		    print!(" {}", key.pubref());
		}
	    }
	    println!("");
	}
	Action::RemoveCdsRrset => {
	    println!("Should remove CDS and CDNSKEY RRsets");
	}
	Action::ReportDnskeyPropagated => {
	    println!("Should wait until the new DNSKEY RRset has propagated to all secondaries");
	}
	Action::ReportDsPropagated => {
	    println!("Should wait until the new DS RRset has propagated to all of the parent's secondaries");
	}
	Action::ReportRrsigPropagated => {
	    println!("Should wait until the new RRSIG records have propagated to all secondaries");
	}
    }
}

fn print_status(ks: &KeySet) {
    let keys = ks.keys();
    for key in keys {
	match key.keytype() {
	    KeyType::Ksk(keystate)
	    | KeyType::Zsk(keystate)
	    | KeyType::Include(keystate)
		=> {
		println!("{} {} {}", key.pubref(),
			match key.privref() { None => "", Some(s) => s },
			keystate);
	    }
	    KeyType::Csk(keystate_ksk, keystate_zsk)
		=> {
		println!("{} {} {} {}", key.pubref(),
			match key.privref() { None => "", Some(s) => s },
			keystate_ksk, keystate_zsk);
	    }
	}
	let ts = key.timestamps();
	println!("Created: {}, published: {}",
		ts.creation().map_or("<empty>".to_string(), |x| x.to_string()),
		ts.published().map_or("<empty>".to_string(), |x| x.to_string()));
	println!("Visible: {}, DS visible: {}",
		ts.visible().map_or("<empty>".to_string(), |x| x.to_string()),
		ts.ds_visible().map_or("<empty>".to_string(), |x| x.to_string()));
	println!("RRSIG visible: {}, withdrawn: {}",
		ts.rrsig_visible().map_or("<empty>".to_string(), |x| x.to_string()),
		ts.withdrawn().map_or("<empty>".to_string(), |x| x.to_string()));
    }
}
