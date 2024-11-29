//! Demonstrate the use of key sets.
use domain::base::Name;
use domain::sign::keyset::{
    Action, Error, KeySet, KeyType, RollType, UnixTime,
};
use std::env;
use std::fs::File;
use std::io::Write;
use std::process::exit;
use std::str::FromStr;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        // Should display a help message including example.
        eprintln!(
            "Subcommand required. Valid subcommands are:
	init <domain>
	addkey <key-type> <pubref> [<privref>]
	deletekey <pubref>
	start <roll-type>
	propagation1-complete <roll-type> <ttl>
	cache-expired1 <roll-type>
	propagation2-complete <roll-type> <ttl>
	cache-expired2 <roll-type>
	done <roll-type>
	actions <roll-type>
	status
	"
        );
        eprintln!();
        eprintln!(
            "Try for example the following commands:
keyset example-keyset.json init example.com
keyset example-keyset.json addkey ksk first-ksk.key
keyset example-keyset.json addkey zsk first-zsk.key first-zsk.private
keyset example-keyset.json start ksk-roll
keyset example-keyset.json propagation1-complete ksk-roll 1
keyset example-keyset.json cache-expired1 ksk-roll
keyset example-keyset.json propagation2-complete ksk-roll 1
keyset example-keyset.json cache-expired2 ksk-roll
keyset example-keyset.json done ksk-roll
keyset example-keyset.json actions ksk-roll
keyset example-keyset.json status
	"
        );
        exit(1);
    }

    let filename = &args[1];
    let command = &args[2];

    if command == "init" {
        do_init(filename, &args[3..]);
        return;
    }
    if command == "addkey" {
        do_addkey(filename, &args[3..]);
        return;
    }
    if command == "deletekey" {
        do_deletekey(filename, &args[3..]);
        return;
    }
    if command == "start" {
        do_start(filename, &args[3..]);
        return;
    }
    if command == "propagation1-complete" {
        do_propagation1(filename, &args[3..]);
        return;
    }
    if command == "cache-expired1" {
        do_cache_expired1(filename, &args[3..]);
        return;
    }
    if command == "propagation2-complete" {
        do_propagation2(filename, &args[3..]);
        return;
    }
    if command == "cache-expired2" {
        do_cache_expired2(filename, &args[3..]);
        return;
    }
    if command == "done" {
        do_done(filename, &args[3..]);
        return;
    }
    if command == "actions" {
        do_actions(filename, &args[3..]);
        return;
    }
    if command == "status" {
        do_status(filename, &args[3..]);
        return;
    }

    eprintln!("Unknown command '{command}'. Valid commands are: init, addkey, deletekey, start, propagation1-complete, cache-expired1, propagation2-complete, cache-expired2, done, actions, and status");
    exit(1);
}

fn do_init(filename: &str, args: &[String]) {
    if args.len() != 1 {
        // Give usage.
        todo!();
    }
    let domainname = &args[0];

    let ks = KeySet::new(Name::from_str(domainname).unwrap());

    save_keyset(filename, &ks);
}

fn do_addkey(filename: &str, args: &[String]) {
    if args.len() < 2 || args.len() > 3 {
        // Give usage.
        todo!();
    }
    let keytype = &args[0];
    let pubref = args[1].clone();
    let privref = if args.len() == 3 {
        Some(args[2].clone())
    } else {
        None
    };

    let mut ks = load_keyset(filename);
    if keytype == "ksk" {
        ks.add_key_ksk(pubref, privref, UnixTime::now());
    } else if keytype == "zsk" {
        ks.add_key_zsk(pubref, privref, UnixTime::now());
    } else if keytype == "csk" {
        ks.add_key_csk(pubref, privref, UnixTime::now());
    } else {
        todo!();
    }
    save_keyset(filename, &ks);
}

fn do_deletekey(filename: &str, args: &[String]) {
    if args.len() != 1 {
        // Give usage.
        todo!();
    }
    let pubref = &args[0];

    let mut ks = load_keyset(filename);
    if let Err(e) = ks.delete_key(pubref) {
        eprintln!("Unable to delete key {pubref}: {e}");
        exit(1);
    }
    save_keyset(filename, &ks);
}

fn do_start(filename: &str, args: &[String]) {
    if args.len() != 1 {
        // Give usage.
        todo!();
    }
    let rolltype = &args[0];

    let rolltype = str_to_rolltype(rolltype);

    let mut ks = load_keyset(filename);
    let mut old = Vec::new();
    let mut new = Vec::new();

    // Find old and new keys.
    let keys = ks.keys().to_vec();
    match rolltype {
        RollType::KskRoll => {
            for key in keys {
                if let KeyType::Ksk(keystate) = key.keytype() {
                    if keystate.old() {
                        continue;
                    }
                    if keystate.signer()
                        || keystate.present()
                        || keystate.at_parent()
                    {
                        old.push(key.pubref().to_string());
                    } else {
                        new.push(key.pubref().to_string());
                    }
                }
            }
        }
        RollType::ZskRoll => {
            for key in keys {
                if let KeyType::Zsk(keystate) = key.keytype() {
                    if keystate.old() {
                        continue;
                    }
                    if keystate.signer()
                        || keystate.present()
                        || keystate.at_parent()
                    {
                        old.push(key.pubref().to_string());
                    } else {
                        new.push(key.pubref().to_string());
                    }
                }
            }
        }
        RollType::CskRoll => {
            for key in keys {
                match key.keytype() {
                    KeyType::Ksk(keystate)
                    | KeyType::Zsk(keystate)
                    | KeyType::Csk(keystate, _) => {
                        if keystate.old() {
                            continue;
                        }
                        if keystate.signer()
                            || keystate.present()
                            || keystate.at_parent()
                        {
                            old.push(key.pubref().to_string());
                        } else {
                            new.push(key.pubref().to_string());
                        }
                    }
                    KeyType::Include(_) => (),
                }
            }
        }
    }

    let old_str: Vec<&str> = old.iter().map(|s| s.as_ref()).collect();
    let new_str: Vec<&str> = new.iter().map(|s| s.as_ref()).collect();

    let actions = ks.start_roll(rolltype, &old_str, &new_str);
    report_actions(actions, &ks);

    save_keyset(filename, &ks);
}

fn do_propagation1(filename: &str, args: &[String]) {
    if args.len() != 2 {
        // Give usage.
        todo!();
    }
    let rolltype = &args[0];
    let ttl = &args[1];

    let rolltype = str_to_rolltype(rolltype);
    let ttl = ttl.parse().unwrap();

    let mut ks = load_keyset(filename);

    let actions = ks.propagation1_complete(rolltype, ttl);
    report_actions(actions, &ks);

    save_keyset(filename, &ks);
}

fn do_cache_expired1(filename: &str, args: &[String]) {
    if args.len() != 1 {
        // Give usage.
        todo!();
    }
    let rolltype = &args[0];

    let rolltype = str_to_rolltype(rolltype);

    let mut ks = load_keyset(filename);

    let actions = ks.cache_expired1(rolltype);
    report_actions(actions, &ks);

    save_keyset(filename, &ks);
}

fn do_propagation2(filename: &str, args: &[String]) {
    if args.len() != 2 {
        // Give usage.
        todo!();
    }
    let rolltype = &args[0];
    let ttl = &args[1];

    let rolltype = str_to_rolltype(rolltype);
    let ttl = ttl.parse().unwrap();

    let mut ks = load_keyset(filename);

    let actions = ks.propagation2_complete(rolltype, ttl);
    report_actions(actions, &ks);

    save_keyset(filename, &ks);
}

fn do_cache_expired2(filename: &str, args: &[String]) {
    if args.len() != 1 {
        // Give usage.
        todo!();
    }
    let rolltype = &args[0];

    let rolltype = str_to_rolltype(rolltype);

    let mut ks = load_keyset(filename);

    let actions = ks.cache_expired2(rolltype);
    report_actions(actions, &ks);

    save_keyset(filename, &ks);
}

fn do_done(filename: &str, args: &[String]) {
    if args.len() != 1 {
        // Give usage.
        todo!();
    }
    let rolltype = &args[0];

    let rolltype = str_to_rolltype(rolltype);

    let mut ks = load_keyset(filename);

    let actions = ks.roll_done(rolltype);
    report_actions(actions, &ks);

    save_keyset(filename, &ks);
}

fn do_actions(filename: &str, args: &[String]) {
    if args.len() != 1 {
        // Give usage.
        todo!();
    }
    let rolltype = &args[0];

    let rolltype = str_to_rolltype(rolltype);

    let mut ks = load_keyset(filename);

    let actions = ks.actions(rolltype);
    report_actions(actions, &ks);
}

fn do_status(filename: &str, args: &[String]) {
    if !args.is_empty() {
        // Give usage.
        todo!();
    }

    let ks = load_keyset(filename);

    println!("Keys:");
    let keys = ks.keys();
    for key in keys {
        match key.keytype() {
            KeyType::Ksk(keystate)
            | KeyType::Zsk(keystate)
            | KeyType::Include(keystate) => {
                println!(
                    "\t{} {}",
                    key.pubref(),
                    key.privref().unwrap_or_default(),
                );
                println!("\t\tState: {}", keystate);
            }
            KeyType::Csk(keystate_ksk, keystate_zsk) => {
                println!(
                    "\t{} {}",
                    key.pubref(),
                    key.privref().unwrap_or_default(),
                );
                println!("\t\tKSK role state: {}", keystate_ksk,);
                println!("\t\tZSK role state: {}", keystate_zsk,);
            }
        }
        let ts = key.timestamps();
        println!(
            "\t\tCreated: {}",
            ts.creation()
                .map_or("<empty>".to_string(), |x| x.to_string()),
        );
        println!(
            "\t\tPublished: {}",
            ts.published()
                .map_or("<empty>".to_string(), |x| x.to_string())
        );
        println!(
            "\t\tVisible: {}",
            ts.visible()
                .map_or("<empty>".to_string(), |x| x.to_string()),
        );
        println!(
            "\t\tDS visible: {}",
            ts.ds_visible()
                .map_or("<empty>".to_string(), |x| x.to_string())
        );
        println!(
            "\t\tRRSIG visible: {}",
            ts.rrsig_visible()
                .map_or("<empty>".to_string(), |x| x.to_string()),
        );
        println!(
            "\t\tWithdrawn: {}",
            ts.withdrawn()
                .map_or("<empty>".to_string(), |x| x.to_string())
        );
    }
    let rolls = ks.rollstates();
    let active_rolls = rolls.keys();
    if active_rolls.len() == 0 {
        println!("No rolls in progress");
    } else {
        println!("Rolls:");
        for roll in active_rolls {
            println!("\t{roll:?}: {:?}", rolls.get(roll).unwrap());
        }
    }
}

fn save_keyset(filename: &str, ks: &KeySet) {
    let json = serde_json::to_string(&ks).unwrap();

    let mut file = File::create(filename).unwrap();
    write!(file, "{json}").unwrap();
}

fn load_keyset(filename: &str) -> KeySet {
    let file = File::open(filename).unwrap();
    let ks: KeySet = serde_json::from_reader(file).unwrap();
    ks
}

fn str_to_rolltype(rolltype: &str) -> RollType {
    if rolltype == "ksk-roll" {
        RollType::KskRoll
    } else if rolltype == "zsk-roll" {
        RollType::ZskRoll
    } else if rolltype == "csk-roll" {
        RollType::CskRoll
    } else {
        panic!("Unknown roll type {rolltype}");
    }
}

fn report_actions(actions: Result<Vec<Action>, Error>, ks: &KeySet) {
    let actions = match actions {
        Err(e) => {
            eprintln!("Error: {e}");
            exit(1);
        }
        Ok(a) => a,
    };
    if actions.is_empty() {
        println!("No actions to perform");
        return;
    }
    println!("Actions to perform:");
    for a in actions {
        match a {
            Action::UpdateDnskeyRrset => {
                println!("\tUpdate the DNSKEY RRset");
                let keys = ks.keys();
                println!("\t\tKeys in the DNSKEY RRset:");
                for key in keys {
                    let status = match key.keytype() {
                        KeyType::Ksk(keystate)
                        | KeyType::Zsk(keystate)
                        | KeyType::Csk(keystate, _)
                        | KeyType::Include(keystate) => keystate,
                    };
                    if status.present() {
                        println!("\t\t\t{}", key.pubref());
                    }
                }
                println!("\t\tKeys signing the DNSKEY RRset:");
                for key in keys {
                    match key.keytype() {
                        KeyType::Ksk(keystate)
                        | KeyType::Csk(keystate, _) => {
                            if keystate.signer() {
                                println!("\t\t\t{}", key.pubref());
                            }
                        }
                        KeyType::Zsk(_) | KeyType::Include(_) => (),
                    }
                }
            }
            Action::UpdateRrsig => {
                println!("\tSign the zone with the following keys:");
                let keys = ks.keys();
                for key in keys {
                    match key.keytype() {
                        KeyType::Zsk(keystate)
                        | KeyType::Csk(_, keystate) => {
                            if keystate.signer() {
                                println!("\t\t{}", key.pubref());
                            }
                        }
                        KeyType::Ksk(_) | KeyType::Include(_) => (),
                    }
                }
            }
            Action::UpdateDsRrset => {
                println!("\tUpdate the DS records at the parent to contain just the following keys:");
                let keys = ks.keys();
                for key in keys {
                    let status = match key.keytype() {
                        KeyType::Ksk(keystate)
                        | KeyType::Zsk(keystate)
                        | KeyType::Csk(keystate, _)
                        | KeyType::Include(keystate) => keystate,
                    };
                    if status.at_parent() {
                        println!("\t\t{}", key.pubref());
                    }
                }
            }
            Action::CreateCdsRrset => {
                println!("\tCreate CDS and CDNSKEY RRsets with the following keys:");
                let keys = ks.keys();
                for key in keys {
                    let status = match key.keytype() {
                        KeyType::Ksk(keystate)
                        | KeyType::Zsk(keystate)
                        | KeyType::Csk(keystate, _)
                        | KeyType::Include(keystate) => keystate,
                    };
                    if status.at_parent() {
                        println!("\t\t{}", key.pubref());
                    }
                }
            }
            Action::RemoveCdsRrset => {
                println!("\tRemove CDS and CDNSKEY RRsets")
            }
            Action::ReportDnskeyPropagated => {
                println!("\tReport that the DNSKEY RRset has propagated")
            }
            Action::ReportRrsigPropagated => {
                println!("\tReport that the RRSIG records have propagated")
            }
            Action::ReportDsPropagated => println!(
                "\tReport that the DS RRset has propagated at the parent"
            ),
        }
    }
}
