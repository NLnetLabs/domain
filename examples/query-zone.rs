//! Reads a zone file into memory and queries it.
//! Command line argument and response style emulate that of dig.

use std::env;
use std::fs::File;
use std::{process::exit, str::FromStr};

use bytes::{Bytes, BytesMut};
use core::pin::Pin;
use core::task::{Context, Poll};
use domain::base::iana::{Class, Rcode};
use domain::base::record::ComposeRecord;
use domain::base::{Name, ParsedName, Rtype, Ttl};
use domain::base::{ParsedRecord, Record};
use domain::rdata::dnssec::{RtypeBitmap, RtypeBitmapBuilder};
use domain::rdata::{Nsec, ZoneRecordData};
use domain::zonefile::inplace;
use domain::zonetree::types::ZoneUpdate;
use domain::zonetree::update::ZoneUpdater;
use domain::zonetree::{
    Answer, Rrset, SharedRrset, StoredName, StoredRecord,
};
use domain::zonetree::{Zone, ZoneTree};

use futures_util::{Stream, StreamExt};
use octseq::Parser;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing_subscriber::EnvFilter;

#[path = "common/serve-utils.rs"]
mod common;

#[derive(PartialEq, Eq)]
enum Verbosity {
    Quiet,
    Normal,
    Verbose(u8),
}

#[tokio::main]
async fn main() {
    // Initialize tracing based logging. Override with env var RUST_LOG, e.g.
    // RUST_LOG=trace.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        .try_init()
        .ok();

    let mut args = env::args();
    let prog_name = args.next().unwrap(); // SAFETY: O/S always passes our name as the first argument.
    let usage = format!(
        "Usage: {prog_name} [-q|--quiet|-v|--verbose] [+short] <zonefile_path> [<zonefile_path> ..] <qtype> <qname>",
    );

    // Process command line arguments.
    let (verbosity, zone_files, qtype, qname, short) =
        process_dig_style_args(args).unwrap_or_else(|err| {
            eprintln!("{usage}");
            eprintln!("{err}");
            exit(2);
        });

    // Go!
    let mut zones = ZoneTree::new();

    for (zone_file_path, mut zone_file) in zone_files {
        if verbosity != Verbosity::Quiet {
            println!("Reading zone file '{zone_file_path}'...");
        }
        let reader = inplace::Zonefile::load(&mut zone_file).unwrap();

        if verbosity != Verbosity::Quiet {
            println!("Constructing zone...");
        }
        let zone = Zone::try_from(reader).unwrap_or_else(|err| {
            eprintln!("Error while constructing zone: {err}");
            exit(1);
        });

        if verbosity != Verbosity::Quiet {
            println!(
                "Inserting zone for {} class {}...",
                zone.apex_name(),
                zone.class()
            );
        }
        zones.insert_zone(zone).unwrap_or_else(|err| {
            eprintln!("Error while inserting zone: {err}");
            exit(1);
        });
    }

    if let Verbosity::Verbose(level) = verbosity {
        for zone in zones.iter_zones() {
            // NSEC testing
            println!("NSEC'ing and updating...");
            let mut zone_updater =
                ZoneUpdater::new(zone.clone()).await.unwrap();
            let mut zone_iter = NsecZoneIter::new(zone.clone());
            while let Some(rec) = zone_iter.next().await {
                let update = ZoneUpdate::AddRecord(rec);
                zone_updater.apply(update).await.unwrap();
            }
            zone_updater
                .apply(ZoneUpdate::FinishedWithoutNewSoa)
                .await
                .unwrap();

            println!(
                "Dumping zone {} class {}...",
                zone.apex_name(),
                zone.class()
            );
            zone.read()
                .walk(Box::new(move |owner, rrset, _at_zone_cut| {
                    dump_rrset(owner, rrset);
                }));
            println!("Dump complete.");

            if level > 0 {
                println!("Debug dumping zone...");
                dbg!(zone);
            }
        }
    }

    // Find the zone to query
    let qclass = Class::IN;
    if verbosity != Verbosity::Quiet {
        println!("Finding zone for qname {qname} class {qclass}...");
    }
    let zone_answer = if let Some(zone) = zones.find_zone(&qname, qclass) {
        // Query the built zone for the requested records.
        if verbosity != Verbosity::Quiet {
            println!("Querying zone {} class {} for qname {qname} with qtype {qtype}...", zone.apex_name(), zone.class());
        }
        zone.read().query(qname.clone(), qtype).unwrap()
    } else {
        Answer::new(Rcode::NXDOMAIN)
    };

    // Emulate a DIG style response by generating a complete DNS wire response
    // from the zone answer, which requires that we fake a DNS wire query to
    // respond to.
    if verbosity != Verbosity::Quiet {
        println!("Preparing dig style response...\n");
    }
    let wire_query = common::generate_wire_query(&qname, qtype);
    let wire_response =
        common::generate_wire_response(&wire_query, zone_answer);
    common::print_dig_style_response(&wire_query, &wire_response, short);
}

#[allow(clippy::type_complexity)]
fn process_dig_style_args(
    args: env::Args,
) -> Result<(Verbosity, Vec<(String, File)>, Rtype, Name<Bytes>, bool), String>
{
    let mut abort_with_usage = false;
    let mut verbosity = Verbosity::Normal;
    let mut short = false;
    let mut zone_files = vec![];

    let args: Vec<_> = args
        .filter(|arg| {
            if arg.starts_with(['-', '+']) {
                match arg.as_str() {
                    "-q" | "--quiet" => verbosity = Verbosity::Quiet,
                    "-v" | "--verbose" => {
                        if let Verbosity::Verbose(level) = verbosity {
                            verbosity = Verbosity::Verbose(level + 1)
                        } else {
                            verbosity = Verbosity::Verbose(0)
                        }
                    }
                    "+short" => {
                        short = true;
                        if verbosity == Verbosity::Normal {
                            verbosity = Verbosity::Quiet
                        }
                    }
                    _ => abort_with_usage = true,
                }
                false // discard the argument
            } else {
                true // keep the argument
            }
        })
        .collect();

    if args.len() >= 3 {
        let mut i = 0;
        while i < args.len() - 2 {
            let zone_file = File::open(&args[i]).map_err(|err| {
                format!("Cannot open zone file '{}': {err}", args[i])
            })?;
            zone_files.push((args[i].to_string(), zone_file));
            i += 1;
        }

        let qtype = Rtype::from_str(&args[i])
            .map_err(|err| format!("Cannot parse qtype: {err}"))?;
        i += 1;

        let qname = Name::<Bytes>::from_str(&args[i])
            .map_err(|err| format!("Cannot parse qname: {err}"))?;

        Ok((verbosity, zone_files, qtype, qname, short))
    } else {
        Err("Insufficient arguments".to_string())
    }
}

fn dump_rrset(owner: Name<Bytes>, rrset: &Rrset) {
    //
    // The following code renders an owner + rrset (IN class, TTL, RDATA)
    // into zone presentation format. This can be used for diagnostic
    // dumping.
    //
    let mut target = Vec::<u8>::new();
    for item in rrset.data() {
        let record = Record::new(owner.clone(), Class::IN, rrset.ttl(), item);
        if record.compose_record(&mut target).is_ok() {
            let mut parser = Parser::from_ref(&target);
            if let Ok(parsed_record) = ParsedRecord::parse(&mut parser) {
                if let Ok(Some(record)) = parsed_record
                    .into_record::<ZoneRecordData<_, ParsedName<_>>>()
                {
                    println!("> {record}");
                }
            }
        }
    }
}

//------------ NsecZoneIter --------------------------------------------------

pub struct NsecZoneIter {
    rx: UnboundedReceiver<(Name<Bytes>, SharedRrset)>,

    iter_state: NsecZoneIterState,
}

enum NsecZoneIterState {
    New,

    First {
        last_name: StoredName,
        last_rrset: SharedRrset,
    },

    Next {
        apex_name: StoredName,
        apex_ttl: Ttl,
        bitmap: RtypeBitmapBuilder<BytesMut>,
        last_name: StoredName,
    },

    End,
}

impl NsecZoneIter {
    pub fn new(zone: Zone) -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        tokio::task::spawn(zone.read().walk_async(Box::new(
            move |name, rrset, at_zone_cut| {
                // Do not emit glue records as the zone is not authoritative
                // for glue and only authoritative records should be signed.
                if !at_zone_cut || !rrset.rtype().is_glue() {
                    tx.send((name, rrset.clone())).unwrap();
                }
            },
        )));

        Self {
            rx,
            iter_state: NsecZoneIterState::New,
        }
    }
}

impl NsecZoneIterState {
    fn step(
        &mut self,
        name: StoredName,
        rrset: SharedRrset,
    ) -> Option<StoredRecord> {
        match self {
            NsecZoneIterState::New => {
                *self = NsecZoneIterState::First {
                    last_name: name,
                    last_rrset: rrset,
                };
                None
            }

            NsecZoneIterState::First {
                last_name,
                last_rrset,
            } => {
                // We can't generate an NSEC record for the first zone record
                // because we always need a current and a next record, which
                // can also be thought of as a last record and current record.
                // Set the current record as the last record so that on
                // NsecState::Next both a last and a current record are
                // available.
                //
                // The apex name and TTL can be taken from the first record in
                // the zone on the assumption that the zone is ordered so that
                // the first RRset is the apex RRset.
                let mut bitmap = RtypeBitmapBuilder::<BytesMut>::new();
                bitmap.add(last_rrset.rtype()).unwrap();
                bitmap.add(rrset.rtype()).unwrap();

                *self = NsecZoneIterState::Next {
                    apex_name: name.clone(),
                    apex_ttl: rrset.ttl(),
                    bitmap,
                    last_name: last_name.clone(),
                };

                None
            }

            NsecZoneIterState::Next {
                apex_name: _,
                apex_ttl,
                bitmap,
                last_name,
            } => {
                // If this RR has a different owner than the last RR, or there
                // is no next RR, finalize the current bitmap and create an
                // NSEC record.
                if &name == last_name {
                    // Another RR in the same RRset.
                    bitmap.add(rrset.rtype()).unwrap();
                    None
                } else {
                    // A new RRset.
                    bitmap.add(rrset.rtype()).unwrap();
                    let finalized_bitmap = Self::finalize_bitmap(bitmap);
                    let nsec = Nsec::new(name.clone(), finalized_bitmap);
                    let last_name = std::mem::replace(last_name, name);
                    let nsec_rec = Record::new(
                        last_name,
                        Class::IN,
                        *apex_ttl,
                        ZoneRecordData::Nsec(nsec),
                    );
                    Some(nsec_rec)
                }
            }

            NsecZoneIterState::End => unreachable!(),
        }
    }

    fn finalize(&mut self) -> StoredRecord {
        let NsecZoneIterState::Next {
            apex_name,
            apex_ttl,
            bitmap,
            last_name,
        } = self
        else {
            unreachable!();
        };

        let finalized_bitmap = Self::finalize_bitmap(bitmap);

        let nsec = Nsec::new(apex_name.clone(), finalized_bitmap);

        let nsec_rec = Record::new(
            last_name.clone(),
            Class::IN,
            *apex_ttl,
            ZoneRecordData::Nsec(nsec),
        );

        *self = NsecZoneIterState::End;

        nsec_rec
    }

    fn finalize_bitmap(
        bitmap: &mut RtypeBitmapBuilder<BytesMut>,
    ) -> RtypeBitmap<Bytes> {
        bitmap.add(Rtype::RRSIG).unwrap();
        bitmap.add(Rtype::NSEC).unwrap();
        let new_bitmap = RtypeBitmap::<Bytes>::builder();
        std::mem::replace(bitmap, new_bitmap).finalize()
    }
}

impl Stream for NsecZoneIter {
    type Item = StoredRecord;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some((name, rrset))) => {
                match self.iter_state.step(name, rrset) {
                    Some(nsec_rec) => {
                        // RRset completed, NSEC record created
                        Poll::Ready(Some(nsec_rec))
                    }
                    None => {
                        // RRset in-proress, no NSEC record
                        // Poll again to process the next RR.
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }

            Poll::Ready(None)
                if matches!(self.iter_state, NsecZoneIterState::End) =>
            {
                Poll::Ready(None)
            }

            Poll::Ready(None) => {
                Poll::Ready(Some(self.iter_state.finalize()))
            }

            Poll::Pending => Poll::Pending,
        }
    }
}
