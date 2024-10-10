//! Reads a zone file into memory and queries it.
//! Command line argument and response style emulate that of dig.
use core::ops::Sub;
use core::pin::Pin;
use core::task::{Context, Poll};

use std::env;
use std::fmt::Debug;
use std::fs::File;
use std::ops::Add;
use std::{process::exit, str::FromStr};

use bytes::{Bytes, BytesMut};
use domain::rdata::nsec3::Nsec3Salt;
use futures_util::Stream;
use octseq::Parser;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing_subscriber::EnvFilter;

use domain::base::iana::{Class, Nsec3HashAlg, Rcode, SecAlg};
use domain::base::record::ComposeRecord;
use domain::base::{Name, ParsedName, Rtype, ToName, Ttl};
use domain::base::{ParsedRecord, Record};
use domain::rdata::dnssec::{
    ProtoRrsig, RtypeBitmap, RtypeBitmapBuilder, Timestamp,
};
use domain::rdata::{Dnskey, Nsec, ZoneRecordData};
use domain::sign::key::SigningKey;
use domain::sign::records::{FamilyName, SortedRecords};
use domain::sign::ring::{RingKey, Signature};
use domain::zonefile::inplace;
use domain::zonetree::types::StoredRecordData;
use domain::zonetree::{
    Answer, Rrset, SharedRrset, StoredName, StoredRecord,
};
use domain::zonetree::{Zone, ZoneTree};

use common::serve_utils::{
    generate_wire_query, generate_wire_response, print_dig_style_response,
};

#[path = "common/mod.rs"]
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

            // Generate or import a zone signing key.
            let rng = SystemRandom::new();

            let pkcs8 = EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )
            .unwrap();
            let keypair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8.as_ref(),
                &rng,
            )
            .unwrap();

            let pubkey = keypair.public_key().as_ref()[1..].to_vec();

            let dnskey: Dnskey<Vec<u8>> =
                Dnskey::new(256, 3, SecAlg::ECDSAP256SHA256, pubkey.clone())
                    .unwrap();
            let ringkey = RingKey::Ecdsa(keypair);
            let key = domain::sign::ring::Key::new(dnskey, ringkey, &rng);

            // // Dump the keys out
            // let key_info =
            //     pkcs8::PrivateKeyInfo::try_from(pkcs8.as_ref()).unwrap();
            // let key_data = KeyData::Ec(EcKeyData::new(
            //     13,
            //     key_info.private_key.to_vec(),
            // ));
            // std::fs::write(
            //     "/tmp/x/gen.private",
            //     key_data.gen_private_key_file_text().unwrap(),
            // )
            // .unwrap();

            // let pubkey_rr = format!("{}    {}    DNSKEY  256 3 {} {} ;{{id = {} (zsk), size = {}b}}", zone.apex_name(), zone.class(), key.algorithm().unwrap().to_int(), base64::encode_string(&pubkey), key.key_tag().unwrap(), pubkey.len());
            // std::fs::write("/tmp/x/gen.key", pubkey_rr).unwrap();

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

            tokio::task::spawn(zone.read().walk_async(Box::new(
                move |name, rrset, at_zone_cut| {
                    // Do not emit glue records as the zone is not authoritative
                    // for glue and only authoritative records should be signed.
                    if !at_zone_cut || !rrset.rtype().is_glue() {
                        tx.send((name, rrset.clone())).unwrap();
                    }
                },
            )));

            fn find_apex(
                records: &SortedRecords<StoredName, StoredRecordData>,
            ) -> Result<(FamilyName<Name<Bytes>>, Ttl), std::io::Error>
            {
                let soa = match records.find_soa() {
                    Some(soa) => soa,
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "cannot find SOA record",
                        ))
                    }
                };
                let ttl = match *soa.first().data() {
                    ZoneRecordData::Soa(ref soa) => soa.minimum(),
                    _ => unreachable!(),
                };
                Ok((soa.family_name().cloned(), ttl))
            }

            let mut records =
                SortedRecords::<StoredName, StoredRecordData>::new();

            while let Some((owner, rrset)) = rx.recv().await {
                for rr in rrset.data() {
                    let rec = Record::new(
                        owner.clone(),
                        Class::IN,
                        rrset.ttl(),
                        rr.clone(),
                    );
                    records.insert(rec).unwrap();
                }
            }

            // https://www.rfc-editor.org/rfc/rfc9276#section-3.1
            // - SHA-1, no extra iterations, empty salt.
            let alg = Nsec3HashAlg::SHA1;
            let flags = 0;
            let iterations = 2;
            let salt =
                Nsec3Salt::from_octets(Bytes::from_static(&[0x4, 0xD2]))
                    .unwrap();

            let (apex, ttl) = find_apex(&records).unwrap();
            let nsecs = records.nsec3s::<_, BytesMut>(
                &apex, ttl, alg, flags, iterations, salt,
            );
            records.extend(nsecs.into_iter().map(Record::from_record));
            let record = apex.dnskey(ttl, &key).unwrap();
            let _ = records.insert(Record::from_record(record));
            let inception: Timestamp =
                Timestamp::now().into_int().sub(10).into();
            let expiration = inception.into_int().add(2592000).into(); // XXX 30 days
            let rrsigs =
                records.sign(&apex, expiration, inception, &key).unwrap();
            records.extend(rrsigs.into_iter().map(Record::from_record));
            eprintln!("Writing to file /tmp/x/zone.out");
            let mut dump_file = File::create("/tmp/x/zone.out").unwrap();
            records.write(&mut dump_file).unwrap();
            eprintln!("Write complete");

            // // NSEC testing
            // println!("NSEC'ing and updating...");
            // let mut zone_updater =
            //     ZoneUpdater::new(zone.clone()).await.unwrap();
            // let mut zone_iter = NsecZoneIter::new(zone.clone());
            // while let Some(rec) = zone_iter.next().await {
            //     // This won't work for an NSEC at a CNAME as the tree only
            //     // allows storing a CNAME at the node, not an NSEC too.
            //     let update = ZoneUpdate::AddRecord(rec);
            //     zone_updater.apply(update).await.unwrap();
            // }

            // let dnskey = key.dnskey().unwrap();
            // let rec: StoredRecord = Record::new(
            //     zone.apex_name().to_owned(),
            //     zone.class(),
            //     Ttl::ZERO,
            //     dnskey.convert().into(),
            // );
            // // WARNING: This won't correctly add an NSEC record to a CNAME.
            // let update = ZoneUpdate::AddRecord(rec);
            // zone_updater.apply(update).await.unwrap();

            // zone_updater
            //     .apply(ZoneUpdate::FinishedWithoutNewSoa)
            //     .await
            //     .unwrap();

            // println!(
            //     "Dumping zone {} class {}...",
            //     zone.apex_name(),
            //     zone.class()
            // );
            // zone.read()
            //     .walk(Box::new(move |owner, rrset, _at_zone_cut| {
            //         dump_rrset(owner, rrset);
            //     }));
            // println!("Dump complete.");

            // // signing testing
            // println!("signing and updating...");

            // // // bump the SOA manually before signing.
            // // let (old_soa_ttl, old_soa_data) = zone.read().query(zone.apex_name().to_owned(), Rtype::SOA).unwrap().content().first().unwrap();
            // // let ZoneRecordData::Soa(old_soa) = old_soa_data else {
            // //     unreachable!();
            // // };

            // // // Create a SOA record with a higher serial number than the previous
            // // // SOA record.
            // // let new_soa_serial = old_soa.serial().add(1);
            // // let new_soa_data = domain::rdata::Soa::new(
            // //     old_soa.mname().clone(),
            // //     old_soa.rname().clone(),
            // //     new_soa_serial,
            // //     old_soa.refresh(),
            // //     old_soa.retry(),
            // //     old_soa.expire(),
            // //     old_soa.minimum(),
            // // );
            // // let new_soa_data = ZoneRecordData::Soa(new_soa_data);
            // // let new_soa_rr = Record::new(zone.apex_name().to_owned(), Class::IN, old_soa_ttl, new_soa_data);

            // let mut zone_updater =
            //     ZoneUpdater::new(zone.clone()).await.unwrap();
            // let inception = Timestamp::now();
            // let expiration = Timestamp::now().into_int().add(600).into();

            // let mut zone_iter =
            //     SignZoneIter::new(zone.clone(), key, expiration, inception);
            // while let Some(rec) = zone_iter.next().await {
            //     // This won't work for an RRSIG at a CNAME as the tree only
            //     // allows storing a CNAME at the node, not an RRSIG too. Also,
            //     // I wonder if the walk order is correct if we allow as now
            //     // that the RRSIGs at an owner name get grouped together under
            //     // their own RRtype instead of each RRSIG being associated in
            //     // some way with the RRset for a single RTYPE that it covers?
            //     let update = ZoneUpdate::AddRecord(rec);
            //     zone_updater.apply(update).await.unwrap();
            // }
            // zone_updater
            //     .apply(ZoneUpdate::Finished)
            //     .await
            //     .unwrap();

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
    let wire_query = generate_wire_query(&qname, qtype);
    let wire_response = generate_wire_response(&wire_query, zone_answer);
    print_dig_style_response(&wire_query, &wire_response, short);
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
    for item in rrset.data() {
        let record = Record::new(owner.clone(), Class::IN, rrset.ttl(), item);
        let mut target = Vec::<u8>::new();
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

    if let Some(item) = rrset.rrsig() {
        let record = Record::new(owner.clone(), Class::IN, rrset.ttl(), item);
        let mut target = Vec::<u8>::new();
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
        apex_ttl: Option<Ttl>,
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

                let apex_ttl = if rrset.rtype() == Rtype::SOA {
                    let shared_rr = rrset.first().unwrap();
                    let ZoneRecordData::Soa(soa) = shared_rr.data() else {
                        unreachable!();
                    };
                    // bitmap.add(Rtype::DNSKEY).unwrap();
                    Some(soa.minimum())
                } else {
                    None
                };

                *self = NsecZoneIterState::Next {
                    apex_name: name.clone(),
                    apex_ttl,
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

                    if apex_ttl.is_none() && rrset.rtype() == Rtype::SOA {
                        let shared_rr = rrset.first().unwrap();
                        let ZoneRecordData::Soa(soa) = shared_rr.data()
                        else {
                            unreachable!();
                        };
                        *apex_ttl = Some(soa.minimum());
                        bitmap.add(Rtype::DNSKEY).unwrap();
                    }

                    None
                } else {
                    // A new RRset.
                    let finalized_bitmap = Self::finalize_bitmap(bitmap);
                    bitmap.add(rrset.rtype()).unwrap();
                    let nsec = Nsec::new(name.clone(), finalized_bitmap);
                    let last_name = std::mem::replace(last_name, name);
                    let nsec_rec = Record::new(
                        last_name,
                        Class::IN,
                        apex_ttl.unwrap(),
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
            apex_ttl.unwrap(),
            ZoneRecordData::Nsec(nsec),
        );

        *self = NsecZoneIterState::End;

        nsec_rec
    }

    fn finalize_bitmap(
        bitmap: &mut RtypeBitmapBuilder<BytesMut>,
    ) -> RtypeBitmap<Bytes> {
        bitmap.add(Rtype::RRSIG).unwrap();
        // bitmap.add(Rtype::NSEC).unwrap();
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

//------------ SignZoneIter --------------------------------------------------

pub struct SignZoneIter<Key>
where
    Key: SigningKey<Signature = Signature> + Unpin,
    <Key as SigningKey>::Error: Debug,
{
    rx: UnboundedReceiver<(Name<Bytes>, SharedRrset, bool)>,

    iter_state: SignZoneIterState<Key>,
}

struct SignZoneIterState<Key> {
    apex_name: StoredName,
    key: Key,
    inception: Timestamp,
    expiration: Timestamp,
    buf: Vec<u8>,
}

impl<Key> SignZoneIter<Key>
where
    Key: SigningKey<Signature = Signature> + Unpin,
    <Key as SigningKey>::Error: Debug,
{
    pub fn new(
        zone: Zone,
        key: Key,
        expiration: Timestamp,
        inception: Timestamp,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        tokio::task::spawn(zone.read().walk_async(Box::new(
            move |name, rrset, at_zone_cut| {
                tx.send((name, rrset.clone(), at_zone_cut)).unwrap();
            },
        )));

        Self {
            rx,
            iter_state: SignZoneIterState {
                apex_name: zone.apex_name().to_owned(),
                key,
                inception,
                expiration,
                buf: vec![],
            },
        }
    }
}

impl<Key> SignZoneIterState<Key>
where
    Key: SigningKey<Signature = Signature>,
    <Key as SigningKey>::Error: Debug,
{
    fn step(
        &mut self,
        name: StoredName,
        rrset: SharedRrset,
        at_zone_cut: bool,
    ) -> Option<StoredRecord> {
        if at_zone_cut {
            if rrset.rtype() != Rtype::DS && rrset.rtype() != Rtype::NSEC {
                return None;
            }
        } else if rrset.rtype() == Rtype::RRSIG {
            return None;
        }

        eprintln!("Clear buf");
        self.buf.clear();
        let rrsig = ProtoRrsig::new(
            rrset.rtype(),
            self.key.algorithm().unwrap(),
            name.rrsig_label_count(),
            rrset.ttl(),
            self.expiration,
            self.inception,
            self.key.key_tag().unwrap(),
            self.apex_name.clone(),
        );
        rrsig.compose_canonical(&mut self.buf).unwrap();
        for data in rrset.data() {
            let record = Record::from((&name, Class::IN, rrset.ttl(), data));
            eprintln!("{record:?}");
            record.compose_canonical(&mut self.buf).unwrap();
        }

        Some(Record::new(
            name.clone(),
            Class::IN,
            rrset.ttl(),
            ZoneRecordData::Rrsig(
                rrsig
                    .into_rrsig(self.key.sign(&self.buf).unwrap().into())
                    .unwrap(),
            ),
        ))
    }
}

impl<Key> Stream for SignZoneIter<Key>
where
    Key: SigningKey<Signature = Signature> + Unpin,
    <Key as SigningKey>::Error: Debug,
{
    type Item = StoredRecord;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.as_mut().rx.poll_recv(cx) {
            Poll::Ready(Some((name, rrset, at_zone_cut))) => {
                match self.iter_state.step(name, rrset, at_zone_cut) {
                    Some(rrsig_rec) => {
                        // RRset completed, RRSIG record created
                        Poll::Ready(Some(rrsig_rec))
                    }
                    None => {
                        // RRset in-proress, no RRSIG record
                        // Poll again to process the next RR.
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }

            Poll::Ready(None) => Poll::Ready(None),

            Poll::Pending => Poll::Pending,
        }
    }
}
