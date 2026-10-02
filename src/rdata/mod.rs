//! Record Data of Well-defined Record Types
//!
//! This module will eventually contain implementations for the record data
//! of all defined resource record types.
//!
//! The types are named identically to the
//! [`domain::base::iana::Rtype`][crate::base::iana::Rtype] variant they
//! implement. They are grouped into submodules for the RFCs they are defined
//! in. All types are also re-exported at the top level here. Ie., for the
//! AAAA record type, you can simply `use domain::rdata::Aaaa` instead of
//! `use domain::rdata::rfc3596::Aaaa` which nobody could possibly
//! remember. There are, however, some helper data types defined here and
//! there which are not re-exported to keep things somewhat tidy.
//!
//! See the [`domain::base::iana::Rtype`][crate::base::iana::Rtype] enum for
//! the complete set of record types and, consequently, those types that are
//! still missing.
//!
//! In addition, the module provides two enums combining the known types.
//! [`AllRecordData`] indeed contains all record data types known plus
//! [`UnknownRecordData`] for the rest, while [`ZoneRecordData`] only
//! contains those types that can appear in zone files plus, again,
//! [`UnknownRecordData`] for everything else.

// A note on implementing record types with embedded domain names with regards
// to compression and canonical representation:
//
// RFC 3597 stipulates that only record data of record types defined in RFC
// 1035 is allowed to be compressed. (These are called “well-known record
// types.”) For all other types, `CompressDname::append_compressed_name`
// must not be used and the names be composed with `ToDname::compose`.
//
// RFC 4034 defines the canonical form of record data. For this form, domain
// names included in the record data of the following record types must be
// composed canonically using `ToName::compose_canonical`: All record types
// from RFC 1035 plus RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6,
// RRSIG, NSEC. All other record types must be composed canonically using
// `ToName::compose`.
//
// The macros module contains three macros for generating name-only record
// types in these three categories: `name_type_well_known!` for types from
// RFC 1035, `name_type_canonical!` for non-RFC 1035 types that need to be
// lowercased, and `name_type!` for everything else.

#[macro_use]
mod macros;

pub mod aaaa;
pub mod caa;
pub mod cds;
pub mod dname;
pub mod dnssec;
pub mod ipseckey;
pub mod naptr;
pub mod nsec3;
pub mod openpgpkey;
pub mod rfc1035;
pub mod rp;
pub mod srv;
pub mod sshfp;
pub mod svcb;
pub mod tlsa;
pub mod tsig;
pub mod zonemd;

// The rdata_types! macro (defined in self::macros) defines the modules
// containing the record data types, re-exports those here, and creates the
// ZoneRecordData and AllRecordData enums containing all record types that
// can appear in a zone file and all record types that exist.
//
// All record data types listed here MUST have the same name as the
// `Rtype` variant they implement – some of the code implemented by the macro
// relies on that.
//
// Add any new module here and then add all record types in that module that
// can appear in zone files under "zone" and all others under "pseudo".
// Your type can be generic over an octet type "O" and a domain name type "N".
// Add these as needed. Trait bounds on them differ for different methods, so
// check the bounds on ZoneRecordData and AllRecordData if there are errors.
rdata_types! {
    rfc1035::{
        zone {
            A,
            Cname<N>,
            Hinfo<O>,
            Mb<N>,
            Md<N>,
            Mf<N>,
            Mg<N>,
            Minfo<N>,
            Mr<N>,
            Mx<N>,
            Ns<N>,
            Ptr<N>,
            Soa<N>,
            Txt<O>,
        }
        pseudo {
            Null<O>
        }
    }
    aaaa::{
        zone {
            Aaaa,
        }
    }
    caa::{
        zone {
            Caa<O>,
        }
    }
    cds::{
        zone {
            Cdnskey<O>,
            Cds<O>,
        }
    }
    dname::{
        zone {
            Dname<N>,
        }
    }
    dnssec::{
        zone {
            Dnskey<O>,
            Rrsig<O, N>,
            Nsec<O, N>,
            Ds<O>,
        }
    }
    ipseckey::{
        zone {
            Ipseckey<O, N>,
        }
    }
    naptr::{
        zone {
            Naptr<O, N>,
        }
    }
    nsec3::{
        zone {
            Nsec3<O>,
            Nsec3param<O>,
        }
    }
    openpgpkey::{
        zone {
            Openpgpkey<O>,
        }
    }
    rp::{
        zone {
            Rp<N>,
        }
    }
    srv::{
        zone {
            Srv<N>,
        }
    }
    sshfp::{
        zone {
            Sshfp<O>,
        }
    }
    svcb::{
        zone {
            Svcb<O, N>,
            Https<O, N>,
        }
    }
    tlsa::{
        zone {
            Tlsa<O>,
        }
    }
    tsig::{
        pseudo {
            Tsig<O, N>,
        }
    }
    zonemd::{
        zone {
            Zonemd<O>,
        }
    }
}

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod compression_tests {
    //! RFC 3597 §4: only RFC 1035 types may compress rdata names.
    //!
    //! Every DNS record type whose rdata contains a domain name is covered
    //! here. All rdata is round-tripped through [`AllRecordData`]: composed
    //! into an uncompressed message, re-parsed, then re-composed through
    //! `StaticCompressor`. When the crate adds native support for a type,
    //! the test automatically exercises the new `compose_rdata` without
    //! changes.

    use alloc::{vec, vec::Vec};
    use core::str::FromStr;

    use rstest::rstest;

    use crate::{
        base::{
            CharStr, Message, MessageBuilder, Name, StaticCompressor,
            StreamTarget, Ttl,
            iana::{Class, IpseckeyAlgorithm, SecurityAlgorithm, TsigRcode},
        },
        rdata::{
            dnssec::{RtypeBitmapBuilder, Timestamp},
            ipseckey::IpseckeyGateway,
            svcb::SvcParams,
            tsig::Time48,
        },
    };

    use super::*;

    /// Wire-format encoding of `example.com.`.
    const EXAMPLE_COM: &[u8] = b"\x07example\x03com\x00";

    fn name(s: &str) -> Name<Vec<u8>> {
        Name::from_str(s).unwrap()
    }

    fn has_compression_pointer(bytes: &[u8]) -> bool {
        bytes.iter().any(|b| b & 0xC0 == 0xC0)
    }

    fn unknown(rtype: Rtype, raw: &[u8]) -> UnknownRecordData<Vec<u8>> {
        UnknownRecordData::from_octets(rtype, raw.to_vec()).unwrap()
    }

    /// Compose `rdata` through `StaticCompressor` with `example.com` in
    /// the question section as the compression target.  Returns the raw
    /// rdata bytes from the resulting message.
    ///
    /// The rdata is first composed into an uncompressed message, then
    /// re-parsed through [`AllRecordData`] and re-composed through the
    /// compressor. When the crate adds native support for a type that
    /// was passed in as [`UnknownRecordData`], `AllRecordData` dispatches
    /// to the native variant and the re-compose step exercises its
    /// `compose_rdata`, catching incorrect compression automatically.
    fn rdata_wire<R: ComposeRecordData>(rtype: Rtype, rdata: R) -> Vec<u8> {
        let qname = name("example.com");

        // Phase 1: compose without compression, re-parse through
        // AllRecordData (native variant when available).
        let uncompressed = {
            let b =
                MessageBuilder::from_target(StreamTarget::new_vec()).unwrap();
            let mut b = b.question();
            b.push((&qname, rtype)).unwrap();
            let mut b = b.answer();
            b.push((&qname, Class::IN, Ttl::from_secs(300), &rdata))
                .unwrap();
            b.finish()
        };
        let msg = Message::from_octets(uncompressed.as_ref()).unwrap();
        let parsed = msg
            .answer()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .to_any_record::<AllRecordData<_, ParsedName<_>>>()
            .unwrap();

        // Phase 2: re-compose through StaticCompressor.
        let compressed = {
            let b = MessageBuilder::from_target(StaticCompressor::new(
                StreamTarget::new_vec(),
            ))
            .unwrap();
            let mut b = b.question();
            b.push((&qname, rtype)).unwrap();
            let mut b = b.answer();
            b.push((&qname, Class::IN, Ttl::from_secs(300), parsed.data()))
                .unwrap();
            b.finish().into_target()
        };
        let wire = compressed.as_ref();
        let rdlen = Message::from_octets(wire)
            .unwrap()
            .answer()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .rdlen() as usize;

        wire[wire.len() - rdlen..].to_vec()
    }

    // ---- RFC 1035 types: rdata names MUST be compressed ----

    #[rstest]
    #[case::cname(Rtype::CNAME, Cname::new(name("example.com")))]
    #[case::ns(Rtype::NS, Ns::new(name("example.com")))]
    #[case::ptr(Rtype::PTR, Ptr::new(name("example.com")))]
    #[case::mb(Rtype::MB, Mb::new(name("example.com")))]
    #[case::mg(Rtype::MG, Mg::new(name("example.com")))]
    #[case::mr(Rtype::MR, Mr::new(name("example.com")))]
    #[case::md(Rtype::MD, Md::new(name("example.com")))]
    #[case::mf(Rtype::MF, Mf::new(name("example.com")))]
    #[case::mx(Rtype::MX, Mx::new(10, name("example.com")))]
    #[case::minfo(
        Rtype::MINFO,
        Minfo::new(name("a.example.com"), name("b.example.com"))
    )]
    #[case::soa(Rtype::SOA,  Soa::new(
        name("ns.example.com"), name("admin.example.com"),
        1u32.into(), Ttl::from_secs(3600), Ttl::from_secs(900),
        Ttl::from_secs(604800), Ttl::from_secs(86400),
    ))]
    fn rfc1035_types_compress_rdata_names<R: ComposeRecordData>(
        #[case] rtype: Rtype,
        #[case] rdata: R,
    ) {
        assert!(
            has_compression_pointer(&rdata_wire(rtype, rdata)),
            "{rtype} rdata must use compression (RFC 1035 well-known type)",
        );
    }

    // ---- Non-RFC-1035 types: MUST NOT compress (RFC 3597 §4) ----

    #[rstest]
    // Native types
    #[case::rp(
        Rtype::RP,
        Rp::new(name("a.example.com"), name("b.example.com"))
    )]
    #[case::dname_rdata(Rtype::DNAME, Dname::new(name("example.com")))]
    #[case::srv(Rtype::SRV, Srv::new(10, 0, 443, name("example.com")))]
    #[case::naptr(Rtype::NAPTR, Naptr::new(
        100, 10,
        CharStr::from_octets(b"s".as_ref().to_vec()).unwrap(),
        CharStr::from_octets(b"SIP+D2U".as_ref().to_vec()).unwrap(),
        CharStr::from_octets(Vec::new()).unwrap(),
        name("_sip._udp.example.com"),
    ))]
    #[case::rrsig(Rtype::RRSIG, Rrsig::new(
        Rtype::A, SecurityAlgorithm::RSASHA256, 2, Ttl::from_secs(3600),
        Timestamp::from(0x0102_0304), Timestamp::from(0x0102_0204),
        12345, name("example.com"), vec![0x42; 16],
    ).unwrap())]
    #[case::nsec(Rtype::NSEC, {
        let mut b = RtypeBitmapBuilder::new_vec();
        b.add(Rtype::A).unwrap();
        Nsec::new(name("example.com"), b.finalize())
    })]
    #[case::tsig(Rtype::TSIG,  Tsig::new(
        name("hmac-sha256"), Time48::from_u64(1_000_000),
        300, vec![0x42; 32], 0x1234, TsigRcode::NOERROR, Vec::<u8>::new(),
    ).unwrap())]
    #[case::svcb(Rtype::SVCB, Svcb::new(
        1, name("example.com"), SvcParams::<Vec<u8>>::default(),
    ).unwrap())]
    #[case::https(Rtype::HTTPS,  Https::new(
        1, name("example.com"), SvcParams::<Vec<u8>>::default(),
    ).unwrap())]
    #[case::ipseckey(Rtype::IPSECKEY,
        Ipseckey::new(10, IpseckeyAlgorithm::RSA,
            IpseckeyGateway::Name(name("example.com")), vec![0xBB; 16]))]
    //
    // Non-native types
    // Raw wire bytes contain `example.com` as a domain name. When the crate
    // adds native support, AllRecordData will parse into the native variant
    // and the compose step will catch any incorrect compression.
    //
    // AFSDB (RFC 1183): subtype(2) + hostname
    #[case::afsdb(Rtype::AFSDB, unknown(Rtype::AFSDB, &{
        let mut v = vec![0, 1]; v.extend_from_slice(EXAMPLE_COM); v
    }))]
    // RT (RFC 1183): preference(2) + intermediate-host
    #[case::rt(Rtype::RT, unknown(Rtype::RT, &{
        let mut v = vec![0, 10]; v.extend_from_slice(EXAMPLE_COM); v
    }))]
    // NSAP-PTR (RFC 1706): single domain name (PTR format, but non-RFC-1035)
    #[case::nsap_ptr(Rtype::NSAPPTR, unknown(Rtype::NSAPPTR, EXAMPLE_COM))]
    // SIG (RFC 2535): type-covered(2) + algorithm(1) + labels(1) +
    //   original-ttl(4) + expiration(4) + inception(4) + key-tag(2) +
    //   signer-name + signature
    #[case::sig(Rtype::SIG,  unknown(Rtype::SIG, &{
        let mut v = vec![
            0, 1, 8, 2,               // A, RSASHA256, 2 labels
            0, 0, 0x0E, 0x10,         // original TTL = 3600
            0x65, 0x6E, 0x3D, 0x00,   // expiration
            0x65, 0x6E, 0x2D, 0x00,   // inception
            0x30, 0x39,               // key tag = 12345
        ];
        v.extend_from_slice(EXAMPLE_COM);
        v.extend_from_slice(&[0xAA; 16]); // signature
        v
    }))]
    // PX (RFC 2163): preference(2) + map822 + mapx400
    #[case::px(Rtype::PX,  unknown(Rtype::PX, &{
        let mut v = vec![0, 10];
        v.extend_from_slice(EXAMPLE_COM);
        v.extend_from_slice(EXAMPLE_COM);
        v
    }))]
    // NXT (RFC 2535): next-domain-name + type-bitmap (old bit-array format)
    #[case::nxt(Rtype::NXT, unknown(Rtype::NXT, &{
        let mut v = Vec::new();
        v.extend_from_slice(EXAMPLE_COM);
        v.extend_from_slice(&[0x40, 0x01, 0x00, 0x08]); // A + NS + AAAA
        v
    }))]
    // KX (RFC 2230): preference(2) + exchanger
    #[case::kx(Rtype::KX, unknown(Rtype::KX, &{
        let mut v = vec![0, 10]; v.extend_from_slice(EXAMPLE_COM); v
    }))]
    // A6 (RFC 2874): prefix-len(1) + address-suffix(8) + prefix-name
    #[case::a6(Rtype::A6, unknown(Rtype::A6, &{
        let mut v = vec![64]; // prefix length = 64 → 8-byte suffix
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(EXAMPLE_COM);
        v
    }))]
    // HIP (RFC 8005): hit-len(1) + pk-alg(1) + pk-len(2) + HIT + pubkey +
    //   rendezvous-servers
    #[case::hip(Rtype::HIP, unknown(Rtype::HIP, &{
        let mut v = vec![4, 2, 0, 4]; // HIT-len=4, RSA, PK-len=4
        v.extend_from_slice(&[0xAA; 4]); // HIT
        v.extend_from_slice(&[0xBB; 4]); // public key
        v.extend_from_slice(EXAMPLE_COM); // rendezvous server
        v
    }))]
    // LP (RFC 6742): preference(2) + fqdn
    #[case::lp(Rtype::LP, unknown(Rtype::LP, &{
        let mut v = vec![0, 10]; v.extend_from_slice(EXAMPLE_COM); v
    }))]
    // TKEY (RFC 2930): algorithm(name) + inception(4) + expiration(4) +
    //   mode(2) + error(2) + key-size(2) + key-data + other-size(2)
    #[case::tkey(Rtype::TKEY, unknown(Rtype::TKEY, &{
        let mut v = Vec::new();
        v.extend_from_slice(EXAMPLE_COM); // algorithm
        v.extend_from_slice(&[0; 4]);     // inception
        v.extend_from_slice(&[0, 0, 0, 1]); // expiration
        v.extend_from_slice(&[0, 3]);     // mode = DH
        v.extend_from_slice(&[0, 0]);     // error
        v.extend_from_slice(&[0, 4]);     // key size
        v.extend_from_slice(&[0x42; 4]);  // key data
        v.extend_from_slice(&[0, 0]);     // other size
        v
    }))]
    fn non_rfc1035_types_must_not_compress_rdata_names<
        R: ComposeRecordData,
    >(
        #[case] rtype: Rtype,
        #[case] rdata: R,
    ) {
        assert!(
            !has_compression_pointer(&rdata_wire(rtype, rdata)),
            "{rtype} rdata must not use compression (RFC 3597 §4)",
        );
    }

    /// Compression pointer to `example.com` at question offset 12.
    const PTR: &[u8] = &[0xC0, 0x0C];

    /// Build a DNS message with compression pointers inside rdata, parse
    /// through `AllRecordData`, recompose, and verify the names survived
    /// the round-trip. Non-compliant servers may compress rdata names
    /// that RFC 3597 §4 forbids; parsers must still handle this.
    fn parse_compressed_rdata(
        rtype: Rtype,
        compressed_rdata: &[u8],
    ) -> Vec<u8> {
        let mut wire = Vec::new();
        // Header: QR=1 AA=1, QDCOUNT=1, ANCOUNT=1
        wire.extend_from_slice(&[0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0]);
        // Question: example.com <rtype> IN
        // name starts at offset 12
        wire.extend_from_slice(EXAMPLE_COM);
        wire.extend_from_slice(&rtype.to_int().to_be_bytes());
        wire.extend_from_slice(&1_u16.to_be_bytes());
        // Answer: <ptr to 12> <rtype> IN 300 <rdata>
        wire.extend_from_slice(PTR);
        wire.extend_from_slice(&rtype.to_int().to_be_bytes());
        wire.extend_from_slice(&1_u16.to_be_bytes());
        wire.extend_from_slice(&300_u32.to_be_bytes());
        wire.extend_from_slice(
            &(compressed_rdata.len() as u16).to_be_bytes(),
        );
        wire.extend_from_slice(compressed_rdata);

        let msg = Message::from_octets(wire.as_slice()).unwrap();
        let record = msg.answer().unwrap().next().unwrap().unwrap();
        let typed = record
            .to_any_record::<AllRecordData<_, ParsedName<_>>>()
            .unwrap();

        rdata_wire(rtype, typed.into_data())
    }

    #[rstest]
    // RFC 1035 types: compressed rdata is standard
    #[case::cname(Rtype::CNAME, PTR, Cname::new(name("example.com")))]
    #[case::mx(Rtype::MX, &{
        let mut v = vec![0, 10]; // preference
        v.extend_from_slice(PTR); // exchange
        v
    }, Mx::new(10, name("example.com")))]
    #[case::soa(Rtype::SOA, &{
        let mut v = PTR.to_vec(); // mname
        v.extend_from_slice(PTR);     // rname=ptr
        v.extend_from_slice(&1_u32.to_be_bytes()); // serial
        v.extend_from_slice(&3600_u32.to_be_bytes());
        v.extend_from_slice(&900_u32.to_be_bytes());
        v.extend_from_slice(&604800_u32.to_be_bytes());
        v.extend_from_slice(&86400_u32.to_be_bytes());
        v
    }, Soa::new(
        name("example.com"), name("example.com"),
        1u32.into(), Ttl::from_secs(3600), Ttl::from_secs(900),
        Ttl::from_secs(604800), Ttl::from_secs(86400),
    ))]
    // Non-RFC-1035 types: compressed rdata from non-compliant servers.
    #[case::rp(Rtype::RP, &{
        let mut v = PTR.to_vec(); // mbox
        v.extend_from_slice(PTR); // txt
        v
    }, Rp::new(name("example.com"), name("example.com")))]
    #[case::dname_rdata(Rtype::DNAME, PTR, Dname::new(name("example.com")))]
    #[case::srv(Rtype::SRV, &{
        let mut v = vec![0, 10, 0, 0, 1, 0xBB]; // pri=10, w=0, port=443
        v.extend_from_slice(PTR); // target
        v
    }, Srv::new(10, 0, 443, name("example.com")))]
    #[case::naptr(Rtype::NAPTR, &{
        let mut v = vec![
            0, 100, 0, 10,            // order=100, pref=10
            1, b's',                  // flags="s"
            7, b'S', b'I', b'P', b'+', b'D', b'2', b'U', // services
            0,                        // regexp=""
        ];
        v.extend_from_slice(PTR);     // replacement=ptr
        v
    }, Naptr::new(
        100, 10,
        CharStr::from_octets(b"s".as_ref().to_vec()).unwrap(),
        CharStr::from_octets(b"SIP+D2U".as_ref().to_vec()).unwrap(),
        CharStr::from_octets(Vec::new()).unwrap(),
        name("example.com"),
    ))]
    #[case::rrsig(Rtype::RRSIG, &{
        let mut v = vec![
            0, 1, 8, 2,              // type_covered=A, algo=8, labels=2
            0, 0, 0x0E, 0x10,        // original_ttl=3600
            0x01, 0x02, 0x03, 0x04,  // expiration
            0x01, 0x02, 0x02, 0x04,  // inception
            0x30, 0x39,              // key_tag=12345
        ];
        v.extend_from_slice(PTR);    // signer_name=ptr
        v.extend_from_slice(&[0x42; 16]); // signature
        v
    }, Rrsig::new(
        Rtype::A, SecurityAlgorithm::RSASHA256, 2, Ttl::from_secs(3600),
        Timestamp::from(0x0102_0304), Timestamp::from(0x0102_0204),
        12345, name("example.com"), vec![0x42; 16],
    ).unwrap())]
    #[case::nsec(Rtype::NSEC, &{
        let mut v = PTR.to_vec(); // next_name
        v.extend_from_slice(&[0, 1, 0x40]); // bitmap={A}
        v
    }, {
        let mut b = RtypeBitmapBuilder::new_vec();
        b.add(Rtype::A).unwrap();
        Nsec::new(name("example.com"), b.finalize())
    })]
    #[case::svcb(Rtype::SVCB, &{
        let mut v = vec![0, 1]; // priority
        v.extend_from_slice(PTR); // target
        v
    }, Svcb::new(
        1, name("example.com"), SvcParams::<Vec<u8>>::default(),
    ).unwrap())]
    #[case::https(Rtype::HTTPS, &{
        let mut v = vec![0, 1]; // priority
        v.extend_from_slice(PTR); // target
        v
    }, Https::new(
        1, name("example.com"), SvcParams::<Vec<u8>>::default(),
    ).unwrap())]
    #[case::ipseckey(Rtype::IPSECKEY, &{
        let mut v = vec![10, 3, 2]; // prec=10, gw_type=Name, algo=RSA
        v.extend_from_slice(PTR);   // gateway=ptr
        v.extend_from_slice(&[0xBB; 16]); // key
        v
    }, Ipseckey::new(10, IpseckeyAlgorithm::RSA,
        IpseckeyGateway::Name(name("example.com")), vec![0xBB; 16]))]
    fn parses_compressed_rdata_names<R: ComposeRecordData>(
        #[case] rtype: Rtype,
        #[case] compressed: &[u8],
        #[case] expected: R,
    ) {
        let actual = parse_compressed_rdata(rtype, compressed);
        assert_eq!(
            actual,
            rdata_wire(rtype, expected),
            "{rtype}: parsed compressed rdata must match native compose",
        );
    }
}
