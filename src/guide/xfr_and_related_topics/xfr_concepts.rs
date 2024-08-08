//! # XFR and related concepts and how they apply to domain.
//! 
//! This page describes XFR and related concepts as relevant to the
//! functionality available in the domain crate.
//! 
//! ### Primary or secondary?
//! 
//! Many DNS related RFCs refer to the notion of primary and secondary name
//! servers and [RFC 9499 DNS
//! Terminology](https://www.rfc-editor.org/rfc/rfc9499.html) contains
//! definitions for these terms.
//! 
//! In this documentation the notions of primary and secondary are a simple
//! way to express which actions one can expect a server to take for the zones
//! that it has:
//! 
//! - A primary may send out NOTIFY messages to, and respond to XFR requests
//! from, one or more secondary servers.
//! 
//! - A secondary may act upon NOTIFY requests received from, and send XFR
//!  requests to, one or more primary servers.
//! 
//! In the simplest case a server is either primary or secondary, though more
//! complex deployments are possible such as hidden primaries, secondaries
//! that are also themselves primary to other servers, mixed servers that are
//! primary for some zones and secondary for others, etc.
//! 
//! <div class="warning">
//! 
//! The domain crate does not require you to define your name server as
//! primary or secondary. Rather it offers the building blocks to do the
//! various protocol actions associated with primary and secondary roles and
//! you decide which of them to use.
//! 
//! </div>
//! 
//! ### Synchronizing content between servers
//! 
//! XFR is an abbreviation of the word transfer and refers to the replication
//! of zone content between DNS name servers and clients.
//! 
//! XFR is intended primarily for enabling secondary servers to keep their
//! zone content in sync with a primary server.
//! 
//! Two modes of transfer are defined:
//! 
//! - [AXFR](https://datatracker.ietf.org/doc/rfc5936) (Authoritative XFR)
//!   sends a full copy of the requested zone to requesting clients. Name
//!   servers are required by [RFC
//!   1034](https://www.rfc-editor.org/rfc/rfc1034.html) to support AXFR.
//! 
//! - [IXFR](https://datatracker.ietf.org/doc/rfc1995) (Incremental XFR) sends
//!   changes to the zone to requesting clients to enable them to update their
//!   copy of the zone to match that of the server. IXFR is optional, name
//!   servers are not required to support it.
//!
//! <div class="warning">
//! 
//! The domain crate supports AXFR, IXFR and fallback from IXFR to AXFR. For
//! IXFR changes to zones are captured (both for zones edited locally and for
//! zones that were updated via IXFR from a secondary) and stored in memory.
//! but are not persisted. Persisting of zones is possible but not yet offered
//! out-of-the-box. An example of automated persistence of modified zones to
//! disk is shown in the
//! [`examples/serve-zone.rs`](https://github.com/NLnetLabs/domain/blob/xfr/examples/serve-zone.rs)
//! example in the domain crate GitHub repository.
//! 
//! The domain crate doesn't yet have support for purging older change sets or
//! for "condensing" change sets. It also only supports creation of IXFR
//! change sets for local edits or changes received via IXFR, i.e. differences
//! between the old zone and the new zone are not calculated when a zone is
//! updated by AXFR.
//! 
//! </div>
//! 
//! ### Benefits & risks of XFR and the need for access control
//! 
//! The nature of XFR poses significant risk to a DNS name server due to the
//! comparatively long running nature of XFR transactions and the amount of
//! resources needed to serve them.
//! 
//! Depending on the size of the zone the response to an XFR query may be
//! sufficiently large that it spans multiple DNS response messages and takes
//! a long time to serve compared to other DNS requests, potentially keeping a
//! lot of server resources busy for longer than other types of request.
//! 
//! To accommodate the large message size and the stream of related messages
//! all of which need to be reliably received in sequence, zone transfers are
//! mainly[^note] done over TCP rather than UDP.
//! 
//! Both the large response size and use of TCP are in contrast to the
//! majority of the DNS protocol which, at least until developments such as
//! DNSSEC caused response size to increase considerably, consisted mainly of
//! single responses served over UDP.
//! 
//! If accessible to a client the ability to obtain a complete copy of a zone
//! offers transparency and insight, but access is often restricted as it can
//! be a privacy concern and for large zones is much more impacting for a
//! server to respond to XFR requests than other requests. XFR configuration
//! therefore typically involves limiting access only to authorized parties.
//! 
//! [^note]: [RFC 1034], [RFC 5936] and [RFC 9103] all state that AXFR is
//! restricted to TCP, but [RFC 1995] states _"If an IXFR query is via UDP,
//! the IXFR server may attempt to reply using UDP if the entire response can
//! be contained in a single DNS packet"_.
//!
//! [RFC 1034]: https://www.rfc-editor.org/rfc/rfc1034.html
//! [RFC 1995]: https://www.rfc-editor.org/rfc/rfc1995.html
//! [RFC 5936]: https://www.rfc-editor.org/rfc/rfc5936.html
//! [RFC 9103]: https://www.rfc-editor.org/rfc/rfc9103.html
//! 
//! <div class="warning">
//! 
//! The domain crate has limited support at present for restricting access by
//! clients to XFR and on restricting resources used by the server.
//! Restricting client access is on a per IP address basis, netblocks are not
//! yet supported, and the number of concurrently active XFR sessions can be
//! limited, but there is no support for IXFR change set purging yet or any
//! other restrictions.
//! 
//! </div>
//! 
//! ### NOTIFY, TSIG and zone maintenance
//! 
//! Closely related to XFR are NOTIFY, TSIG and zone maintenance.
//! 
//! - NOTIFY messages inform a server that one of its zones may be outdated
//!   compared to another copy of the zone on a different server.
//! 
//! - TSIG is a mechanism for signing DNS messages to authenticate the parties
//!   involved and to prove that exchanged messages have not been tampered
//!   with.
//! 
//! - Zone maintenance concerns keeping a secondary zone in sync with a
//!   primary copy according to a schedule defined by timer values in the SOA
//!   resource record of a zone.
//! 
//! <div class="warning">
//! 
//! The domain crate supports NOTIFY for the SOA QTYPE only, and does not look
//! at any SOA record provided in received NOTIFY messages, it only uses the
//! NOTIFY as a possible trigger to refresh the zone.
//! 
//! There is also currently no support for retrying sent NOTIFY messages or
//! tracking if they were acknowledged.
//! 
//! </div>
