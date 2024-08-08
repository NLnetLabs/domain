//! # Zone maintenance and transfers.
//! 
//! Keeping zones up-to-date across a group of DNS name servers has its own
//! section in one of the earliest DNS RFCs, [RFC 1034 Domain Names - Concepts
//! and Facilities](https://www.rfc-editor.org/rfc/rfc1034.html):
//! 
//! > _Part of the job of a zone administrator is to maintain the zones at all
//! > of the name servers which are authoritative for the zone.  When the
//! > inevitable changes are made, they must be distributed to all of the name
//! > servers.  While this distribution can be accomplished using FTP or some
//! > other ad hoc procedure, the preferred method is the zone transfer part
//! > of the DNS protocol._
//! 
//! The key RFCs that define the zone transfer and related functionality
//! supported by the domain crate are:
//! - [RFC 1995]: Incrememental Zone Transfer in DNS (IXFR)
//! - [RFC 1996]: A Mechanism for Prompt Notification of Zone Changes (NOTIFY)
//! - [RFC 5936]: DNS Zone Transfer Protocol (AXFR)
//! - [RFC 8945]: Secret Key Transaction Authentication for DNS (TSIG)
//! 
//! [RFC 1995]: https://www.rfc-editor.org/rfc/rfc1995.html
//! [RFC 1996]: https://www.rfc-editor.org/rfc/rfc1996.html
//! [RFC 5936]: https://www.rfc-editor.org/rfc/rfc5936.html
//! [RFC 8945]: https://www.rfc-editor.org/rfc/rfc8945.html
//! 
//! As you might have noticed from these RFC titles, zone transfer is often
//! referred to as XFR.
//! 
//! These pages describe the XFR related concepts and functionality that are
//! available with the domain crate and how to use them.
//! 
//! ### An example
//! 
//! Let's take a quick look at the domain components that have to be used
//! together to offer fully functional zone transfer support. It looks like a
//! lot, and it is, but that's also because there's quite a lot going on with
//! server to server zone transfer in DNS.
//! 
//! _**Note:** This incomplete pseudo Rust code is based on the fully working
//! [`examples/serve-zone.rs`](https://github.com/NLnetLabs/domain/blob/xfr/examples/serve-zone.rs)
//! example in the domain crate GitHub repository. Do not try and compile and
//! run this code snippet, instead look at the example in the GitHub
//! repository!_
//! 
//! ```ignore
//! // Create and populate a key store with any TSIG keys that we want to use:
//! let mut key_store = CatalogKeyStore::new();
//! key_store.insert(...);
//! 
//! // Specify for an existing zone (not defined here) which XFR related
//! // operations should be permitted and by which clients:
//! let mut zone_cfg = ZoneConfig::new();
//! zone_cfg.request_xfr_from(...);
//! zone_cfg.provide_xfr_to(...);
//! zone_cfg.allow_notify_from(...);
//! zone_cfg.send_notify_to(...);
//! let zone = TypedZone::new(zone, zone_cfg);
//! 
//! // Create a catalog to hold our zones and to keep them synchronized with
//! // other name servers:
//! let cat_config = catalog::Config::<_, DefaultConnFactory>::new(key_store);
//! let catalog = Catalog::new_with_config(cat_config);
//! let catalog = Arc::new(catalog);
//! catalog.insert_zone(...).await.unwrap();
//!
//! // Build a stack of middleware layers with our application service (not
//! // defined here) at the top:
//! let max_concurrent_xfrs = 1;
//! let svc = service_fn(my_service, catalog.clone());
//! let svc: XfrMiddlewareSvc<Vec<u8>, _, _> =
//!     XfrMiddlewareSvc::<Vec<u8>, _, _>::new(
//!         svc,
//!         catalog.clone(),
//!         max_concurrent_xfrs,
//!         XfrMode::AxfrAndIxfr,
//!     );
//! let svc = NotifyMiddlewareSvc::<Vec<u8>, _, _, _>::new(svc, catalog.clone());
//! let svc = MandatoryMiddlewareSvc::<Vec<u8>, _, _>::new(svc);
//! let svc = TsigMiddlewareSvc::<Vec<u8>, _, _>::new(svc, config.key_store);
//! 
//! // Create and run a server that will pass incoming requests to our service
//! // layers:
//! let tcp_srv = StreamServer:new(sock, VecBufSource, svc);
//! tokio::spawn(async move { tcp_srv.run().await });
//! 
//! // Run the catalog in the background so that it can initiate zone transfers
//! // as needed:
//! tokio::spawn(async move { catalog.run().await });
//! 
//! // Ready!
//! ```
//! 
//! <div class="warning">
//! 
//! Knowledgeable readers may have noticed the similarity between the term
//! `Catalog` and [RFC 9432](https://datatracker.ietf.org/doc/rfc9432) DNS
//! Catalog Zones.
//! 
//! There is no support yet in domain for catalog zones, but the intention is
//! that the [`Catalog`] type acts itself in future as an RFC 9432 catalog
//! zone.
//! 
//! </div>
//! 
//! ### Next steps
//! 
//! Read about the [XFR and related concepts](xfr_concepts) relevant to the
//! domain crate, which components it offers and [how to use
//! them](xfr_in_domain).
//! 
//! [`Catalog`]: crate::zonecatalog::catalog::Catalog

pub mod xfr_concepts;
pub mod xfr_in_domain;