//! Resolver Architecture Documentation
//!
//! <i>This module does not contain any code. It is intended for more
//! detailed documentation of the resolver. Currently, that is limited to
//! a short introduction to its architecture.</i>
//!
//! Let’s start with a bunch of terms: the *resolver* is the collection of
//! all things necessary for answer DNS *queries*. It relies on a number
//! of *services* that represent a single upstream DNS server. Services
//! answer *requests*, that is, they take a DNS request message and try
//! transforming it into a DNS response message or a failure.
//!
//! A query is processed by sending requests to various services according
//! to the resolver configuration until one request succeeds or there is a
//! fatal error (currently, that only happens when the question is broken)
//! or we run out of services to ask. Thus, a query issues a sequence of
//! requests to a number of services.
//!
//! Services are futures spawned into a tokio reactor core. For accepting
//! requests, they have a tokio channel receiver and run until that receiver
//! is disconnected. For responding to requests they are oneshots. Once a
//! service has determined the outcome for a request, it simply completes
//! that oneshot with the result, waking up the query and allowing it to
//! move on.
//!
//! In order to do their work, queries need the sending end of the services’
//! channels as well as the resolver configuration. This is bundled into an
//! internal type named `Core`. Since `Sender`s are not `Sync`, types that
//! contain them do not fulfill the requirements for implementing
//! `Future::boxed()`. This is the reason for the somewhat awkward
//! `ResolverTask`. It keeps its own copy of the core as a `TaskRc<Core>`
//! but it can only create that once there is a task.
//!
//! This also means that each resolver future has its own clone of the core
//! which seems a bit unnecessary. The other option would be to keep the
//! core in an `Arc<Mutex<Core>>` which may have negative consequences in
//! high load situations. Perhaps there is an even better way,
//! either by changing the way queries communicate with services or through
//! something clever? Generally, though, the cloning shouldn’t be too bad.
//! Typical resolver configurations amount to either two or four services
//! (one or two servers with UDP and TCP each), plus the configuration
//! which is stored behind an Arc. But at least the `TaskRc<_>` means that
//! all queries within the same future share one core (typically, address
//! lookups run `A` and `AAAA` queries in parallel).
//!
//! There’s two types of services: datagram services and stream services.
//! Currently, each of these has one concrete implementation: UDP service
//! and TCP service respectively. Encrypted variants will be added later.
//!
//! Both types of services are lazy. They will only open an actual socket
//! when the first request arrives. This is because in a typical
//! configuration, the second server and all the streaming variants are
//! likely to be unused.
//!
//! Since UDP sockets are somewhat cheap, the datagram service keeps its
//! socket once opened, so it is basically just a future that first waits
//! for a request on its receiver and, once one arrives, transforms into
//! the actual service.
//!
//! For stream services, things are a little more difficult. After
//! connecting, they keep their socket open for some time expecting further
//! requests (there is also an option to reopen the connection for each
//! request but that has not yet been implemented). So the future has to
//! shuttle back and forth between an idle state that waits for a request
//! and an active state doing actual work and eventually timing out,
//! returning to idle state. The implementation is somewhat complicated
//! by the fact that we need to move the receiving end of the channel between
//! these states, so simple approaches like `Future::select()` don’t
//! suffice.
//!
//! Both types of services are capable of multiplexing requests. DNS
//! messages contain an ID chosen by the client and repeated in the server’s
//! response for that purpose. Before sending a request, the service picks
//! a random ID (which means that resends will have a new ID), keeps sent
//! requests in a map, and matches incoming responses against that map.
//! The map also serves to time out requests if they linger for too long.
//!
