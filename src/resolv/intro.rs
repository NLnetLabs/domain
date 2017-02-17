//! Resolver Architecture Documentation
//!
//! <i>This module does not contain any code. It is intended for more
//! detailed documentation of the resolver. Currently, that is limited to
//! a short introduction to its architecture.</i>
//!
//!
//! # What’s in a Resolver?
//!
//! Roughly speaking, the task of a resolver is to answer a question using
//! information stored in the DNS. We shall call this question a *lookup.*
//! There is different lookups for different questions. For example, finding
//! all IP addresses for a given hostname is such a lookup. Finding the IP
//! addresses of the mail server for a given domain is another, somewhat more
//! complex lookup.
//!
//! DNS is a relatively simple key-value store: All information is keyed by
//! a tripel of a domain name, a record type, and a class. The values are a
//! set of binary strings who will be interpreted according to rules defined
//! for each record type. One such entry is called a *resource record set,*
//! commonly shortened to *RRset.*
//!
//! Most lookups will require information from more than one such RRset.
//! For example, there are two types of IP addresses: IPv4 and IPv6
//! addresses. Each type has its own record type, so there are two RRsets
//! to consider when determining all addresses assigned to a host.
//!
//! In this case, the two RRsets can be looked up in parallel. In case of the
//! mail server lookup, we first need to determine the host name of the mail
//! server responsible for the domain. There is a record type and hence a
//! RRset for this purpose. Once we have that, we can look up the IP addresses
//! for that host in parallel.
//!
//! In other words, a lookup performs a series of steps each consisting of
//! asking the DNS for one or more RRsets in parallel.
//!
//! Such a request for a specific RRset is called a *query.* Since DNS is a
//! distributed system, the first step of a query would be finding out where
//! exactly the RRset is stored. However, we are implementing a stub resolver
//! which is configured with a set of DNS servers that do this hunt for it.
//! The stub resolver simply asks those configured servers for the RRset and
//! if they all fail to find it, it fails too.
//!
//! Since DNS prefers to use the unreliable UDP as transport protocol, the
//! typical strategy is to ask the first server on the list and wait for a
//! bit. If no answer arrives, ask the second server and wait again. If all
//! servers have been asked and none has answered in due time, repeat the
//! process for a number of times and finally fail. Alternatives are to start
//! with a different server every time or to ask all servers at once.
//! Under some circumstances, the resolver can also fall back to using TCP
//! instead. Plus, there is an effort underway to encrypt the DNS connections.
//!
//! Which all is to say that a query may have to ask different servers for an
//! RRset, potentially using different transport protocols. For our own
//! purposes, we shall henceforth call the process of asking one specific
//! server over one specific transport protocol a *request.* 
//!
//! The *resolver,* finally, collects all information necessary to be able
//! to perform queries. It knows which servers to use with which protocols
//! and has additional configuration information that is used to perform
//! queries.
//!
//!
//! # A Resolver using Futures and Tokio
//!

