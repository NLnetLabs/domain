# Stelline

Stelline is a test runner based around DNS message request/response sequences defined in a human readable text file format.

## Etymology and origins

The Stelline replay file format is a variant of the `.rpl` format used by the [Unbound](https://www.unbound.net/) test tool "testbound", which was itself based on [ldns-testns](https://nlnetlabs.nl/projects/ldns/about/).

The name Stelline derives from Dr Ana Stelline, a descendant of Deckard, where Deckard is both a reference to Rick Deckard in the movie Blade Runner 2049 and to the [CZ-NIC Deckard](https://github.com/CZ-NIC/deckard) project which was [_"heavily inspired by testbound"_](https://lists.nlnetlabs.nl/pipermail/unbound-users/2017-March/004699.html). Coincidentally Dr Ana Stelline is a machine (a "replicant") who creates false memories while the test cases run by Stelline can also be seen as false memories being replayed by a machine.

## Capabilities

Stelline is capable of exercising both the client and server code provided by the `domain` crate.

Stelline is unaware of whether the clients and servers in use are mock or real, this is determined by the clients, servers & mock connections created by the test setup code on a per test basis.

In both cases real `net::client` instances handle interaction with the server.

When using a mock server the replay file should define both test requests and test responses and the mock server replies with the test responses.

When using a real server the replay file defines DNS requests and server configuration and real `net::server` instances reply based on their configuration.
