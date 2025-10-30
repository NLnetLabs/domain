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

## Syntax of an `.rpl` file


The replay format used by Stelline is a line based configuration. The format supports line comments starting with `;`.

The format contains two sections `CONFIG` and `SCENARIO`. The format of the `CONFIG` section depends on how Stelline is used (e.g. as a client or as a server). The `CONFIG` section extends from the start of the file until the line containing the `CONFIG_END` option.

The `SCENARIO` section contains the steps to perform in the test. It starts with `SCENARIO_BEGIN` and ends with `SCENARIO_END`. Note that all `.rpl` files must end with `SCENARIO_END`.

### Steps
A scenario consists of steps. Each step is something that is executed in the test. A step can be one of the following types:

- `QUERY`
- `CHECK_ANSWER`
- `TIME_PASSES`
- `TRAFFIC` (TODO)
- `CHECK_TEMP_FILE` (TODO)
- `ASSIGN` (TODO)

In general, the syntax looks like:

```rpl
STEP id type data
```

where `id` is a positive integer, `type` on of the step types mentioned above, and `data` is the data for the step.

Steps of types `QUERY` and `CHECK_ANSWER` have entries associated with them, which are textual representations of DNS messages. These entries are simply put aafter the `STEP` declaration.

A `QUERY` step queries a server process. It can optionally have data declaring its `ADDRESS` and `KEY`:

```rpl
STEP 1 QUERY
STEP 1 QUERY ADDRESS <ip_address> KEY <key_name>  
```

A `CHECK_ANSWER` step checks an incoming answer. It has no data, only entries.

```rpl
STEP 1 CHECK_ANSWER
```

A `TIME_PASSES` step increments the fake system clock by the specified number of seconds. The time is given after the `ELAPSE` token.

```rpl
STEP 1 TIME_PASSES ELAPSE
```

### Entries

An entry represents a DNS message (or an expected DNS message). It starts with `ENTRY_BEGIN` and ends with `ENTRY_END`. There are several parts to an entry, which depend on the use of the entry. The simplest form is the form used the `QUERY` step:

```rpl
ENTRY_BEGIN
REPLY <opcode> <rcode> <flags>
SECTION <section_type>
  ...
SECTION <section_type>
  ...
...
ENTRY_END
```

The `REPLY` part specifies the header information of the outgoing message. The supported values are:

 - RCODES: `NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED`, `YXDOMAIN`, `YXRRSET`, `NXRRSET`, `NOTAUTH`, `NOTZONE`, `BADVERS`, `BADCOOKIE`.
 - Flags: `AA`, `AD`, `CD`, `DO`, `QR`, `RA`, `RD`, `TC`, `NOTIFY`.

The `SECTION` directives specify which sections to fill with each section with. The content of a section is exactly like a zonefile, except for the question section, which does not require rdata.

There are two other sections in an entry, which are only relevant to ranges (see below), which are `MATCH` and `ADJUST`. The `MATCH` directive specifies which parts of the incoming message must match the reply to match the entry. The following values are allowed:

- `all`: same as `opcode qtype qname rcode flags answer authority additional`
- `opcode`
- `qname`
- `rcode`
- Flags: `AD`, `CD`, `DO`, `RD`, `flags`
- `question`: same as `qtype qname`
- Sections: `answer`, `authority`, `additional`
- `subdomain`
- `ttl`
- Protocol: `TCP`, `UDP`
- `server_cookie`
- `ednsdata`
- `MOCK_CLIENT`
- `CONNECTION_CLOSED`
- `EXTRA_PACKETS`
- `ANY_ANSWER`

The `ADJUST` directive specifies which parts of the incoming message should be changed before sending. The possible values are `copy_id` and `copy_query`.

### Ranges

Mock responses from are defined by a `RANGE`, which specifies the reponses that are given to a "range" of queries. A range is delimited by the `RANGE_BEGIN` and `RANGE_END` tokens.

The `RANGE_BEGIN` directive takes two positive integers: a start and end value. A `QUERY` step with an id within that range can match this range.

After the numeric range, a range has a list of addresses that match on this range, with each address on its own line prefixed with `ADDRESS`.

Lastly, a range contains a list of entries, following the syntax described above.

```rpl
RANGE_BEGIN 0 100 ; begin and end of the range
  ADDRESS 1.1.1.1 ; an address to match
  ADDRESS 2.2.2.2 ; a second address, any number of address is allowed

ENTRY_BEGIN
; ... 
ENTRY_END

; more entries may be added
RANGE_END
```
