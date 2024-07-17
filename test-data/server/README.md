# Stelline server tests

The test recipes defined in this directory follow a common pattern, each
involving two or three parties that communicate via mock network sockets:

  1. A real in-memory server to be tested.
     The behaviour of the server is controlled by the `config:` block that
     preceeds the `CONFIG_END` directive.

     This server is powered by actual running domain server code, not
     test/mock code.

     This server has no network address at which it listens as such, instead
     client requests are delivered via a mock network socket to which the
     server is directly connected.

  2. Real clients querying the server under test.
     The behaviour of these clients is controlled by pairs of `STEP`
     directives: `QUERY` then `CHECK_ANSWER`.

     These clients are powered by actual running domain client code, not
     test/mock code.

     From the perspective of the server the clients appear to send requests
     from 127.0.0.1 unless otherwise specified via
     `STEP <N> QUERY ADDRESS <IP>`.

  3. **[Optional]** Mock servers for use with the above clients & server.
     These servers do not actually exist, they are just a set of mock replies
     which the Stelline test framework will provide as responses to matching
     queries (from either the clients or the server under test).
     
     Queries are matched by both step number (only steps in the defined range
     can match) and by properties of the DNS query.

# Known limitations

- The `QUERY` step only sets expectations, the actual sending of the query, the
  receiving and checking of the answer all happen in the `CHECK_ANSWER` step.

- The first use of a particular client IP address (or the default if none is
  specified via `ADDRESS`) will determine the configuration of that client. If
  two different steps define a different configuration for the same client,
  e.g. a latter step specifying that requests should be signed using a
  particular TSIG key, the former step will determine that the client sends
  unsigned requests and the latter TSIG key specification will be ignored.

- By default server responses are expected consist of only a single reply. The
  `EXTRA_PACKET` directive can be used to denote that a subsequent reply should
  also be expected. The `EXTRA_PACKET` directive can be used more than once.
  The number of replies must exactly match the number of expected replies. To
  make it possible to define which RRs will appear in which reply, when running
  these tests the server will order zone contents in memory, while there is
  usually no such ordering guarantee.

- Specifying a TSIG key via `STEP <N> QUERY KEY <KEYNAME>` will cause the real
  TSIG client code to TSIG sign the request, and to strip out the TSIG signing
  in the reply before the comparison is made with the expected reply contents
  as definedby the `SECTION` blocks of a `CHECK_ANSWER` step. As such the
  actual effects of TSIG signing are not visible nor explicitly tested for in
  test steps that use `KEY <KEYNAME>`.