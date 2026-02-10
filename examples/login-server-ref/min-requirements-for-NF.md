# Minimum Requirements for an NF implementation:

Architecture decisions
-----------------------
Decouple networking and processing logic into platform file and linking file respectively.
To support multiple connections, enable asynchronous message-handling.
- For improved throughput, enable multithreaded message handling.
Single threaded, sequential --> multithreaded, sequential, single threaded, asynchronous --> multithreaded, asynchronous

a. Decide the dependencies required to implement networking logic. `platform.cpp`
A networking platform file requires:
1. primitives to read/write a socket. -> unix sockets api.

2. Ability to support multiple interfaces at a single NF, with possibly unique transport protocols <define the interfaces>

3.  For stream sockets, ability to extract bitstring of arbitrary message-types from the socket recv buffer. (Current platform file expects only HTTP message.)
The platform file needs to be able to extract bitstrings for custom application protocols as well.

4. The application-layer protocol being used must provide a mechanism (via a library) to create, encode and decode supported message-types.
Eg: http protocol is well-defined, however individual implementations may differ.

5. Platform file must be able to track and trigger timer callbacks when appropriate.

6. A structure to reperesent server state (In current platform -> struct nfvInst).

7. Running a single, *independent* server instance per user thread.
Platform file will need to be modified to store state of multiple NF instances.\

8. A NF instance is defined in terms of its interfaces. Each NF interface will be associated with a socket bound to a well-known port.
- As connections are made

9. A per-connection data structure that stores recv data, etc.
- User-level state maintained at server.


- modification to 