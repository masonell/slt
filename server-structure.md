# Server Architecture

## Front Doors

### UDP Front Door
- Owns UDP socket bound to port 443 (all reads happen here)
- Enforces UDP classification:
  - Drop non-QUIC-format datagrams
  - Long header → forward to nginx (NAT forwarder path)
  - Short header → lookup DCID in `cid_map`; claim if present, else forward to nginx
- Owns `Arc<RwLock<CidMap>>` for connection ID tracking
- Owns LRU + idle timeout map for NAT peer 4-tuples
- Spawns a task per NAT mapping to proxy responses from nginx back to the client
- Passes claimed UDP-QSP packets to the owning `ClientSession`

### TCP Front Door
- Owns TCP listener on port 443
- On accept: spawns a new task
- Task performs client detection via TLS ClientHello inspection
- Non-clients: proxied to nginx upstream
- Clients: socket passed to `AuthHandler`

## VPN

### AuthHandler (Intermediary State)
- Performs TLS termination
- Executes Auth/AuthOk handshake
- Checks if `client_id` already exists (reconnecting client?)
- On success: creates `ClientSession` with assigned IP + optional previous session
- On failure: closes connection

### ClientSession
- Owns client connection (socket/stream, crypto keys, assigned IP)
- Receives optional previous session (if reconnecting); decides whether to take over or reject
- Enforces one active data path per `client_id` (new auth takes over)
- Routes traffic bidirectionally between client and TUN
- Maintains ping/pong for liveness
- Owns activity timer with timeout (self-destructs on expiry)
- Owns active transport state and verify-before-switch (UDP-QSP PING/PONG)
- Handles `REGISTER_CID` and updates `cid_map` (with explicit ack before UDP-QSP is accepted)
- Has channel sender for TUN → client traffic
- Has channel receiver for client → TUN traffic
- Drops outbound packets when per-client queue is full (do not block TUN reader)
- Registers itself in shared maps on creation, deregisters on drop

### TUN
- Owns TUN device
- Owns `ip -> ClientSession` channel map for routing outbound packets
- Reads from TUN, forwards packets to appropriate `ClientSession`
- Owns receiver channel, writes inbound packets to TUN
- Uses a dedicated writer task for TUN writes (single mutable writer)
- Validates source IPs (anti-spoofing)
