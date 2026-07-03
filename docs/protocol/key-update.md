# Key Phase and Rekeying

UDP-QSP uses in-band key updates to periodically rotate encryption keys without
requiring a new `REGISTER_CID` exchange. Key updates are signaled via the key phase
bit in the QUIC short header and both endpoints derive new keys locally using HKDF.

## 1. Overview

Key updates serve several purposes:

- Limit the amount of data encrypted under any single key (cryptographic hygiene)
- Provide forward secrecy within a session
- Maintain traffic flow without control-plane intervention

Key characteristics:

- **In-band signaling**: No explicit rekey messages; the key phase bit signals transitions
- **Unidirectional independence**: TX and RX directions rekey independently
- **Local derivation**: Both endpoints derive new keys from current keys using HKDF
- **No REGISTER_CID retransmit**: Periodic rekeying does not involve the control plane

## 2. Key Phase Bit

### Location

The key phase bit is bit 2 of the first byte in the QUIC short header:

```
Bit 7: Header Form (0 for short header)
Bit 6: Fixed Bit (1)
Bit 5: Spin Bit (unused)
Bits 4-3: Reserved (0)
Bit 2: Key Phase        <-- This bit
Bits 1-0: PN Length minus 1
```

### Meaning

| Key Phase | Meaning |
|-----------|---------|
| 0 | Initial keys (from `REGISTER_CID`) or even-numbered key generation |
| 1 | First rekey or odd-numbered key generation |

The key phase bit toggles between 0 and 1 with each key rotation. The bit is protected
by header protection, so observers cannot directly see when a key transition occurs.

### Initial Value

The initial key phase value comes from `REGISTER_CID`:

```
offset size field
...    1    key_phase (0 or 1)
```

Both endpoints start with the same key phase value. In typical operation this is 0,
but non-zero initial values are supported for session resumption scenarios.

## 3. Rekey Interval

### When Rekey Happens

Key rotation occurs when the packet number crosses a multiple of `KEY_UPDATE_INTERVAL`:

| Constant | Value | Source |
|----------|-------|--------|
| `KEY_UPDATE_INTERVAL` | 2^21 (2,097,152) | `slt-core/src/crypto/udp_qsp/session.rs` |

```rust
pub const KEY_UPDATE_INTERVAL: u64 = 1 << 21;
```

Example timeline:
- Packets 0 through 2,097,151: Key phase 0
- Packets 2,097,152 through 4,194,303: Key phase 1
- Packets 4,194,304 through 6,291,455: Key phase 0
- And so on...

### Why This Interval

The rekey interval is chosen to be much larger than the replay window:

| Constant | Value | Ratio |
|----------|-------|-------|
| `PN_REPLAY_WINDOW` | 1024 | - |
| `KEY_UPDATE_INTERVAL` | 2,097,152 | ~2048x larger |

This large margin ensures:

1. **Replay window containment**: All packets from the previous key phase are outside
   the replay window before the next rekey, eliminating ambiguity about which keys to use
2. **Reordering tolerance**: Network reordering within the replay window never crosses
   a key phase boundary
3. **Implementation simplicity**: No complex key phase tracking for replayed packets

## 4. HKDF Key Derivation

New keys are derived from current keys using HKDF-SHA256. The derivation is deterministic,
so both endpoints compute identical next-generation keys. Output lengths follow the active
cipher suite: AES-128-GCM derives 16-byte HP and AEAD keys, ChaCha20-Poly1305 derives
32-byte HP and AEAD keys; both derive a 12-byte IV.

### Per-Suite Sizes

| Suite | HP key | AEAD key | IV | IKM (`hp || aead || iv`) |
|-------|-------:|---------:|---:|-------------------------:|
| AES-128-GCM        | 16 | 16 | 12 | 44 bytes |
| ChaCha20-Poly1305  | 32 | 32 | 12 | 76 bytes |

### Context Strings and Labels

From `slt-core/src/crypto/udp_qsp/keys.rs`:

```rust
const KEY_UPDATE_CONTEXT: &[u8] = b"slt-udp-qsp/key-update-v1";
const KEY_UPDATE_HP_INFO: &[u8] = b"slt-udp-qsp/key-update-v1/hp";
const KEY_UPDATE_AEAD_INFO: &[u8] = b"slt-udp-qsp/key-update-v1/aead";
const KEY_UPDATE_IV_INFO: &[u8] = b"slt-udp-qsp/key-update-v1/iv";
```

### Derivation Process

**Step 1: Assemble input key material (IKM)**

Concatenate current directional keys:

```rust
ikm = hp_key || aead_key || iv
// Length: hp_len + aead_len + 12
//   AES-128-GCM:       16 + 16 + 12 = 44 bytes
//   ChaCha20-Poly1305: 32 + 32 + 12 = 76 bytes
```

**Step 2: HKDF-Extract**

```rust
extract_input = KEY_UPDATE_CONTEXT || ikm
prk = HMAC-SHA256(current_iv, extract_input)
```

The current IV is used as the salt. The output PRK is 32 bytes.

**Step 3: HKDF-Expand**

Derive each new key component with its specific info label, expanding to the active
suite's lengths:

```rust
new_hp_key   = HKDF-Expand-SHA256(prk, KEY_UPDATE_HP_INFO,   hp_len)   // 16 or 32
new_aead_key = HKDF-Expand-SHA256(prk, KEY_UPDATE_AEAD_INFO, aead_len) // 16 or 32
new_iv       = HKDF-Expand-SHA256(prk, KEY_UPDATE_IV_INFO,   12)
```

### What Gets Rotated

Each directional rekey rotates all three key components:

| Component | AES-128-GCM | ChaCha20-Poly1305 | Purpose |
|-----------|------------:|------------------:|---------|
| HP key | 16 bytes | 32 bytes | Header protection (AES-128-ECB / ChaCha20) |
| AEAD key | 16 bytes | 32 bytes | Payload encryption (AES-128-GCM / ChaCha20-Poly1305) |
| IV | 12 bytes | 12 bytes | Nonce construction |

TX and RX directions rekey independently. When the TX direction rotates, the RX keys
remain unchanged, and vice versa.

### Implementation

From `derive_direction_keys` in `keys.rs`:

```rust
fn derive_direction_keys(
    current: &DirectionKeys,
    config: CipherConfig,
) -> Result<DirectionKeys, QspCryptoError> {
    // Assemble IKM with suite-specific lengths
    let mut ikm = Vec::with_capacity(config.hp_key_len() + config.aead_key_len() + config.iv_len());
    ikm.extend_from_slice(current.hp.key_material());
    ikm.extend_from_slice(&current.aead.key);
    ikm.extend_from_slice(&current.aead.iv);

    // Extract
    let mut extract_input = Vec::with_capacity(KEY_UPDATE_CONTEXT.len() + ikm.len());
    extract_input.extend_from_slice(KEY_UPDATE_CONTEXT);
    extract_input.extend_from_slice(&ikm);
    let prk = hkdf_extract_sha256(&current.aead.iv, &extract_input)?;

    // Expand to suite-specific lengths
    let next_iv = hkdf_expand_sha256_vec(&prk, KEY_UPDATE_IV_INFO, config.iv_len())?;
    Ok(DirectionKeys {
        hp: HeaderProtectionKey::new(
            config.hp,
            &hkdf_expand_sha256_vec(&prk, KEY_UPDATE_HP_INFO, config.hp_key_len())?,
        )?,
        aead: PacketKey::new(
            &hkdf_expand_sha256_vec(&prk, KEY_UPDATE_AEAD_INFO, config.aead_key_len())?,
            &next_iv,
            config.aead,
        )?,
    })
}
```

## 5. Sender Behavior

### Detecting Threshold Crossing

Before sending each packet, the sender checks if the packet number has reached
or crossed a rekey threshold:

```rust
fn maybe_rotate_tx_keys(&mut self, pn: u64) -> Result<(), QspSessionError> {
    while let Some(threshold) = self.tx_next_rekey_pn {
        if pn < threshold {
            break;
        }

        // Perform rotation
        self.keys = self.keys.with_next_tx_keys()?;
        self.tx_key_phase = !self.tx_key_phase;
        self.tx_next_rekey_pn = next_rekey_after(threshold, self.rekey_policy.interval);
    }
    Ok(())
}
```

The threshold calculation:

```rust
const fn next_rekey_after(pn: u64, interval: u64) -> Option<u64> {
    if interval == 0 {
        return None;
    }

    let rem = pn % interval;
    let step = if rem == 0 { interval } else { interval - rem };
    pn.checked_add(step)
}
```

### Deriving New Keys

When a threshold is crossed, the sender:

1. Calls `with_next_tx_keys()` to derive new TX keys
2. Flips `tx_key_phase` (0 -> 1 or 1 -> 0)
3. Computes the next threshold

### Flipping Key Phase Bit

The key phase bit in outgoing packets reflects the current `tx_key_phase`:

```rust
self.keys.protect_into(
    self.dcid.as_slice(),
    pn,
    self.tx_key_phase,  // <-- Current key phase
    payload,
    &mut self.send_buf,
)?;
```

### No Explicit Rekey ACK

There is no acknowledgment message for key updates. The sender simply:

1. Rotates keys at the threshold
2. Continues sending with the new key phase

The receiver detects the key phase change implicitly when it successfully decrypts
a packet with a different key phase bit.

## 6. Receiver Behavior

The receiver maintains multiple key states to handle packet reordering and
detect key phase transitions.

### Key State Tracking

```rust
struct QuicQspSession<I> {
    // ...
    keys: UdpQspKeys,              // Current RX keys
    rx_key_phase: bool,            // Current RX key phase
    rx_next_rekey_pn: Option<u64>, // Expected rekey threshold
    previous_rx: Option<PreviousRxKeys>, // Prior key phase
    // ...
}

struct PreviousRxKeys {
    keys: UdpQspKeys,
    valid_until_pn: u64,  // Expiration boundary
}
```

### Decryption Attempt Order

On receiving a packet, the receiver tries decryption in this order:

**1. Try current keys first**

```rust
let current_opened = self.keys
    .open_into(self.scid.len(), packet, expected_pn, &mut self.recv_buf)
    .ok()
    .map(|opened| (opened.pn, opened.pn_len, opened.key_phase));

if let Some((pn, pn_len, key_phase)) = current_opened
    && key_phase == self.rx_key_phase
{
    return self.accept_opened(pn, pn_len, key_phase);
}
```

If the packet decrypts successfully and the key phase matches, accept immediately.

**2. Try previous keys within grace window**

```rust
if self.can_try_previous(expected_pn)
    && let Some(previous) = &self.previous_rx
    && let Some((pn, pn_len, key_phase)) = previous.keys
        .open_into(self.scid.len(), packet, expected_pn, &mut self.recv_buf)
        .ok()
        .map(|opened| (opened.pn, opened.pn_len, opened.key_phase))
    && key_phase != self.rx_key_phase
{
    return self.accept_opened(pn, pn_len, key_phase);
}
```

Previous keys are only tried if:
- They exist (a rekey has occurred)
- The expected PN is within the grace window
- The decrypted key phase differs from current

**3. Try candidate keys near rekey threshold**

```rust
if self.should_try_candidate(expected_pn)
    && let Some(candidate_keys) = self.derive_candidate_rx_keys()?
    && let Some((pn, pn_len, key_phase)) = candidate_keys
        .open_into(self.scid.len(), packet, expected_pn, &mut self.recv_buf)
        .ok()
        .map(|opened| (opened.pn, opened.pn_len, opened.key_phase))
    && key_phase != self.rx_key_phase
{
    self.promote_candidate_rx_keys(candidate_keys);
    return self.accept_opened(pn, pn_len, key_phase);
}
```

Candidate keys are derived on-demand when:
- No previous keys exist (not already mid-transition)
- The expected PN is near the rekey threshold

### Candidate Key Derivation

```rust
fn derive_candidate_rx_keys(&self) -> Result<Option<UdpQspKeys>, QspSessionError> {
    if self.rx_next_rekey_pn.is_none() {
        return Ok(None);
    }
    Ok(Some(self.keys.with_next_rx_keys()?))
}
```

### Key Promotion on Success

When candidate keys successfully decrypt a packet:

```rust
fn promote_candidate_rx_keys(&mut self, candidate: UdpQspKeys) {
    let threshold = self.rx_next_rekey_pn
        .unwrap_or_else(|| self.replay_window.expected_pn());
    let valid_until = threshold.saturating_add(PN_REPLAY_WINDOW as u64);

    // Save current keys as previous
    self.previous_rx = Some(PreviousRxKeys {
        keys: self.keys.clone(),
        valid_until_pn: valid_until,
    });

    // Promote candidate to current
    self.keys = candidate;
    self.rx_key_phase = !self.rx_key_phase;
    self.rx_next_rekey_pn = next_rekey_after(threshold, self.rekey_policy.interval);
}
```

### Previous Key Expiration

Previous keys are discarded when the expected packet number exceeds the
validity window:

```rust
fn maybe_confirm_previous_rx_keys(&mut self, expected_pn: u64) {
    if self.previous_rx
        .as_ref()
        .is_some_and(|prev| expected_pn > prev.valid_until_pn)
    {
        self.previous_rx = None;
    }
}
```

## 7. Rekey Windows

### Late Margin

The late margin defines how far past the rekey threshold the receiver will
attempt candidate key derivation:

| Constant | Value | Source |
|----------|-------|--------|
| `KEY_UPDATE_LATE_MARGIN` | 8,192 (8 * `PN_REPLAY_WINDOW`) | `slt-core/src/crypto/udp_qsp/session.rs` |

```rust
pub const KEY_UPDATE_LATE_MARGIN: u64 = (PN_REPLAY_WINDOW as u64) * 8;
```

### When to Try Candidate Keys

```rust
const fn should_try_candidate(&self, expected_pn: u64) -> bool {
    if self.previous_rx.is_some() {
        return false;  // Already mid-transition
    }
    let Some(threshold) = self.rx_next_rekey_pn else {
        return false;  // No rekey scheduled
    };
    pn_distance(expected_pn, threshold) <= self.rekey_policy.late_margin
}
```

The candidate window is centered on the expected rekey threshold. Packets within
`late_margin` of the threshold trigger candidate key derivation.

### Grace Window for Previous Keys

Previous keys remain valid for one replay window after the rekey threshold:

```rust
let valid_until = threshold.saturating_add(PN_REPLAY_WINDOW as u64);
```

This handles reordering where packets from the old key phase arrive after
the transition.

### Dead Channel Detection

When consecutive decryption failures exceed a threshold, the channel is
declared dead:

| Constant | Value | Source |
|----------|-------|--------|
| `DEAD_CHANNEL_FAILURE_THRESHOLD` | 64 | `slt-core/src/crypto/udp_qsp/session.rs` |

```rust
self.consecutive_decrypt_failures = self.consecutive_decrypt_failures.saturating_add(1);
if self.consecutive_decrypt_failures >= self.rekey_policy.dead_failures {
    return Err(QspSessionError::DeadChannel);
}
```

The counter resets to 0 on any successful decryption.

## 8. Key Update Invariants

### One Update in Flight per Direction

At most one key update may be in progress per direction at any time:

- After a sender rotates TX keys, it must not rotate again until receiving
  packets with the new key phase
- After a receiver promotes RX keys, it discards the previous keys and
  cannot accept a second concurrent transition

This invariant is enforced by:
- Checking `previous_rx.is_none()` before trying candidate keys
- Discarding previous keys after the grace window expires

### No Packet Number Wrapping

Packet numbers are u64 values that must not wrap:

```rust
self.next_pn = pn
    .checked_add(1)
    .ok_or(QspSessionError::PacketNumberOverflow)?;
```

If `next_pn` would overflow u64::MAX, the session must be replaced rather than
continuing. This ensures:

- Nonce uniqueness (each packet has a unique PN)
- No ambiguity in key phase (the key phase bit alone suffices)

### Key Phase Bit Uniqueness

Within any single key generation, all packets have the same key phase bit value.
The bit only changes when keys rotate. Combined with the no-wrapping invariant,
a receiver can always determine the correct key generation from:
1. The packet's key phase bit
2. The expected packet number
3. The proximity to known rekey thresholds

### Directional Independence

TX and RX directions rekey independently:

- A sender may rotate TX keys while still receiving on old RX keys
- The two directions may have different key phases at the same time
- Key derivation for one direction does not affect the other

This allows asymmetric rekey timing based on actual traffic patterns in each direction.
