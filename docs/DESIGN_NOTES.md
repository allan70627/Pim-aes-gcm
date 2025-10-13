# PIM AES‑GCM – Design Notes

_Last updated: {{today}}_

This document explains the RTL structure, interfaces, and end‑to‑end workflow for the **AES‑GCM** engine used in the PIM near‑storage project. It targets a minimal, synthesizable implementation that wraps the **secworks/aes** core and matches the agent’s security algorithm semantics.

---

## 1) High‑level goals

- **Exact algorithm match** to NIST SP 800‑38D and the project’s software agent:
  - 96‑bit IV fast‑path: `J0 = {IV, 0^31, 1}`
  - Payload encrypted via **AES‑CTR** (AES encryption primitive only)
  - GHASH over **AAD → CIPHERTEXT → lengths**; tag = `Y ⊕ AES_Enc(K, J0)`
  - 128‑bit authentication tag
- **Minimal hardware**: one shared AES core, small controller + datapath
- **Synth‑ready**: clean timing, no latches, AXI‑Stream‑like handshakes

---

## 2) Block diagram

```
                +----------------------------- Top (aes_gcm_top) -----------------------------+
Streams/CSRs -->|  Controller (aes_gcm_ctrl)      Datapath (aes_gcm_datapath)                |--> Streams/Status
                |   phases: AAD→PLD→LEN→TAG    +-------------------------+                    |
                |                                |  secworks aes_core     |<-- key,key_we ---- |
                |   +------------------------+   +-------------------------+                    |
                |   |  gcm_lenblock         |          ^       ^     ^                        |
 aad_* -------->|-->|                        |          |       |     |                        |
                |   +------------------------+          |       |     |                        |
                |                                       |       |     |                        |
 din_* --+----> ctr_xor <---- keystream (CTR) <---------+       |     |                        |
         |            \                                  \      |     |                        |
         |             \--> ciphertext ------------------> GHASH(Y)    |                        |
         |                                                         \    |                        |
         |                                                          +-- gcm_tagmask (AES(J0))   |
         |                                                                                      |
         +--------------------------------------------------------------------------------------+
```

**Shared AES usage** (one instance in datapath):
1. `H = AES_Enc(K, 0^128)` once per key (h_subkey)
2. `S_i = AES_Enc(K, J0+i)` for CTR keystream (payload)
3. `mask = AES_Enc(K, J0)` once per message (tagmask)

---

## 3) Files and responsibilities

### Top & orchestration
- **`rtl/aes_gcm_top.v`** – Chip‑facing wrapper. Exposes CSRs and streams; instantiates controller + datapath.
- **`rtl/aes_gcm_ctrl.v`** – FSM sequencing the phases:
  - `IDLE → ABSORB_AAD → PROCESS_PAYLOAD → LENS → TAG → DONE`
  - Drives GHASH init; routes AAD; supervises CTR XOR; injects length block; requests tagmask; XORs `tag_pre_xor` with `tagmask`; compares tag in DEC; raises `auth_fail`.
- **`rtl/aes_gcm_datapath.v`** – Crypto plumbing + shared AES arbiter:
  - Holds **one** `aes_core` and a tiny arbiter for **H / CTR / tagmask**
  - Provides keystream to `ctr_xor`, feeds **ciphertext** to GHASH, and exposes `tag_pre_xor` + `tagmask` to the controller

### AES helpers
- **`rtl/ctr_gen.v`** – Forms `J0` from 96‑bit IV and emits counters `J0+1, J0+2, …` (increment low 32b)
- **`rtl/h_subkey.v`** – Tracks `key_we` and requests a single AES run on `0^128`; latches `H` and pulses `H_valid`
- **`rtl/gcm_tagmask.v`** – Builds `J0`; requests a single AES run on `J0`; outputs `mask` and `mask_valid`
- **`rtl/ctr_xor.v`** – Streams `S_i ⊕ data` (ENC: `C=P⊕S`; DEC: `P=C⊕S`); consumes/requests keystream words; honors `*_keep` on final beat

### GHASH path
- **`rtl/gf128_mul.v`** – Carry‑less 128×128 multiply (GF(2)) → 256‑bit product
- **`rtl/gf128_reduce.v`** – Reduce mod `x^128 + x^7 + x^2 + x + 1` → 128‑bit result
- **`rtl/ghash_core.v`** – Streaming accumulator: `Y ← (Y ⊕ X)·H mod poly` over AAD, CIPHERTEXT, and lengths; outputs `Y` (`tag_pre_xor`)
- **`rtl/gcm_lenblock.v`** – Combinational packer `{len(AAD)_bits, len(C)_bits}` (both 64b, big‑endian)

### Third‑party core
- **`rtl/third_party/secworks_aes/*`** – _secworks/aes_ encryption core (iterative). Used for all AES calls (Enc only).

### Synthesis
- **`syn/dc_compile_gcm.tcl`** – DC 2016.03 script to read all RTL (inc. secworks), constrain, compile, and report PPA

---

## 4) Interfaces

### Streams (AXI‑Stream‑like, 128‑bit)
- **AAD in:** `aad_valid,aad_ready,aad_last,aad_data[127:0],aad_keep[15:0]`
- **Payload in:** `din_valid,din_ready,din_last,din_data[127:0],din_keep[15:0]`
- **Payload out:** `dout_valid,dout_ready,dout_last,dout_data[127:0],dout_keep[15:0]`
- **Handshake rule:** transfer when `valid && ready` is `1`. On the final beat, only bytes with `keep=1` are meaningful.

### Control/status (CSRs/wires)
- Key/IV & lengths: `key_in[255:0], key_we, aes256_en, iv_in[95:0], iv_we, len_aad_bits[63:0], len_pld_bits[63:0]`
- Mode & start: `start, enc_mode` (1=ENC, 0=DEC), `framed_mode` (optional)
- Tag I/O: `tag_in[127:0], tag_in_we` (DEC), `tag_out[127:0], tag_out_valid` (ENC)
- Error: `auth_fail`

---

## 5) Exact algorithm (ENC/DEC)

**Common setup**
1) On `key_we`: compute **H = AES_Enc(K, 0^128)** (once per key)
2) On `iv_we`: set **J0 = {IV, 0^31, 1}**; first CTR block is `J0+1`

**Encrypt (enc_mode=1)**
1) GHASH all **AAD** blocks
2) For each payload block `i`:
   - Keystream: `S_i = AES_Enc(K, J0+i)`
   - Ciphertext: `C_i = P_i ⊕ S_i`
   - GHASH **ciphertext** `C_i`
3) GHASH the **lengths block** `{len(AAD)_bits, len(C)_bits}`
4) Compute `mask = AES_Enc(K, J0)` and **tag = Y ⊕ mask**; present `tag_out`

**Decrypt (enc_mode=0)**
1) GHASH **AAD**
2) For each payload block `i`:
   - Keystream: `S_i = AES_Enc(K, J0+i)`
   - Plaintext: `P_i = C_i ⊕ S_i`
   - GHASH **ciphertext** `C_i`
3) GHASH lengths; compute `tag' = Y ⊕ AES_Enc(K, J0)`
4) Compare to `tag_in`; if mismatch → `auth_fail=1`

> In both ENC & DEC, GHASH consumes **ciphertext**. The lengths block uses **bit lengths**, 64 bits each, **big‑endian**.

---

## 6) AES sharing policy (single core)

Arbiter order and constraints:
- **H‑subkey** runs immediately after `key_we`, before any message work
- **CTR** has priority during `PROCESS_PAYLOAD` to sustain streaming
- **Tagmask** runs only in the `TAG` phase
- Back‑pressure: if CTR stalls, datapath throttles the payload stream via `din_ready`

---

## 7) Reset/clocking & coding guidelines

- Synchronous design, active‑low `rst_n`
- Add `` `default_nettype none `` to all RTL, restore with `` `default_nettype wire `` at EOF
- No `$display/$finish` in synthesizable code
- Register stream boundaries; avoid long combinational chains (especially XOR trees)

---

## 8) Testing plan (no DC required)

**Unit tests**
- `ctr_gen`: IV→expect counters ending in `...00000002, 03, 04`
- `h_subkey`: key write→expect single `H_valid` pulse
- `ghash_core`: sanity checks – `H=0 ⇒ Y=0`; `H=1 ⇒ Y = XOR(all blocks)`

**End‑to‑end**
- Use one 96‑bit IV NIST vector (no AAD first): check ENC `CT` & `TAG`; DEC recovers `PT` and `auth_fail==0`
- Add AAD case (non‑multiple of 16B) to validate `keep`/padding

(Optional) dump VCD/SAIF for realistic power later.

---

## 9) Synthesis (when DC is available)

- Script: `syn/dc_compile_gcm.tcl` (L‑2016.03)
- Read all RTL + `secworks_aes/src/rtl/*.v`; set clock (e.g., 2.5 ns)
- `compile_ultra`; `report_timing/area/power`
- Vectorless power first, then activity‑based via SAIF from the end‑to‑end sim

---

## 10) TODO checklist

- [ ] Ensure only **one** `aes_core` instance (in datapath)
- [ ] Verify GHASH lengths block endianness and bit counts
- [ ] Confirm ciphertext is GHASHed in both ENC & DEC
- [ ] Add `` `default_nettype none `` and fix any undeclared wires
- [ ] Run unit tests (ctr_gen, h_subkey, ghash)
- [ ] Run one end‑to‑end NIST vector (no AAD), then with AAD
- [ ] (Optional) Implement framed mode (IV|C|TAG) if required by the agent
- [ ] SAIF‑based power report once DC is available

---

## 11) Interfaces (concise reference)

```
// AAD in
input  aad_valid, aad_last; output aad_ready;
input  [127:0] aad_data; input [15:0] aad_keep;

// Payload in/out
input  din_valid, din_last; output din_ready;
input  [127:0] din_data;   input [15:0] din_keep;
output dout_valid, dout_last; input  dout_ready;
output [127:0] dout_data;  output [15:0] dout_keep;

// CSRs / control
input  [255:0] key_in; input key_we; input aes256_en;
input  [95:0]  iv_in;  input iv_we;
input  [63:0]  len_aad_bits, len_pld_bits;
input  start, enc_mode, framed_mode;
input  [127:0] tag_in; input tag_in_we;
output [127:0] tag_out; output tag_out_valid;
output auth_fail;
```

---

## 12) Notes on matching the software agent

- IV is a **96‑bit nonce** provided by the agent (nonce discipline); hardware uses the fast path exclusively
- AAD is **opaque bytes** supplied by the agent (e.g., capability header); authenticated but not encrypted
- Tag length fixed to **128 bits**
- Decrypt path still uses AES encryption on counters; no inverse rounds needed

---

## 13) References

- NIST SP 800‑38D: Galois/Counter Mode (GCM) and GMAC
- secworks/aes: https://github.com/secworks/aes
- Project PIM agent sources (security algorithm framing)

