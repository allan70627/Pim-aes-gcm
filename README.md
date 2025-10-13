# Pim-AES-GCM (RTL)

## What this project is
A synthesizable **AES-GCM** engine in Verilog. It performs authenticated encryption (AEAD) following **NIST SP 800-38D**: plaintext is encrypted using AES in **CTR** mode while a **GHASH** authenticator (over GF(2¹²⁸)) accumulates AAD and ciphertext to produce a 128-bit tag.

The design shares a single AES core (from the **secworks/aes** project) between:
- **H subkey derivation** (encrypting 0 with the key to get GHASH subkey `H`)
- **J0/CTR keystream generation** for payload encryption/decryption

### High-level data flow
1. **Key/IV program** → derive `H`, build `J0` (96-bit IV fast path).
2. **AAD path** → GHASH accumulates AAD blocks.
3. **Payload path** → CTR keystream ⊕ plaintext = ciphertext; GHASH accumulates ciphertext (encrypt) or plaintext (decrypt), per GCM spec.
4. **Len block** → GHASH finalization uses the 128-bit length block (`len_aad || len_payload`).
5. **Tag** → Compute `S = GHASH(...)`, then `Tag = E_K(J0) ⊕ S`.

---

## Repository layout (what each file does)


### Top-level & control

- **`aes_gcm_top.v`**  
  The **integration wrapper**. Exposes the streaming interfaces (AAD/payload in, payload out), CSR-like programming ports (key, IV, length fields, start, mode), and outputs (`tag_out`, `tag_out_valid`, and optionally `auth_fail` if your top supports verify). Internally wires the control FSM, datapath, CTR generator, GHASH, and the secworks AES core.

- **`aes_gcm_ctrl.v`**  
  The **control state machine**. Sequences the mode (encrypt/decrypt), key/IV programming, when to accept AAD vs. payload, when to finalize GHASH (length block), and when to assert `tag_out_valid`. It also coordinates backpressure with the ready/valid streams.

- **`aes_gcm_datapath.v`**  
  The **data mover**. Routes blocks between:
  - AES (for keystream and subkey generation),
  - XOR stage (CTR ⊕ data),
  - GHASH path (accumulate AAD + ciphertext/plaintext),
  - length block finalization and tag post-processing.
  Handles partial last blocks using `*_keep` (bit-per-byte).

### CTR (counter) path

- **`ctr_gen.v`**  
  Builds **J0** from a 96-bit IV (fast path) or general IV if supported, initializes and increments the **counter block** per GCM (big-endian 32-bit counter in the low word). Issues counter blocks to AES for keystream.

- **`ctr_xor.v`**  
  XORs the 128-bit keystream with the payload lane. Deals with `keep` masks for partial final beats.

### GHASH / GF(2¹²⁸)

- **`ghash_core.v`**  
  Implements the polynomial hash over GF(2¹²⁸). It takes input blocks (AAD first, then ciphertext for ENC / plaintext for DEC), multiplies with `H`, and accumulates the running hash `X` (S in the spec). Provides the final GHASH value used to compute the tag.

- **`gf128_mul.v`**  
  **Carry-less multiply** in GF(2¹²⁸). Multiplies `X` by `H` (or vice-versa) before reduction.

- **`gf128_reduce.v`**  
  Reduces the 256-bit intermediate product back into the **GF(2¹²⁸)** field using the GCM irreducible polynomial.

### GCM utilities

- **`gcm_lenblock.v`**  
  Forms the **128-bit length block** = (`len(AAD)` || `len(PLD)`) in **bits**, as required by the spec, and injects it into GHASH during finalization.

- **`gcm_tagmask.v`**  
  Post-processing for the final **tag**. XORs **E_K(J0)** with the final GHASH value to produce the 128-bit authentication tag. Optionally masks/tag-pads if your integration requires it.

- **`h_subkey.v`**  
  Derives the **hash subkey H** by encrypting the all-zero block with the configured AES key: `H = E_K(0¹²⁸)`. Feeds H to `ghash_core`.

### Third-party AES core

- **`third_party/secworks_aes/src/rtl/*.v`**  
  The **secworks AES** implementation (AES-128/256). Used for both:
  - `E_K(0)` (H subkey derivation),
  - `E_K(counter)` (CTR keystream).

> The SECWORKS core is kept as a subdirectory; consult its own README/license for details.

---

## Interfaces (at a glance)

- **Clock/Reset**  
  `clk`, active-low `rst_n`.

- **Programming / Control**  
  - `key_in[255:0]`, `key_we`, `aes256_en`  
  - `iv_in[95:0]`, `iv_we`  
  - `len_aad_bits[63:0]`, `len_pld_bits[63:0]`  
  - `start` (pulse to start a transaction), `enc_mode` (1=encrypt, 0=decrypt)

- **AAD Stream (input)**  
  `aad_valid/aad_ready`, `aad_data[127:0]`, `aad_keep[15:0]`, `aad_last`

- **Payload Stream (input)**  
  `din_valid/din_ready`, `din_data[127:0]`, `din_keep[15:0]`, `din_last`

- **Payload Stream (output)**  
  `dout_valid/dout_ready`, `dout_data[127:0]`, `dout_keep[15:0]`, `dout_last`

- **Tag / Status**  
  `tag_out[127:0]`, `tag_out_valid`  
  Optional: `auth_fail` for verify failures in decrypt mode (if implemented)

**Notes**
- `*_keep` is **bit-per-byte** (16’b1111… indicates valid bytes); used for partial final blocks.
- `len_aad_bits` and `len_pld_bits` are **bit lengths** per the GCM spec.

---

## Design highlights
- **Single AES core** shared between CTR and H-derivation for small area.
- **Streaming interfaces** with backpressure: clean ready/valid on AAD and payload.
- **Partial block support** with `keep` masks and correct GHASH handling.
- **Spec-compliant** length block and tag computation (SP 800-38D).

---

## Credits
- AES core from **secworks/aes** (see its license in `rtl/third_party/secworks_aes`).
- GHASH and glue logic implemented in this project to integrate AES-CTR and GCM rules.
