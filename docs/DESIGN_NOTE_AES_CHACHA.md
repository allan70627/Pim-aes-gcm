Design Note: AES–ChaCha Keystream Unification
1. Goal

Enable the existing AES-GCM engine to share its keystream datapath with a ChaCha-based mode, so that:

ctr_xor can consume keystream from either AES or ChaCha through the same interface.

Existing AES-GCM behavior remains intact when ChaCha is disabled.

Modes:

algo_sel = 0 → AES-GCM (original behavior).

algo_sel = 1 → ChaCha keystream feeds ctr_xor (toward ChaCha20-Poly1305).

2. Keystream Interface Refactor (ctr_xor ↔ datapath)

Files touched: rtl/aes_gcm_datapath.v

What changed

Introduced a generic keystream interface between ctr_xor and the rest of the datapath:

ks_req – request next 128-bit keystream block

ks_valid – selected producer indicates data is valid

ks_data – 128-bit keystream block

Split the old “flat” keystream signals into:

Generic: ks_req, ks_valid, ks_data (used by ctr_xor only)

AES-specific: ks_valid_aes, ks_data_aes

Left the ctr_xor instantiation unchanged: it still only sees the generic ks_* signals.

Why

Previously, ctr_xor was implicitly hard-wired to AES via a single ks_data_reg and ks_valid driven only by AES.

By making ks_* generic and introducing ks_*_aes, we can later plug in other keystream producers (ChaCha) without touching ctr_xor or external ports.

3. AES Path: Explicit Keystream Producer

Files touched: rtl/aes_gcm_datapath.v

What changed

AES result capture logic now fills AES-local keystream signals:

On AES CTR consumption:

Write aes_result into ks_data_aes.

Assert ks_valid_aes when aes_result_valid && ctr_consuming.

Tagmask/other uses of AES output remain unchanged.

The generic interface is initially driven only from AES:

ks_valid = ks_valid_aes

ks_data = ks_data_aes

Why

This makes AES CTR look like a clean “producer” behind the generic interface.

The rest of the GCM datapath (GHASH, tagmask, lengths) remains untouched; only the keystream path is abstracted.

It preserves bit-exact AES-GCM behavior when algo_sel = 0 while preparing the design for another producer.

4. New ChaCha Keystream Unit

Files touched: rtl/chacha_keystream_unit.v (new), rtl/aes_gcm_datapath.v (instantiation)

What changed

Added a new module chacha_keystream_unit that:

Latches ChaCha configuration:

chacha_key

chacha_nonce

chacha_ctr_init

cfg_we (write enable for config)

Connects to chacha_core using the existing interface (key, ctr, iv, rounds, data_out, ready, valid).

Implements the same unified keystream interface as AES:

Input: ks_req

Outputs: ks_valid, ks_data (128-bit)

Current behavior (first version):

For each ks_req when chacha_core is ready:

Issue a single next pulse to the core.

Wait for data_out_valid.

Take the lower 128 bits of the 512-bit ChaCha block as ks_data.

Pulse ks_valid for one cycle.

Increment an internal 32-bit block counter for the next request.

aes_gcm_datapath now instantiates chacha_keystream_unit and wires:

chacha_key ← internal active AES key register (for now)

chacha_nonce ← iv_in (95:0)

chacha_ctr_init ← constant 32'd1 (initial block counter)

cfg_we ← currently tied low (TODO: drive from CSRs in ChaCha mode)

ks_req ← gated version of generic ks_req when ChaCha mode is selected

Why

Encapsulates all ChaCha specifics (key/nonce mapping, ctr/iv packing, handshake with chacha_core) inside a single unit.

Presents the same simple ks_req / ks_valid / ks_data interface to aes_gcm_datapath, making it symmetric with AES.

The first-pass “1× ks_req → 1× 128-bit word” policy is:

Functionally correct.

Easy to reason about with the existing ctr_xor design.

Leaves room for a later optimization to reuse all 512 bits (4× 128-bit words).

5. Keystream Mux: AES vs ChaCha

Files touched: rtl/aes_gcm_datapath.v

What changed

Introduced ChaCha-specific keystream signals:

ks_valid_chacha

ks_data_chacha

Added a simple 2-to-1 mux that drives the generic keystream interface:

ks_valid = algo_is_chacha ? ks_valid_chacha : ks_valid_aes

ks_data = algo_is_chacha ? ks_data_chacha : ks_data_aes

When ChaCha is selected, ks_req is also gated before it reaches chacha_keystream_unit:

AES always sees the full AES CTR/control context.

ChaCha only sees ks_req when algo_is_chacha = 1.

Why

Centralizes the “which producer is active?” decision in one place inside the datapath.

Keeps ctr_xor oblivious to algorithm choice.

Ensures only the selected producer is actually driven by the live keystream request.

6. Algorithm Select CSR (algo_sel)

Files touched: rtl/aes_gcm_top.v, rtl/aes_gcm_datapath.v

What changed

Added a 1-bit algorithm select input at the top level:

algo_sel:

0 → AES-GCM mode

1 → ChaCha-mode keystream

Propagated algo_sel into aes_gcm_datapath.

Introduced an internal decoded signal in the datapath:

algo_is_chacha = algo_sel;

algo_is_chacha is used to:

Gate ks_req into chacha_keystream_unit.

Select AES vs ChaCha in the keystream mux.

Why

Provides a single CSR bit under host/SSD controller control to choose the active keystream algorithm.

Keeps algorithm selection out of ctr_xor and out of the lower RTL blocks, minimizing intrusion into existing logic.

7. Behavioral Summary
AES-only mode (algo_sel = 0)

algo_is_chacha = 0

ks_req → AES CTR keystream path only.

ks_valid / ks_data come from ks_valid_aes / ks_data_aes.

ChaCha path is instantiated but effectively idle.

Functional behavior matches the original AES-GCM design.

ChaCha keystream mode (algo_sel = 1)

algo_is_chacha = 1

ks_req is forwarded to chacha_keystream_unit.

ks_valid / ks_data come from ChaCha’s FSM (one 128-bit word per ChaCha block).

GHASH / tag path is still AES-oriented; a full ChaCha20-Poly1305 tag pipeline is not yet implemented.

8. Current Limitations and Next Steps

Current limitations:

cfg_we for ChaCha is tied low; key/nonce/counter are not yet driven from a dedicated ChaCha CSR path.

ChaCha block utilization is suboptimal: only 128/512 bits are used per block.

Tag generation remains AES-GCM-specific; there is no Poly1305 path yet.

Planned next steps:

Drive ChaCha key/nonce/counter registers from mode-aware CSRs when algo_sel = 1.

Enhance chacha_keystream_unit to reuse each 512-bit ChaCha output as 4× 128-bit keystream blocks.

Add a Poly1305/tag pipeline and top-level mode control to complete a proper ChaCha20-Poly1305 datapath.