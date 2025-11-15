1. chacha_core

This module is the encryption engine for a single 512-bit ChaCha20 block.

It takes a key, counter (ctr), IV, and a 512-bit input (data_in) and XORs it with the ChaCha output to produce data_out.

It uses a chacha_block instance to perform 20 rounds of ChaCha operations internally, one round per clock cycle.

It manages start/pending flags and asserts data_out_valid when the XORed output is ready.

ready indicates the module can accept a new block (either init or next).




2. chacha_block

Implements the core ChaCha20 round function.

Operates one round per clock cycle, alternating column and diagonal rounds.

Contains 16 32-bit words (w0-w15) representing the internal state and performs the quarter-round operations.

When all rounds are done, it performs feed-forward addition with the original state and asserts done.

Outputs a full 512-bit ChaCha state, which chacha_core then XORs with the input data.



3. reduce_mod_poly1305

Performs modular reduction modulo  required for Poly1305 accumulation.

Takes a 258-bit input (value_in) and reduces it to 130 bits (value_out).

Uses simple combinational logic with registers to compute lo + hi*5 and conditionally subtract (2^130 - 5).

Produces done and busy signals to indicate when reduction is finished.

This module is a utility for the Poly1305 MAC calculation in chacha20_poly1305_core.




4. chacha20_poly1305_core

Top-level wrapper for ChaCha20-Poly1305 AEAD encryption.

Instantiates chacha_core (via chacha_keystream_unit) for encryption and chacha_poly1305_adapter for MAC calculation.

Handles input streams: AAD, payload, and length blocks via valid/ready handshakes.

Maintains internal done flags (aad_done, pld_done, lens_done) and outputs them to the outside.

Produces 512-bit keystreams and Poly1305 tag outputs along with valid signals.




5. tb_chacha20_poly1305_core (testbench)

Provides a cycle-accurate simulation of chacha20_poly1305_core using a single 512-bit payload split into 4 x 128-bit words.

Tracks each step: configuration write, keystream generation, AAD, payload input, length block, tag computation, and done.

Prints cycle numbers, input data, output keystream, and tag values for debugging and verification.

Forces algo_sel = 1 to use ChaCha only, ignoring AES.

Serves as a visual, step-by-step monitor of data flow through the ChaCha AEAD pipeline.



6. aes_gcm_top_chacha (ChaCha part only)

Top-level unified interface supporting both AES-GCM and ChaCha20-Poly1305.

Instantiates chacha20_poly1305_core and forwards keys, nonce, payload, and AAD.

Selects ChaCha outputs using algo_sel signal, ignoring AES if algo_sel = 1.

Handles muxing of keystream and done signals to external ports.

Provides a simple interface for higher-level modules to use ChaCha encryption and MAC.



7. chacha_keystream_unit

Generates ChaCha20 keystream blocks based on key, nonce, and counter.

Produces 512-bit keystream output (ks_data) with valid signal.

Supports start/configuration control (cfg_we, ks_req) to trigger keystream generation.

Performs the core ChaCha20 rounds internally.

Acts as the primary source of keystream for both payload encryption and Poly1305 MAC.



8. chacha_poly1305_adapter

Takes in AAD and payload blocks and streams them to the Poly1305 accumulator.

Computes intermediate authentication values (tag_pre_xor and tagmask).

Generates done flags (aad_done, pld_done, lens_done) when each data type finishes.

Supports variable-length inputs using valid/ready handshake.

Integrates tightly with ChaCha20 keystream for AEAD processing.
