Design Note: Shared Keystream Interface for AES-GCM and ChaCha
1. Overview

This design change prepares the existing AES-GCM engine to share its keystream datapath with a ChaCha-based mode (targeting ChaCha20-Poly1305), without breaking the current AES-only behavior.

Goals:

Keep the external top-level interface and AES-GCM behavior intact when desired.

Introduce a generic keystream producer interface that ctr_xor can use for both AES and ChaCha.

Add a ChaCha keystream unit behind that interface.

Add an algorithm-select CSR so the host/SSD controller can choose AES or ChaCha.

When algo_sel = 0, the design behaves as the original AES-GCM engine. ChaCha logic is present but dormant.

2. Files and Modules Touched

rtl/aes_gcm_datapath.v
Refactored keystream signals into generic and AES-specific. Added ChaCha keystream signals and muxing logic.

rtl/aes_gcm_top.v
Added algo_sel CSR input and passed it into aes_gcm_datapath.

rtl/chacha_keystream_unit.v
New module: ChaCha-based keystream producer implementing the unified keystream interface.

rtl/chacha_core.v
Not modified in this step, but now instantiated by chacha_keystream_unit.

3. Generic Keystream Interface
3.1 Motivation

Originally, ctr_xor was implicitly tied to AES:

ctr_xor asserted ks_req to request a keystream block.

AES produced keystream via a dedicated register and valid signal.

There was no explicit way to plug in another cipher, such as ChaCha.

We now treat keystream generation as a generic producer behind a small interface:

// Generic keystream interface (seen by ctr_xor)
ks_req   // request next keystream block
ks_valid // producer indicates data is ready
ks_data  // 128-bit keystream block


ctr_xor does not know who the producer is; it only talks to this interface.

3.2 Refactor in aes_gcm_datapath.v

Old code:

// CTR XOR connection
wire         ks_req;
wire         ks_valid;
reg  [127:0] ks_data_reg;
wire [127:0] ks_data = ks_data_reg;


New structure:

// ------------------------------------------------------------------
// CTR XOR connection (generic keystream interface)
// ------------------------------------------------------------------
wire         ks_req;      // from ctr_xor to keystream producer(s)
wire         ks_valid;    // selected keystream valid (AES or ChaCha)
wire [127:0] ks_data;     // selected keystream data

// AES-specific keystream signals
wire         ks_valid_aes;
reg  [127:0] ks_data_aes_reg;
wire [127:0] ks_data_aes = ks_data_aes_reg;


The ctr_xor instantiation remains unchanged and continues to use only the generic signals:

ctr_xor u_ctr_xor (
    .clk        (clk),
    .rst_n      (rst_n),
    .enc_mode   (enc_mode_reg),
    .din_valid  (payload_channel_active ? din_valid : 1'b0),
    .din_data   (din_data),
    .din_keep   (din_keep),
    .din_last   (payload_channel_active ? din_last : 1'b0),
    .dout_ready (dout_ready),
    .dout_valid (ctr_dout_valid),
    .dout_data  (ctr_dout_data),
    .dout_keep  (ctr_dout_keep),
    .dout_last  (ctr_dout_last),
    .ks_req     (ks_req),
    .ks_valid   (ks_valid),
    .ks_data    (ks_data)
);

4. AES as a Keystream Producer

Previously, the AES scheduler directly wrote the generic keystream register and drove ks_valid.

Before (simplified):

// reset
ks_data_reg <= 128'h0;

// on AES result
if (aes_result_valid) begin
    if (ctr_consuming) begin
        ks_data_reg <= aes_result;
    end else if (tagmask_consuming) begin
        tagmask_reg       <= aes_result;
        tagmask_valid_reg <= 1'b1;
    end
end

assign ks_valid      = aes_result_valid && ctr_consuming;
assign tagmask       = tagmask_reg;
assign tagmask_valid = tagmask_valid_reg;


After:

// reset
ks_data_aes_reg <= 128'h0;

// on AES result
if (aes_result_valid) begin
    if (ctr_consuming) begin
        ks_data_aes_reg <= aes_result;
    end else if (tagmask_consuming) begin
        tagmask_reg       <= aes_result;
        tagmask_valid_reg <= 1'b1;
    end
end

assign ks_valid_aes  = aes_result_valid && ctr_consuming;
assign tagmask       = tagmask_reg;
assign tagmask_valid = tagmask_valid_reg;


Tagmask and GHASH behavior are unchanged.

Initially, AES is the only producer behind the generic interface:

assign ks_valid = ks_valid_aes;
assign ks_data  = ks_data_aes;


This preserves original AES-GCM behavior while allowing other producers (ChaCha) to be added cleanly.

5. New Module: chacha_keystream_unit
5.1 Purpose and Interface

chacha_keystream_unit encapsulates a ChaCha core and exposes the same keystream interface (ks_req, ks_valid, ks_data) as AES, plus configuration inputs.

File: rtl/chacha_keystream_unit.v

module chacha_keystream_unit (
    input  wire         clk,
    input  wire         rst_n,

    // Configuration (driven from key/IV CSRs in ChaCha mode)
    input  wire [255:0] chacha_key,
    input  wire [95:0]  chacha_nonce,
    input  wire [31:0]  chacha_ctr_init,
    input  wire         cfg_we,        // latch key/nonce/counter

    // Unified keystream interface for ctr_xor
    input  wire         ks_req,
    output reg          ks_valid,
    output reg  [127:0] ks_data
);
    ...
endmodule


Configuration registers:

reg [255:0] key_reg;
reg [95:0]  nonce_reg;
reg [31:0]  ctr_reg;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        key_reg   <= 256'h0;
        nonce_reg <= 96'h0;
        ctr_reg   <= 32'h0;
    end else if (cfg_we) begin
        key_reg   <= chacha_key;
        nonce_reg <= chacha_nonce;
        ctr_reg   <= chacha_ctr_init;
    end
end


Connection to chacha_core:

wire         core_ready;
wire         core_data_valid;
wire [511:0] core_data_out;

reg          core_init_reg, core_next_reg;
reg  [31:0]  ctr_next;

// Map nonce + counter into core's ctr/iv format
wire [63:0] ctr64 = {nonce_reg[31:0], ctr_reg};
wire [63:0] iv64  = nonce_reg[95:32];

chacha_core u_chacha_core (
    .clk           (clk),
    .reset_n       (rst_n),
    .init          (core_init_reg),
    .next          (core_next_reg),
    .keylen        (1'b1),
    .key           (key_reg),
    .ctr           (ctr64),
    .iv            (iv64),
    .rounds        (5'h14),
    .data_in       (512'h0),
    .ready         (core_ready),
    .data_out      (core_data_out),
    .data_out_valid(core_data_valid)
);

5.2 FSM Behavior (First Version)

The first working version uses a simple mapping:

One ks_req → one ChaCha block → one 128-bit keystream word.

FSM:

localparam S_IDLE  = 2'd0;
localparam S_WAIT  = 2'd1;
localparam S_OUT   = 2'd2;

reg [1:0] state_reg, state_next;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        state_reg     <= S_IDLE;
        core_init_reg <= 1'b0;
        core_next_reg <= 1'b0;
        ctr_reg       <= 32'h0;
    end else begin
        state_reg     <= state_next;
        core_init_reg <= 1'b0;
        core_next_reg <= 1'b0;
        ctr_reg       <= ctr_next;
    end
end

always @* begin
    state_next = state_reg;
    ctr_next   = ctr_reg;

    ks_valid   = 1'b0;
    ks_data    = 128'h0;

    case (state_reg)
        S_IDLE: begin
            // Accept a keystream request when core is ready
            if (ks_req && core_ready) begin
                core_next_reg = 1'b1;
                state_next    = S_WAIT;
            end
        end

        S_WAIT: begin
            if (core_data_valid) begin
                // Use lower 128 bits of the 512-bit ChaCha block
                ks_data    = core_data_out[127:0];
                ks_valid   = 1'b1;
                ctr_next   = ctr_reg + 1;
                state_next = S_OUT;
            end
        end

        S_OUT: begin
            // ks_valid was asserted in S_WAIT
            state_next = S_IDLE;
        end

        default: state_next = S_IDLE;
    endcase
end


Notes:

Only core_data_out[127:0] is used, so 75% of each ChaCha block is discarded in this version.

This is intentionally simple for integration and can be optimized later by caching the full 512 bits and emitting 4 × 128-bit keystream words.

6. Keystream Producer Selection in aes_gcm_datapath

Inside aes_gcm_datapath.v we add ChaCha-specific keystream signals:

wire         ks_valid_chacha;
wire [127:0] ks_data_chacha;


ChaCha keystream unit instantiation:

chacha_keystream_unit u_chacha_ks (
    .clk             (clk),
    .rst_n           (rst_n),
    .chacha_key      (key_active_reg),
    .chacha_nonce    (iv_in),
    .chacha_ctr_init (32'd1),
    .cfg_we          (1'b0),                      // TODO: drive in ChaCha mode
    .ks_req          (algo_is_chacha ? ks_req : 1'b0),
    .ks_valid        (ks_valid_chacha),
    .ks_data         (ks_data_chacha)
);


Final mux that feeds the generic interface:

// Keystream producer selection
// 0 = AES, 1 = ChaCha
assign ks_valid = algo_is_chacha ? ks_valid_chacha : ks_valid_aes;
assign ks_data  = algo_is_chacha ? ks_data_chacha  : ks_data_aes;


So:

When algo_is_chacha = 0, ctr_xor consumes AES keystream (original behavior).

When algo_is_chacha = 1, ctr_xor consumes ChaCha keystream.

7. Algorithm Select CSR (algo_sel)
7.1 Top-Level CSR in aes_gcm_top

The top-level now exposes a 1-bit CSR that chooses the keystream algorithm:

module aes_gcm_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key_in,
    input  wire         key_we,
    input  wire         aes256_en,
    input  wire [95:0]  iv_in,
    input  wire         iv_we,
    input  wire         start,
    input  wire         enc_mode,
    input  wire [63:0]  len_aad_bits,
    input  wire [63:0]  len_pld_bits,
    input  wire [127:0] tag_in,
    input  wire         tag_in_we,
    input  wire         algo_sel,   // 0 = AES-GCM, 1 = ChaCha mode
    ...
);


This bit is driven by the host or SSD controller.

7.2 Propagation to aes_gcm_datapath

In aes_gcm_datapath.v the port list is extended:

module aes_gcm_datapath (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key_in,
    input  wire         key_we,
    input  wire         aes256_en,
    input  wire [95:0]  iv_in,
    input  wire         iv_we,
    input  wire         start,
    input  wire         enc_mode,
    input  wire         algo_sel,   // 0 = AES, 1 = ChaCha
    ...
);


The top-level connects it:

aes_gcm_datapath u_datapath (
    .clk        (clk),
    .rst_n      (rst_n),
    .key_in     (key_in),
    .key_we     (key_we),
    .aes256_en  (aes256_en),
    .iv_in      (iv_in),
    .iv_we      (iv_we),
    .start      (start),
    .enc_mode   (enc_mode),
    .algo_sel   (algo_sel),
    ...
);


Internal decode:

// 0 = AES-GCM, 1 = ChaCha mode
wire algo_is_chacha = algo_sel;


This wire is used to:

Gate ks_req into chacha_keystream_unit.

Select between AES and ChaCha keystream outputs in the mux.

aes_gcm_ctrl is unchanged in this step.

8. Backward Compatibility and Status
8.1 Backward Compatibility

With algo_sel = 0:

algo_is_chacha = 0.

AES remains the only active producer.

Behavior and timing should match the original AES-GCM engine.

With algo_sel = 1:

ChaCha keystream logic is enabled, but some control and tag handling for a full ChaCha20-Poly1305 mode remain TODO.

8.2 Current Implementation Status

✅ Unified keystream interface (ks_req, ks_valid, ks_data) between ctr_xor and producers

✅ AES path refactored into an explicit keystream producer (ks_valid_aes, ks_data_aes)

✅ New chacha_keystream_unit that talks to chacha_core and emits 128-bit keystream words

✅ algo_sel CSR added in aes_gcm_top and wired into aes_gcm_datapath

✅ Keystream mux between AES and ChaCha inside aes_gcm_datapath

⏳ Drive cfg_we and ChaCha config from CSRs in ChaCha mode

⏳ Improve ChaCha block utilization (reuse full 512-bit block)

⏳ Integrate Poly1305/tag path for complete ChaCha20-Poly1305 mode