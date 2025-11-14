`default_nettype none
// chacha_poly1305_adapter.v
// Produces Poly1305 tag for ChaCha20-Poly1305 using existing chacha_block + multiplier + reducer.
// Streams in: AAD and PAYLOAD (128-bit lanes with keep mask).
// Outputs: tag_pre_xor (128-bit accumulator), tag_pre_xor_valid,
//          tagmask (s, 128-bit), tagmask_valid.
// Minimal, synthesizable Verilog. One chacha_block used (1 round/cycle) to get keystream block-0.

module chacha_poly1305_adapter (
    input  wire         clk,
    input  wire         rst_n,

    // Control: pulse start when new message starts
    input  wire         start,       // 1-cycle pulse to begin processing for a message
    input  wire         algo_sel,    // 1 = ChaCha mode (adapter will be active), 0 = inactive

    // Key/nonce interface (reuse aes_gcm_datapath internals)
    input  wire [255:0] key,         // ChaCha key (256-bit)
    input  wire [95:0]  nonce,       // ChaCha 96-bit nonce
    input  wire [31:0]  ctr_init,    // counter initial value for keystream used elsewhere (we use 0 for OTK)

    // AAD stream (external to datapath; connect to same signals used for GHASH input)
    input  wire         aad_valid,
    input  wire [127:0] aad_data,
    input  wire [15:0]  aad_keep,
    output reg          aad_ready,

    // Payload stream (ciphertext) - these should be the *ciphertext* blocks
    input  wire         pld_valid,
    input  wire [127:0] pld_data,
    input  wire [15:0]  pld_keep,
    output reg          pld_ready,

    // Lengths block (len_aad_bits || len_ct_bits) — 128-bit — provided by gcm_lenblock or datapath
    input  wire         len_valid,
    input  wire [127:0] len_block,
    output reg          len_ready,

    // Outputs (to datapath ctrl)
    output reg  [127:0] tag_pre_xor,    // poly accumulator low 128 bits (Y)
    output reg          tag_pre_xor_valid,
    output reg  [127:0] tagmask,        // Poly1305 's' (pad)
    output reg          tagmask_valid,

    // status outputs (not used by datapath directly, but available)
    output reg          aad_done,
    output reg          pld_done,
    output reg          lens_done
);

    // ------------------------------------------------------------------
    // Local params / states
    // ------------------------------------------------------------------
    localparam S_IDLE     = 3'd0;
    localparam S_OTK      = 3'd1; // produce one-time key (ChaCha block 0)
    localparam S_AAD      = 3'd2; // absorb AAD
    localparam S_PLD      = 3'd3; // absorb ciphertext
    localparam S_LEN      = 3'd4; // process length block
    localparam S_DONE     = 3'd5;

    reg [2:0] state, next_state;

    // ------------------------------------------------------------------
    // Internal: one-time key (OTK) from ChaCha block0 -> r || s
    reg [127:0] r_reg;   // 'r' (clamped)
    reg [127:0] s_reg;   // 's' (pad)
    reg         otk_valid_reg;

    // ------------------------------------------------------------------
    // ChaCha block0 generator (use existing chacha_block via chacha_core)
    // ------------------------------------------------------------------
    reg          chacha_start_block;
    wire         chacha_done;
    wire [511:0] chacha_out;

    reg [511:0] chacha_state_in;

    // Instantiate chacha_core to produce block0 (we use init to load state and start)
    chacha_core CHACHA0 (
        .clk      (clk),
        .reset_n  (rst_n),
        .init     (chacha_start_block),
        .next     (1'b0),
        .key      (key),
        .ctr      ({32'h0, ctr_init}),
        .iv       (nonce[95:32]),
        .data_in  (512'h0),
        .ready    (),
        .data_out (chacha_out),
        .data_out_valid(chacha_done)
    );

    // ------------------------------------------------------------------
    // Poly1305 accumulator state
    // ------------------------------------------------------------------
    reg [129:0] acc_reg; // 130-bit accumulator

    // multiplier + reducer wires & control (reuse user's modules)
    reg mul_start;
    reg red_start;
    reg [129:0] mul_a;
    reg [127:0] mul_b;
    wire [257:0] mul_product;
    wire mul_done;
    wire [129:0] red_out;
    wire red_done;

    mult_130x128_limb MUL_INST (
        .clk(clk),
        .reset_n(rst_n),
        .start(mul_start),
        .a_in(mul_a),
        .b_in(mul_b),
        .product_out(mul_product),
        .busy(),
        .done(mul_done)
    );

    reduce_mod_poly1305 RED_INST (
        .clk(clk),
        .reset_n(rst_n),
        .start(red_start),
        .value_in(mul_product),
        .value_out(red_out),
        .busy(),
        .done(red_done)
    );

    // ------------------------------------------------------------------
    // Utility: mask 128-bit word by 16-bit keep mask (same as your aes mask_block).
    // ------------------------------------------------------------------
    function [127:0] mask_block;
        input [127:0] data;
        input [15:0]  keep;
        integer i;
        begin
            mask_block = 128'h0;
            for (i = 0; i < 16; i = i + 1) begin
                mask_block[i*8 +: 8] = keep[i] ? data[i*8 +: 8] : 8'h00;
            end
        end
    endfunction

    // Convert block to 130-bit integer for Poly1305: [129] = 1 (the appended one), [127:0] = little-endian block
    function [129:0] block_to_130;
        input [127:0] blk;
        begin
            block_to_130 = {1'b1, blk};
        end
    endfunction

    // ------------------------------------------------------------------
    // Block staging - single block buffer for multiply pipeline
    // ------------------------------------------------------------------
    reg [127:0] block_reg;
    reg [15:0]  block_keep_reg;
    reg         block_valid_reg;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            aad_ready <= 1'b0;
            pld_ready <= 1'b0;
            len_ready <= 1'b0;
            block_valid_reg <= 1'b0;
            block_reg <= 128'h0;
            block_keep_reg <= 16'h0;
        end else begin
            aad_ready <= 1'b0;
            pld_ready <= 1'b0;
            len_ready <= 1'b0;

            if (state == S_AAD) begin
                if (!block_valid_reg && aad_valid) begin
                    block_reg <= mask_block(aad_data, aad_keep);
                    block_keep_reg <= aad_keep;
                    block_valid_reg <= 1'b1;
                    aad_ready <= 1'b1;
                end
            end else if (state == S_PLD) begin
                if (!block_valid_reg && pld_valid) begin
                    block_reg <= mask_block(pld_data, pld_keep);
                    block_keep_reg <= pld_keep;
                    block_valid_reg <= 1'b1;
                    pld_ready <= 1'b1;
                end
            end else if (state == S_LEN) begin
                if (!block_valid_reg && len_valid) begin
                    block_reg <= len_block;
                    block_keep_reg <= 16'hFFFF;
                    block_valid_reg <= 1'b1;
                    len_ready <= 1'b1;
                end
            end

            // Clear when we launch multiply
            if (mul_start) block_valid_reg <= 1'b0;
        end
    end

    // ------------------------------------------------------------------
    // Multiply/reduce pipeline controller
    // ------------------------------------------------------------------
    reg mul_in_progress;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            mul_start <= 1'b0;
            red_start <= 1'b0;
            mul_in_progress <= 1'b0;
            mul_a <= 130'b0;
            mul_b <= 128'b0;
        end else begin
            mul_start <= 1'b0;
            red_start <= 1'b0;
            if (!mul_in_progress) begin
                if (block_valid_reg && otk_valid_reg) begin
                    mul_a <= acc_reg + block_to_130(block_reg);
                    mul_b <= r_reg;
                    mul_start <= 1'b1;
                    mul_in_progress <= 1'b1;
                end
            end else begin
                if (mul_done) begin
                    red_start <= 1'b1;
                end
                if (red_done) begin
                    acc_reg <= red_out;
                    mul_in_progress <= 1'b0;
                end
            end
        end
    end

    // ------------------------------------------------------------------
    // Main state machine
    // ------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= S_IDLE;
            r_reg <= 128'h0;
            s_reg <= 128'h0;
            otk_valid_reg <= 1'b0;
            acc_reg <= 130'h0;
            tag_pre_xor <= 128'h0;
            tag_pre_xor_valid <= 1'b0;
            tagmask <= 128'h0;
            tagmask_valid <= 1'b0;
            aad_done <= 1'b0;
            pld_done <= 1'b0;
            lens_done <= 1'b0;
            chacha_start_block <= 1'b0;
        end else begin
            tag_pre_xor_valid <= 1'b0;
            tagmask_valid <= 1'b0;
            chacha_start_block <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start && algo_sel) begin
                        acc_reg <= 130'h0;
                        otk_valid_reg <= 1'b0;
                        aad_done <= 1'b0;
                        pld_done <= 1'b0;
                        lens_done <= 1'b0;
                        chacha_start_block <= 1'b1;
                        state <= S_OTK;
                    end
                end

                S_OTK: begin
                    if (chacha_done) begin
                        // assign r and s (note: byte order of chacha_out must match expectations)
                        r_reg <= chacha_out[127:0];
                        s_reg <= chacha_out[255:128];
                        otk_valid_reg <= 1'b1;
                        state <= S_AAD;
                    end
                end

                S_AAD: begin
                    // Wait for external signal to indicate AAD completed.
                    // aes_gcm_ctrl will set aad_done externally; user can assert this by wiring
                    if (aad_done) begin
                        state <= S_PLD;
                    end
                end

                S_PLD: begin
                    if (pld_done) begin
                        state <= S_LEN;
                    end
                end

                S_LEN: begin
                    if (!mul_in_progress && !block_valid_reg) begin
                        // finalize: output tag_pre_xor and tagmask
                        tag_pre_xor <= acc_reg[127:0];
                        tag_pre_xor_valid <= 1'b1;
                        tagmask <= s_reg;
                        tagmask_valid <= 1'b1;
                        state <= S_DONE;
                    end
                end

                S_DONE: begin
                    // hold outputs one cycle, then go idle
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule

`default_nettype wire
