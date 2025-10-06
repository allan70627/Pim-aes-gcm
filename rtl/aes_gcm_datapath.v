`default_nettype none

// -----------------------------------------------------------------------------
// AES-GCM datapath
// - Single shared aes_core used for H, tagmask, and CTR keystream
// - 96-bit IV fast-path: J0 = {IV, 0^31, 1}
// - GHASH absorbs: AAD -> CIPHERTEXT -> lengths block
// - Tag pre-xor from GHASH; tagmask = AES(K, J0)
// -----------------------------------------------------------------------------
module aes_gcm_datapath (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key_in,
    input  wire         key_we,
    input  wire         aes256_en,
    input  wire [95:0]  iv_in,
    input  wire         iv_we,
    input  wire [63:0]  len_aad_bits,
    input  wire [63:0]  len_pld_bits,
    input  wire         start,
    input  wire         enc_mode,
    // AAD stream
    input  wire         aad_valid,
    output wire         aad_ready,
    input  wire         aad_last,
    input  wire [127:0] aad_data,
    input  wire [15:0]  aad_keep,
    // Payload in/out
    input  wire         din_valid,
    output wire         din_ready,
    input  wire         din_last,
    input  wire [127:0] din_data,
    input  wire [15:0]  din_keep,
    output wire         dout_valid,
    input  wire         dout_ready,
    output wire         dout_last,
    output wire [127:0] dout_data,
    output wire [15:0]  dout_keep,
    // Tag/Mask + status
    output wire [127:0] tag_pre_xor,
    output wire         tag_pre_xor_valid,
    output wire [127:0] tagmask,
    output wire         tagmask_valid,
    output wire         aad_done,
    output wire         pld_done,
    output wire         lens_done
);

    // ------------------------------------------------------------------
    // Local parameters and helper functions
    // ------------------------------------------------------------------
    localparam PH_IDLE    = 3'd0;
    localparam PH_AAD     = 3'd1;
    localparam PH_PAYLOAD = 3'd2;
    localparam PH_LEN     = 3'd3;
    localparam PH_WAIT    = 3'd4;
    localparam PH_DONE    = 3'd5;

    function automatic [127:0] mask_block;
        input [127:0] data;
        input [15:0]  keep;
        integer idx;
        begin
            for (idx = 0; idx < 16; idx = idx + 1) begin
                mask_block[idx*8 +: 8] = keep[idx] ? data[idx*8 +: 8] : 8'h00;
            end
        end
    endfunction

    // ------------------------------------------------------------------
    // Registers and wires
    // ------------------------------------------------------------------
    reg         start_d;
    reg         enc_mode_reg;
    reg [63:0]  len_aad_bits_reg;
    reg [63:0]  len_pld_bits_reg;
    reg [2:0]   phase_reg, phase_next;

    reg [127:0] H_reg;
    reg [127:0] pld_buf_data_reg;
    reg         pld_buf_valid_reg;
    reg         pld_buf_last_reg;
    reg         payload_pending_reg;
    reg         dout_valid_q;
    reg         aad_done_reg;
    reg         pld_done_reg;
    reg         lens_done_reg;
    reg         pld_consumed_last_reg;
    reg         len_pending_reg;
    reg [127:0] tag_pre_xor_reg;
    reg         tag_pre_xor_valid_reg;

    // Key and IV handling
    reg [255:0] key_active_reg;
    reg         keylen_active_reg;
    reg         key_init_pending_reg;
    reg         h_pending_reg;
    reg [95:0]  iv_reg;

    wire start_pulse  = start && !start_d;
    wire no_aad_start = (len_aad_bits == 64'd0);
    wire no_pld_start = (len_pld_bits == 64'd0);
    wire no_pld       = (len_pld_bits_reg == 64'd0);

    wire [127:0] aad_data_masked        = mask_block(aad_data, aad_keep);
    wire [127:0] payload_data_masked_in = mask_block(din_data, din_keep);

    // Counter generator
    wire [127:0] ctr_block;
    wire         ctr_valid;
    reg          ctr_next_reg;

    // GHASH interface
    wire         ghash_din_ready;
    wire [127:0] ghash_Y;
    wire         ghash_Y_valid;
    wire [127:0] len_block;

    reg          ghash_valid_int;
    reg [127:0]  ghash_data_int;
    reg          ghash_last_int;

    // CTR XOR connection
    wire         ks_req;
    wire         ks_valid;
    reg  [127:0] ks_data_reg;
    wire [127:0] ks_data = ks_data_reg;

    wire         payload_channel_active = (phase_reg == PH_PAYLOAD);
    wire         ctr_dout_valid;
    wire [127:0] ctr_dout_data;
    wire [15:0]  ctr_dout_keep;
    wire         ctr_dout_last;
    wire [127:0] payload_data_masked_out = mask_block(ctr_dout_data, ctr_dout_keep);

    wire         aad_handshake          = (phase_reg == PH_AAD) && ghash_valid_int;
    wire         aad_last_handshake     = aad_handshake && aad_last;
    wire         payload_din_handshake  = payload_channel_active && din_valid && din_ready;
    wire         payload_dout_handshake = payload_channel_active && ctr_dout_valid && dout_ready;
    wire         load_pld_buf_dec       = !enc_mode_reg && payload_din_handshake && !pld_buf_valid_reg &&\n                       h_ready_reg;
    wire         load_pld_buf_enc       =  enc_mode_reg && payload_dout_handshake && !pld_buf_valid_reg &&\n                       h_ready_reg;
    wire         load_pld_buf           = load_pld_buf_dec | load_pld_buf_enc;
    wire [127:0] pld_buf_data_load      = load_pld_buf_dec ? payload_data_masked_in : payload_data_masked_out;
    wire         pld_buf_last_load      = load_pld_buf_dec ? din_last : ctr_dout_last;
    wire         consume_pld_buf        = payload_channel_active && pld_buf_valid_reg && ghash_din_ready;
    wire         consume_pld_buf_last   = consume_pld_buf && pld_buf_last_reg;
    wire         len_handshake          = (phase_reg == PH_LEN) && len_pending_reg && ghash_din_ready;
    wire         payload_last_handshake = enc_mode_reg ? (payload_dout_handshake && ctr_dout_last)
                                                      : (payload_din_handshake && din_last);
    wire         dout_valid_rise        = ctr_dout_valid && !dout_valid_q;

    // AES core control
    reg         aes_init_reg;
    reg         aes_next_reg;
    reg [127:0] aes_block_reg;
    wire        aes_ready;
    wire [127:0] aes_result;
    wire        aes_result_valid;

    // Task tracking
    reg         ctr_pending_reg;   // waiting for CTR aes_result
    reg         tagmask_pending_reg;
    reg         tagmask_valid_reg;
    reg [127:0] tagmask_reg;
    reg         ctr_consuming;
    reg         tagmask_consuming;
    reg         h_consuming;

    // ------------------------------------------------------------------
    // Sequential logic
    // ------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            start_d <= 1'b0;
        end else begin
            start_d <= start;
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            enc_mode_reg         <= 1'b0;
            len_aad_bits_reg     <= 64'd0;
            len_pld_bits_reg     <= 64'd0;
            key_active_reg       <= 256'h0;
            keylen_active_reg    <= 1'b0;
            key_init_pending_reg <= 1'b0;
            h_pending_reg        <= 1'b0;
            iv_reg               <= 96'h0;
        end else begin
            if (start_pulse) begin
                enc_mode_reg     <= enc_mode;
                len_aad_bits_reg <= len_aad_bits;
                len_pld_bits_reg <= len_pld_bits;
            end

            if (key_we) begin
                key_active_reg       <= (aes256_en ? key_in : {128'h0, key_in[127:0]});
                keylen_active_reg    <= aes256_en;
                key_init_pending_reg <= 1'b1;
                h_pending_reg        <= 1'b1;
            end

            if (iv_we) begin
                iv_reg <= iv_in;
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            H_reg       <= 128'h0;
            h_ready_reg <= 1'b0;
        end else begin
            if (key_we) begin
                h_ready_reg <= 1'b0;
            end
            if (aes_result_valid && h_consuming) begin
                H_reg       <= aes_result;
                h_ready_reg <= 1'b1;
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            phase_reg <= PH_IDLE;
        end else begin
            phase_reg <= phase_next;
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pld_buf_valid_reg <= 1'b0;
            pld_buf_data_reg  <= 128'h0;
            pld_buf_last_reg  <= 1'b0;
        end else begin
            if (start_pulse) begin
                pld_buf_valid_reg <= 1'b0;
                pld_buf_last_reg  <= 1'b0;
            end else if (consume_pld_buf) begin
                pld_buf_valid_reg <= 1'b0;
                pld_buf_last_reg  <= 1'b0;
            end

            if (load_pld_buf) begin
                pld_buf_valid_reg <= 1'b1;
                pld_buf_data_reg  <= pld_buf_data_load;
                pld_buf_last_reg  <= pld_buf_last_load;
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            payload_pending_reg <= 1'b0;
            dout_valid_q        <= 1'b0;
        end else begin
            dout_valid_q <= ctr_dout_valid;

            if (start_pulse) begin
                payload_pending_reg <= 1'b0;
            end else begin
                if (payload_din_handshake) begin
                    payload_pending_reg <= 1'b1;
                end else if (dout_valid_rise) begin
                    payload_pending_reg <= 1'b0;
                end
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            aad_done_reg <= 1'b0;
        end else if (start_pulse) begin
            aad_done_reg <= no_aad_start;
        end else if (aad_last_handshake) begin
            aad_done_reg <= 1'b1;
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pld_done_reg <= 1'b0;
        end else if (start_pulse) begin
            pld_done_reg <= no_pld_start;
        end else if (payload_last_handshake) begin
            pld_done_reg <= 1'b1;
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            lens_done_reg <= 1'b0;
        end else if (start_pulse) begin
            lens_done_reg <= 1'b0;
        end else if (len_handshake) begin
            lens_done_reg <= 1'b1;
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pld_consumed_last_reg <= 1'b1;
        end else if (start_pulse) begin
            pld_consumed_last_reg <= no_pld_start;
        end else begin
            if (load_pld_buf) begin
                pld_consumed_last_reg <= 1'b0;
            end else if (consume_pld_buf_last) begin
                pld_consumed_last_reg <= 1'b1;
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            len_pending_reg <= 1'b0;
        end else if (start_pulse) begin
            len_pending_reg <= 1'b1;
        end else if (len_handshake) begin
            len_pending_reg <= 1'b0;
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tag_pre_xor_reg       <= 128'h0;
            tag_pre_xor_valid_reg <= 1'b0;
        end else if (start_pulse) begin
            tag_pre_xor_reg       <= 128'h0;
            tag_pre_xor_valid_reg <= 1'b0;
        end else begin
            if (ghash_Y_valid) begin
                tag_pre_xor_reg       <= ghash_Y;
                tag_pre_xor_valid_reg <= 1'b1;
            end
        end
    end

    // ------------------------------------------------------------------
    // GHASH input routing
    // ------------------------------------------------------------------
    always @* begin
        ghash_valid_int = 1'b0;
        ghash_data_int  = 128'h0;
        ghash_last_int  = 1'b0;

        case (phase_reg)
            PH_AAD: begin
                if (ghash_din_ready && aad_valid) begin
                    ghash_valid_int = 1'b1;
                    ghash_data_int  = aad_data_masked;
                end
            end
            PH_PAYLOAD: begin
                if (ghash_din_ready && pld_buf_valid_reg) begin
                    ghash_valid_int = 1'b1;
                    ghash_data_int  = pld_buf_data_reg;
                end
            end
            PH_LEN: begin
                if (ghash_din_ready && len_pending_reg) begin
                    ghash_valid_int = 1'b1;
                    ghash_data_int  = len_block;
                    ghash_last_int  = 1'b1;
                end
            end
            default: begin
            end
        endcase
    end

    // Phase transitions
    always @* begin
        phase_next = phase_reg;

        if (start_pulse) begin
            if (!no_aad_start) begin
                phase_next = PH_AAD;
            end else if (!no_pld_start) begin
                phase_next = PH_PAYLOAD;
            end else begin
                phase_next = PH_LEN;
            end
        end else begin
            case (phase_reg)
                PH_IDLE: begin
                end
                PH_AAD: begin
                    if (aad_last_handshake) begin
                        if (no_pld) phase_next = PH_LEN; else phase_next = PH_PAYLOAD;
                    end
                end
                PH_PAYLOAD: begin
                    if (pld_consumed_last_reg && !pld_buf_valid_reg && !payload_pending_reg && !ctr_dout_valid) begin
                        phase_next = PH_LEN;
                    end
                end
                PH_LEN: begin
                    if (len_handshake) begin
                        phase_next = PH_WAIT;
                    end
                end
                PH_WAIT: begin
                    if (ghash_Y_valid) begin
                        phase_next = PH_DONE;
                    end
                end
                PH_DONE: begin
                    phase_next = PH_IDLE;
                end
                default: phase_next = PH_IDLE;
            endcase
        end
    end

    // ------------------------------------------------------------------
    // Ready/valid signals to external
    // ------------------------------------------------------------------
    assign aad_ready = (phase_reg == PH_AAD) && ghash_din_ready && h_ready_reg;
    assign din_ready = payload_channel_active &&
                       dout_ready &&
                       !payload_pending_reg &&
                       !ctr_dout_valid &&
                       !pld_buf_valid_reg &&\n                       h_ready_reg;
    assign dout_valid = ctr_dout_valid;
    assign dout_data  = ctr_dout_data;
    assign dout_keep  = ctr_dout_keep;
    assign dout_last  = ctr_dout_last;

    assign tag_pre_xor       = tag_pre_xor_reg;
    assign tag_pre_xor_valid = tag_pre_xor_valid_reg;
    assign aad_done          = aad_done_reg;
    assign pld_done          = pld_done_reg;
    assign lens_done         = lens_done_reg;

    // ------------------------------------------------------------------
    // Submodule instances
    // ------------------------------------------------------------------
    gcm_lenblock u_gcm_lenblock (
        .len_aad_bits (len_aad_bits_reg),
        .len_ct_bits  (len_pld_bits_reg),
        .len_block    (len_block)
    );

    ghash_core u_ghash_core (
        .clk       (clk),
        .rst_n     (rst_n),
        .init      (start_pulse && h_ready_reg),
        .H         (H_reg),
        .din_valid (ghash_valid_int),
        .din_ready (ghash_din_ready),
        .din_data  (ghash_data_int),
        .din_last  (ghash_last_int),
        .Y         (ghash_Y),
        .Y_valid   (ghash_Y_valid)
    );

    // CTR XOR (consume keystream from centralized AES)
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

    ctr_gen u_ctr_gen (
        .clk       (clk),
        .rst_n     (rst_n),
        .load_iv   (iv_we),
        .iv96      (iv_in),
        .next      (ctr_next_reg),
        .ctr_block (ctr_block),
        .ctr_valid (ctr_valid)
    );

    // Central AES core
    aes_core u_aes_core (
        .clk          (clk),
        .reset_n      (rst_n),
        .encdec       (1'b1),
        .init         (aes_init_reg),
        .next         (aes_next_reg),
        .ready        (aes_ready),
        .key          (key_active_reg),
        .keylen       (keylen_active_reg),
        .block        (aes_block_reg),
        .result       (aes_result),
        .result_valid (aes_result_valid)
    );

    // ------------------------------------------------------------------
    // AES task scheduler: priority CTR > TAGMASK > H; INIT asap on key change
    // ------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            aes_init_reg          <= 1'b0;
            aes_next_reg          <= 1'b0;
            aes_block_reg         <= 128'h0;
            ks_data_reg           <= 128'h0;
            ctr_pending_reg       <= 1'b0;
            ctr_next_reg          <= 1'b0;
            tagmask_pending_reg   <= 1'b0;
            tagmask_reg           <= 128'h0;
            tagmask_valid_reg     <= 1'b0;
            ctr_consuming         <= 1'b0;
            tagmask_consuming     <= 1'b0;
            h_consuming           <= 1'b0;
        end else begin
            aes_init_reg      <= 1'b0; // default pulse
            aes_next_reg      <= 1'b0; // default pulse
            ctr_next_reg      <= 1'b0;

            // Reset tagmask_valid on new message
            if (start_pulse) begin
                tagmask_pending_reg <= 1'b1; // compute early
                tagmask_valid_reg   <= 1'b0;
            end

            // Request keystream for each block request
            if (ks_req && !ctr_pending_reg) begin
                // Kick counter to produce next block
                ctr_next_reg    <= 1'b1;
                ctr_pending_reg <= 1'b1;
            end

            // AES INIT on key change
            if (key_init_pending_reg && aes_ready) begin
                aes_init_reg          <= 1'b1;
                key_init_pending_reg  <= 1'b0;
            end

            // Schedule CTR encryption if pending and a block is ready
            if (ctr_pending_reg && ctr_valid && aes_ready) begin
                aes_block_reg   <= ctr_block;
                aes_next_reg    <= 1'b1;
                ctr_consuming   <= 1'b1;
                tagmask_consuming <= 1'b0;
                h_consuming     <= 1'b0;
                ctr_pending_reg <= 1'b0; // waiting for result now
            end else if (tagmask_pending_reg && aes_ready && !ks_req) begin
                // Tagmask when AES is free and no CTR request
                aes_block_reg     <= {iv_reg, 32'h00000001};
                aes_next_reg      <= 1'b1;
                tagmask_consuming <= 1'b1;
                ctr_consuming     <= 1'b0;
                h_consuming       <= 1'b0;
                tagmask_pending_reg <= 1'b0;
            end else if (h_pending_reg && aes_ready && !ks_req) begin
                // Compute H = AES(K, 0^128) when free and no CTR pressure
                aes_block_reg   <= 128'h0;
                aes_next_reg    <= 1'b1;
                h_consuming     <= 1'b1;
                ctr_consuming   <= 1'b0;
                tagmask_consuming <= 1'b0;
                h_pending_reg   <= 1'b0;
            end

            // Capture AES result
            if (aes_result_valid) begin
                if (ctr_consuming) begin
                    ks_data_reg   <= aes_result;
                end else if (tagmask_consuming) begin
                    tagmask_reg       <= aes_result;
                    tagmask_valid_reg <= 1'b1;
                end else if (h_consuming) begin
                    // H captured in H_reg in its own always block
                end
                ctr_consuming       <= 1'b0;
                tagmask_consuming   <= 1'b0;
                h_consuming         <= 1'b0;
            end
        end
    end

    assign ks_valid      = aes_result_valid && ctr_consuming;
    assign tagmask       = tagmask_reg;
    assign tagmask_valid = tagmask_valid_reg;

endmodule

`default_nettype wire






