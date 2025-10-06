// -----------------------------------------------------------------------------
// AES-GCM datapath: single shared aes_core, GHASH routing, 96-bit IV fast path.
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
    input  wire         aad_valid,
    output wire         aad_ready,
    input  wire         aad_last,
    input  wire [127:0] aad_data,
    input  wire [15:0]  aad_keep,
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
    reg [2:0]   phase_reg;
    reg [2:0]   phase_next;
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

    wire        start_pulse    = start && !start_d;
    wire        no_aad_start   = (len_aad_bits == 64'd0);
    wire        no_pld_start   = (len_pld_bits == 64'd0);
    wire        no_pld         = (len_pld_bits_reg == 64'd0);

    wire [127:0] aad_data_masked        = mask_block(aad_data, aad_keep);
    wire [127:0] payload_data_masked_in = mask_block(din_data, din_keep);

    // h_subkey shared AES interface
    wire [127:0] H_wire;
    wire         H_valid;
    wire         h_aes_req;
    wire         h_aes_gnt;
    wire         h_aes_init;
    wire         h_aes_next;
    wire [255:0] h_aes_key;
    wire         h_aes_keylen;
    wire [127:0] h_aes_block;
    wire         h_aes_ready;
    wire [127:0] h_aes_result;
    wire         h_aes_result_valid;

    // Tag mask shared AES interface
    wire         tagmask_busy;
    wire         tag_aes_req;
    wire         tag_aes_gnt;
    wire         tag_aes_init;
    wire         tag_aes_next;
    wire [255:0] tag_aes_key;
    wire         tag_aes_keylen;
    wire [127:0] tag_aes_block;
    wire         tag_aes_ready;
    wire [127:0] tag_aes_result;
    wire         tag_aes_result_valid;

    // CTR XOR datapath shared AES interface
    wire         ctr_keystream_req;
    wire         ctr_aes_req;
    wire         ctr_aes_gnt;
    wire         ctr_aes_init;
    wire         ctr_aes_next;
    wire [255:0] ctr_aes_key;
    wire         ctr_aes_keylen;
    wire [127:0] ctr_aes_block;
    wire         ctr_aes_ready;
    wire [127:0] ctr_aes_result;
    wire         ctr_aes_result_valid;

    // Counter generator outputs
    wire [127:0] ctr_block;
    wire         ctr_valid;

    // CTR XOR outputs
    wire         ctr_dout_valid;
    wire [127:0] ctr_dout_data;
    wire [15:0]  ctr_dout_keep;
    wire         ctr_dout_last;

    // GHASH interface
    wire         ghash_din_ready;
    wire [127:0] ghash_Y;
    wire         ghash_Y_valid;

    wire [127:0] len_block;

    reg          ghash_valid_int;
    reg [127:0]  ghash_data_int;
    reg          ghash_last_int;

    wire [127:0] payload_data_masked_out = mask_block(ctr_dout_data, ctr_dout_keep);
    wire         payload_channel_active  = (phase_reg == PH_PAYLOAD);
    wire         aad_handshake           = (phase_reg == PH_AAD) && ghash_valid_int;
    wire         aad_last_handshake      = aad_handshake && aad_last;
    wire         payload_din_handshake   = payload_channel_active && din_valid && din_ready;
    wire         payload_dout_handshake  = payload_channel_active && ctr_dout_valid && dout_ready;
    wire         load_pld_buf_dec        = !enc_mode_reg && payload_din_handshake && !pld_buf_valid_reg;
    wire         load_pld_buf_enc        =  enc_mode_reg && payload_dout_handshake && !pld_buf_valid_reg;
    wire         load_pld_buf            = load_pld_buf_dec | load_pld_buf_enc;
    wire [127:0] pld_buf_data_load       = load_pld_buf_dec ? payload_data_masked_in : payload_data_masked_out;
    wire         pld_buf_last_load       = load_pld_buf_dec ? din_last : ctr_dout_last;
    wire         consume_pld_buf         = payload_channel_active && pld_buf_valid_reg && ghash_din_ready;
    wire         consume_pld_buf_last    = consume_pld_buf && pld_buf_last_reg;
    wire         len_handshake           = (phase_reg == PH_LEN) && len_pending_reg && ghash_din_ready;
    wire         payload_last_handshake  = enc_mode_reg ? (payload_dout_handshake && ctr_dout_last)
                                                       : (payload_din_handshake && din_last);
    wire         dout_valid_rise         = ctr_dout_valid && !dout_valid_q;

    // AES core arbiter
    localparam CLIENT_H   = 2'd0;
    localparam CLIENT_TAG = 2'd1;
    localparam CLIENT_CTR = 2'd2;

    reg [1:0] grant_idx_reg;
    reg [1:0] grant_idx_next;
    reg       grant_active_reg;
    reg       grant_active_next;
    reg [1:0] rr_ptr_reg;
    reg [1:0] rr_ptr_next;

    reg        aes_init_mux;
    reg        aes_next_mux;
    reg [255:0] aes_key_mux;
    reg        aes_keylen_mux;
    reg [127:0] aes_block_mux;

    wire       aes_ready_core;
    wire [127:0] aes_result_core;
    wire       aes_result_valid_core;

    wire       req_h   = h_aes_req;
    wire       req_tag = tag_aes_req;
    wire       req_ctr = ctr_aes_req;

    function automatic [1:0] next_client;
        input [1:0] cur;
        begin
            case (cur)
                CLIENT_H:   next_client = CLIENT_TAG;
                CLIENT_TAG: next_client = CLIENT_CTR;
                default:    next_client = CLIENT_H;
            endcase
        end
    endfunction

    wire h_client_active   = grant_active_reg && (grant_idx_reg == CLIENT_H);
    wire tag_client_active = grant_active_reg && (grant_idx_reg == CLIENT_TAG);
    wire ctr_client_active = grant_active_reg && (grant_idx_reg == CLIENT_CTR);

    assign h_aes_gnt   = h_client_active;
    assign tag_aes_gnt = tag_client_active;
    assign ctr_aes_gnt = ctr_client_active;

    assign h_aes_ready        = h_client_active   ? aes_ready_core        : 1'b0;
    assign h_aes_result       = h_client_active   ? aes_result_core       : 128'h0;
    assign h_aes_result_valid = h_client_active   ? aes_result_valid_core : 1'b0;

    assign tag_aes_ready        = tag_client_active ? aes_ready_core        : 1'b0;
    assign tag_aes_result       = tag_client_active ? aes_result_core       : 128'h0;
    assign tag_aes_result_valid = tag_client_active ? aes_result_valid_core : 1'b0;

    assign ctr_aes_ready        = ctr_client_active ? aes_ready_core        : 1'b0;
    assign ctr_aes_result       = ctr_client_active ? aes_result_core       : 128'h0;
    assign ctr_aes_result_valid = ctr_client_active ? aes_result_valid_core : 1'b0;

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
            enc_mode_reg     <= 1'b0;
            len_aad_bits_reg <= 64'd0;
            len_pld_bits_reg <= 64'd0;
        end else if (start_pulse) begin
            enc_mode_reg     <= enc_mode;
            len_aad_bits_reg <= len_aad_bits;
            len_pld_bits_reg <= len_pld_bits;
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            H_reg <= 128'h0;
        end else if (H_valid) begin
            H_reg <= H_wire;
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
            if (ghash_init) begin
                tag_pre_xor_valid_reg <= 1'b0;
            end

            if (ghash_Y_valid) begin
                tag_pre_xor_reg       <= ghash_Y;
                tag_pre_xor_valid_reg <= 1'b1;
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            grant_idx_reg    <= CLIENT_H;
            grant_active_reg <= 1'b0;
            rr_ptr_reg       <= CLIENT_H;
        end else begin
            grant_idx_reg    <= grant_idx_next;
            grant_active_reg <= grant_active_next;
            rr_ptr_reg       <= rr_ptr_next;
        end
    end

    // ------------------------------------------------------------------
    // Combinational control
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
                // no data for GHASH
            end
        endcase
    end

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
                    // wait for start
                end

                PH_AAD: begin
                    if (aad_last_handshake) begin
                        if (no_pld) begin
                            phase_next = PH_LEN;
                        end else begin
                            phase_next = PH_PAYLOAD;
                        end
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

                default: begin
                    phase_next = PH_IDLE;
                end
            endcase
        end
    end

    always @* begin
        grant_idx_next    = grant_idx_reg;
        grant_active_next = grant_active_reg;
        rr_ptr_next       = rr_ptr_reg;

        if (grant_active_reg) begin
            case (grant_idx_reg)
                CLIENT_H: begin
                    if (!req_h) begin
                        grant_active_next = 1'b0;
                        rr_ptr_next       = next_client(grant_idx_reg);
                    end
                end

                CLIENT_TAG: begin
                    if (!req_tag) begin
                        grant_active_next = 1'b0;
                        rr_ptr_next       = next_client(grant_idx_reg);
                    end
                end

                default: begin
                    if (!req_ctr) begin
                        grant_active_next = 1'b0;
                        rr_ptr_next       = next_client(grant_idx_reg);
                    end
                end
            endcase
        end else begin
            if (req_h || req_tag || req_ctr) begin
                case (rr_ptr_reg)
                    CLIENT_H: begin
                        if (req_h) begin
                            grant_idx_next = CLIENT_H;
                        end else if (req_tag) begin
                            grant_idx_next = CLIENT_TAG;
                        end else begin
                            grant_idx_next = CLIENT_CTR;
                        end
                    end

                    CLIENT_TAG: begin
                        if (req_tag) begin
                            grant_idx_next = CLIENT_TAG;
                        end else if (req_ctr) begin
                            grant_idx_next = CLIENT_CTR;
                        end else begin
                            grant_idx_next = CLIENT_H;
                        end
                    end

                    default: begin
                        if (req_ctr) begin
                            grant_idx_next = CLIENT_CTR;
                        end else if (req_h) begin
                            grant_idx_next = CLIENT_H;
                        end else begin
                            grant_idx_next = CLIENT_TAG;
                        end
                    end
                endcase
                grant_active_next = 1'b1;
            end
        end
    end

    always @* begin
        aes_init_mux   = 1'b0;
        aes_next_mux   = 1'b0;
        aes_key_mux    = 256'h0;
        aes_keylen_mux = 1'b0;
        aes_block_mux  = 128'h0;

        if (grant_active_reg) begin
            case (grant_idx_reg)
                CLIENT_H: begin
                    aes_init_mux   = h_aes_init;
                    aes_next_mux   = h_aes_next;
                    aes_key_mux    = h_aes_key;
                    aes_keylen_mux = h_aes_keylen;
                    aes_block_mux  = h_aes_block;
                end

                CLIENT_TAG: begin
                    aes_init_mux   = tag_aes_init;
                    aes_next_mux   = tag_aes_next;
                    aes_key_mux    = tag_aes_key;
                    aes_keylen_mux = tag_aes_keylen;
                    aes_block_mux  = tag_aes_block;
                end

                default: begin
                    aes_init_mux   = ctr_aes_init;
                    aes_next_mux   = ctr_aes_next;
                    aes_key_mux    = ctr_aes_key;
                    aes_keylen_mux = ctr_aes_keylen;
                    aes_block_mux  = ctr_aes_block;
                end
            endcase
        end
    end

    // ------------------------------------------------------------------
    // Ready/valid signals to external world
    // ------------------------------------------------------------------
    assign aad_ready = (phase_reg == PH_AAD) && ghash_din_ready;

    assign din_ready = payload_channel_active &&
                       dout_ready &&
                       !payload_pending_reg &&
                       !ctr_dout_valid &&
                       !pld_buf_valid_reg;

    assign dout_valid = ctr_dout_valid;
    assign dout_data  = ctr_dout_data;
    assign dout_keep  = ctr_dout_keep;
    assign dout_last  = ctr_dout_last;

    assign tag_pre_xor = tag_pre_xor_reg;
    assign tag_pre_xor_valid = tag_pre_xor_valid_reg;
    assign aad_done    = aad_done_reg;
    assign pld_done    = pld_done_reg;
    assign lens_done   = lens_done_reg;

    // ------------------------------------------------------------------
    // Submodule instances
    // ------------------------------------------------------------------
    wire [127:0] H_active = H_valid ? H_wire : H_reg;
    wire         ghash_init = start_pulse || H_valid;

    h_subkey #(
        .SHARED_AES(1)
    ) u_h_subkey (
        .clk             (clk),
        .rst_n           (rst_n),
        .key_in          (key_in),
        .key_we          (key_we),
        .aes256_en       (aes256_en),
        .H               (H_wire),
        .H_valid         (H_valid),
        .aes_req         (h_aes_req),
        .aes_gnt         (h_aes_gnt),
        .aes_init        (h_aes_init),
        .aes_next        (h_aes_next),
        .aes_key         (h_aes_key),
        .aes_keylen      (h_aes_keylen),
        .aes_block       (h_aes_block),
        .aes_ready       (h_aes_ready),
        .aes_result      (h_aes_result),
        .aes_result_valid(h_aes_result_valid)
    );

    gcm_tagmask #(
        .SHARED_AES(1)
    ) u_gcm_tagmask (
        .clk             (clk),
        .rst_n           (rst_n),
        .key_in          (key_in),
        .key_we          (key_we),
        .aes256_en       (aes256_en),
        .iv_in           (iv_in),
        .iv_we           (iv_we),
        .start           (start),
        .mask            (tagmask),
        .mask_valid      (tagmask_valid),
        .busy            (tagmask_busy),
        .aes_req         (tag_aes_req),
        .aes_gnt         (tag_aes_gnt),
        .aes_init        (tag_aes_init),
        .aes_next        (tag_aes_next),
        .aes_key         (tag_aes_key),
        .aes_keylen      (tag_aes_keylen),
        .aes_block       (tag_aes_block),
        .aes_ready       (tag_aes_ready),
        .aes_result      (tag_aes_result),
        .aes_result_valid(tag_aes_result_valid)
    );

    ctr_xor #(
        .SHARED_AES(1)
    ) u_ctr_xor (
        .clk              (clk),
        .rst_n            (rst_n),
        .enc_mode         (enc_mode_reg),
        .key_in           (key_in),
        .key_we           (key_we),
        .aes256_en        (aes256_en),
        .ctr_block        (ctr_block),
        .ctr_valid        (ctr_valid),
        .din_valid        (payload_channel_active ? din_valid : 1'b0),
        .din_data         (din_data),
        .din_keep         (din_keep),
        .din_last         (payload_channel_active ? din_last : 1'b0),
        .dout_ready       (dout_ready),
        .keystream_req    (ctr_keystream_req),
        .dout_valid       (ctr_dout_valid),
        .dout_data        (ctr_dout_data),
        .dout_keep        (ctr_dout_keep),
        .dout_last        (ctr_dout_last),
        .aes_req          (ctr_aes_req),
        .aes_gnt          (ctr_aes_gnt),
        .aes_init         (ctr_aes_init),
        .aes_next         (ctr_aes_next),
        .aes_key          (ctr_aes_key),
        .aes_keylen       (ctr_aes_keylen),
        .aes_block        (ctr_aes_block),
        .aes_ready        (ctr_aes_ready),
        .aes_result       (ctr_aes_result),
        .aes_result_valid (ctr_aes_result_valid)
    );

    ctr_gen u_ctr_gen (
        .clk       (clk),
        .rst_n     (rst_n),
        .load_iv   (iv_we),
        .iv96      (iv_in),
        .next      (ctr_keystream_req),
        .ctr_block (ctr_block),
        .ctr_valid (ctr_valid)
    );

    gcm_lenblock u_gcm_lenblock (
        .len_aad_bits (len_aad_bits_reg),
        .len_ct_bits  (len_pld_bits_reg),
        .len_block    (len_block)
    );

    ghash_core u_ghash_core (
        .clk       (clk),
        .rst_n     (rst_n),
        .init      (ghash_init),
        .H         (H_active),
        .din_valid (ghash_valid_int),
        .din_ready (ghash_din_ready),
        .din_data  (ghash_data_int),
        .din_last  (ghash_last_int),
        .Y         (ghash_Y),
        .Y_valid   (ghash_Y_valid)
    );

    aes_core u_aes_core (
        .clk          (clk),
        .reset_n      (rst_n),
        .encdec       (1'b1),
        .init         (aes_init_mux),
        .next         (aes_next_mux),
        .ready        (aes_ready_core),
        .key          (aes_key_mux),
        .keylen       (aes_keylen_mux),
        .block        (aes_block_mux),
        .result       (aes_result_core),
        .result_valid (aes_result_valid_core)
    );

endmodule

