// -----------------------------------------------------------------------------
// CTR XOR datapath: encrypts counter blocks, XORs with payload stream.
// Supports optional sharing of an external aes_core instance.
// -----------------------------------------------------------------------------
module ctr_xor #(
    parameter SHARED_AES = 0
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         enc_mode,
    input  wire [255:0] key_in,
    input  wire         key_we,
    input  wire         aes256_en,
    input  wire [127:0] ctr_block,
    input  wire         ctr_valid,
    input  wire         din_valid,
    input  wire [127:0] din_data,
    input  wire [15:0]  din_keep,
    input  wire         din_last,
    input  wire         dout_ready,
    output wire         keystream_req,
    output wire         dout_valid,
    output wire [127:0] dout_data,
    output wire [15:0]  dout_keep,
    output wire         dout_last,
    // Shared AES interface (used when SHARED_AES != 0)
    output wire         aes_req,
    input  wire         aes_gnt,
    output wire         aes_init,
    output wire         aes_next,
    output wire [255:0] aes_key,
    output wire         aes_keylen,
    output wire [127:0] aes_block,
    input  wire         aes_ready,
    input  wire [127:0] aes_result,
    input  wire         aes_result_valid
);

    localparam ST_IDLE       = 3'd0;
    localparam ST_KEY_INIT   = 3'd1;
    localparam ST_WAIT_INIT  = 3'd2;
    localparam ST_WAIT_CTR   = 3'd3;
    localparam ST_WAIT_GRANT = 3'd4;
    localparam ST_ISSUE_NEXT = 3'd5;
    localparam ST_WAIT_RES   = 3'd6;

    reg [2:0]   state_reg;
    reg [2:0]   state_next;

    reg [255:0] key_active_reg;
    reg [255:0] key_active_next;
    reg         keylen_active_reg;
    reg         keylen_active_next;

    reg [255:0] key_queue_reg;
    reg [255:0] key_queue_next;
    reg         keylen_queue_reg;
    reg         keylen_queue_next;
    reg         queue_valid_reg;
    reg         queue_valid_next;

    reg         key_init_pending_reg;
    reg         key_init_pending_next;

    reg [127:0] block_reg;
    reg [127:0] block_next;

    reg         keystream_req_reg;
    reg            assign keystream_req = keystream_req_next;

    wire [255:0] sanitized_key    = aes256_en ? key_in : {128'h0, key_in[127:0]};
    wire         sanitized_keylen = aes256_en;

    wire         have_grant = (SHARED_AES != 0) ? aes_gnt : 1'b1;

    wire         core_init = (state_reg == ST_KEY_INIT);
    wire         core_next = (state_reg == ST_ISSUE_NEXT);

    wire         core_ready;
    wire [127:0] core_result;
    wire         core_result_valid;

    // ------------------------------------------------------------------
    // Payload staging (single-block buffer)
    // ------------------------------------------------------------------
    reg         payload_valid_reg;
    reg [127:0] payload_data_reg;
    reg [15:0]  payload_keep_reg;
    reg         payload_last_reg;
    reg         payload_enc_reg;

    wire accept_payload = din_valid && dout_ready && !payload_valid_reg && !dout_valid_reg;
    wire clear_payload  = core_result_valid;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            payload_valid_reg <= 1'b0;
            payload_data_reg  <= 128'h0;
            payload_keep_reg  <= 16'h0;
            payload_last_reg  <= 1'b0;
            payload_enc_reg   <= 1'b0;
        end else begin
            if (accept_payload) begin
                payload_valid_reg <= 1'b1;
                payload_data_reg  <= din_data;
                payload_keep_reg  <= din_keep;
                payload_last_reg  <= din_last;
                payload_enc_reg   <= enc_mode;
            end else if (clear_payload) begin
                payload_valid_reg <= 1'b0;
            end
        end
    end

    // ------------------------------------------------------------------
    // Output registers for back-pressure
    // ------------------------------------------------------------------
    reg         dout_valid_reg;
    reg [127:0] dout_data_reg;
    reg [15:0]  dout_keep_reg;
    reg         dout_last_reg;

    reg [127:0] xor_result;
    integer idx;

    always @* begin
        xor_result = payload_data_reg;
        for (idx = 0; idx < 16; idx = idx + 1) begin
            if (payload_keep_reg[idx]) begin
                xor_result[idx*8 +: 8] = payload_data_reg[idx*8 +: 8] ^ core_result[idx*8 +: 8];
            end else if (payload_enc_reg) begin
                xor_result[idx*8 +: 8] = 8'h00;
            end else begin
                xor_result[idx*8 +: 8] = payload_data_reg[idx*8 +: 8];
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            dout_valid_reg <= 1'b0;
            dout_data_reg  <= 128'h0;
            dout_keep_reg  <= 16'h0;
            dout_last_reg  <= 1'b0;
        end else begin
            if (core_result_valid) begin
                dout_valid_reg <= 1'b1;
                dout_data_reg  <= xor_result;
                dout_keep_reg  <= payload_keep_reg;
                dout_last_reg  <= payload_last_reg;
            end else if (dout_valid_reg && dout_ready) begin
                dout_valid_reg <= 1'b0;
            end
        end
    end

    assign dout_valid = dout_valid_reg;
    assign dout_data  = dout_data_reg;
    assign dout_keep  = dout_keep_reg;
    assign dout_last  = dout_last_reg;

    // ------------------------------------------------------------------
    // Key management and state machine registers
    // ------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_reg            <= ST_IDLE;
            key_active_reg       <= 256'h0;
            keylen_active_reg    <= 1'b0;
            key_queue_reg        <= 256'h0;
            keylen_queue_reg     <= 1'b0;
            queue_valid_reg      <= 1'b0;
            key_init_pending_reg <= 1'b0;
            block_reg            <= 128'h0;
            keystream_req_reg    <= 1'b0;
        end else begin
            state_reg            <= state_next;
            key_active_reg       <= key_active_next;
            keylen_active_reg    <= keylen_active_next;
            key_queue_reg        <= key_queue_next;
            keylen_queue_reg     <= keylen_queue_next;
            queue_valid_reg      <= queue_valid_next;
            key_init_pending_reg <= key_init_pending_next;
            block_reg            <= block_next;
            keystream_req_reg    <=    assign keystream_req = keystream_req_next;
        end
    end

    // ------------------------------------------------------------------
    // Combinational control (AES + CTR coordination)
    // ------------------------------------------------------------------
    always @* begin
        state_next            = state_reg;
        key_active_next       = key_active_reg;
        keylen_active_next    = keylen_active_reg;
        key_queue_next        = key_queue_reg;
        keylen_queue_next     = keylen_queue_reg;
        queue_valid_next      = queue_valid_reg;
        key_init_pending_next = key_init_pending_reg;
        block_next            = block_reg;
        keystream_req_next    = 1'b0;

        // Promote queued key when idle and no pending init
        if ((state_reg == ST_IDLE) && !key_init_pending_next && queue_valid_reg) begin
            key_active_next       = key_queue_reg;
            keylen_active_next    = keylen_queue_reg;
            key_init_pending_next = 1'b1;
            queue_valid_next      = 1'b0;
        end

        // Capture new key writes
        if (key_we) begin
            if ((state_reg == ST_IDLE) && !key_init_pending_next) begin
                key_active_next       = sanitized_key;
                keylen_active_next    = sanitized_keylen;
                key_init_pending_next = 1'b1;
            end else begin
                key_queue_next    = sanitized_key;
                keylen_queue_next = sanitized_keylen;
                queue_valid_next  = 1'b1;
            end
        end

        case (state_reg)
            ST_IDLE: begin
                if (key_init_pending_next) begin
                    if (have_grant) begin
                        state_next            = ST_KEY_INIT;
                        key_init_pending_next = 1'b0;
                    end
                end else if (payload_valid_reg && !dout_valid_reg) begin
                    keystream_req_next = 1'b1;
                    state_next         = ST_WAIT_CTR;
                end
            end

            ST_KEY_INIT: begin
                state_next = ST_WAIT_INIT;
            end

            ST_WAIT_INIT: begin
                if (core_ready) begin
                    state_next = ST_IDLE;
                end
            end

            ST_WAIT_CTR: begin
                if (ctr_valid) begin
                    block_next = ctr_block;
                    if (have_grant) begin
                        state_next = ST_ISSUE_NEXT;
                    end else begin
                        state_next = ST_WAIT_GRANT;
                    end
                end else begin
                    keystream_req_next = 1'b1;
                end
            end

            ST_WAIT_GRANT: begin
                if (have_grant) begin
                    state_next = ST_ISSUE_NEXT;
                end
            end

            ST_ISSUE_NEXT: begin\n                keystream_req_next = 1'b0;\n                state_next         = ST_WAIT_RES;\n            end

            ST_WAIT_RES: begin
                if (core_result_valid) begin\n                    if (queue_valid_reg) begin\n                        key_active_next       = key_queue_reg;\n                        keylen_active_next    = keylen_queue_reg;\n                        queue_valid_next      = 1'b0;\n                        key_init_pending_next = 1'b1;\n                    end\n                    state_next = ST_IDLE;\n                end
            end

            default: begin
                state_next = ST_IDLE;
            end
        endcase
    end

    assign keystream_req = keystream_req_next;|    assign keystream_req = keystream_req_next;

    // ------------------------------------------------------------------
    // AES core hookup (internal or shared)
    // ------------------------------------------------------------------
    wire        core_ready_int;
    wire [127:0] core_result_int;
    wire        core_result_valid_int;

    generate
        if (SHARED_AES == 0) begin : gen_internal_aes
            aes_core u_aes_core (
                .clk          (clk),
                .reset_n      (rst_n),
                .encdec       (1'b1),
                .init         (core_init),
                .next         (core_next),
                .ready        (core_ready_int),
                .key          (key_active_reg),
                .keylen       (keylen_active_reg),
                .block        (block_reg),
                .result       (core_result_int),
                .result_valid (core_result_valid_int)
            );
        end else begin : gen_shared_aes
            assign core_ready_int        = 1'b0;
            assign core_result_int       = 128'h0;
            assign core_result_valid_int = 1'b0;
        end
    endgenerate

    assign core_ready        = (SHARED_AES == 0) ? core_ready_int : aes_ready;
    assign core_result       = (SHARED_AES == 0) ? core_result_int : aes_result;
    assign core_result_valid = (SHARED_AES == 0) ? core_result_valid_int : aes_result_valid;

    assign aes_block  = (SHARED_AES != 0) ? block_reg : 128'h0;
    assign aes_key    = (SHARED_AES != 0) ? key_active_reg : 256'h0;
    assign aes_keylen = (SHARED_AES != 0) ? keylen_active_reg : 1'b0;
    assign aes_init   = (SHARED_AES != 0) ? core_init : 1'b0;
    assign aes_next   = (SHARED_AES != 0) ? core_next : 1'b0;
    assign aes_req    = (SHARED_AES != 0) ? (queue_valid_reg | key_init_pending_reg | (state_reg != ST_IDLE) | (state_next != ST_IDLE)) : 1'b0;

endmodule


