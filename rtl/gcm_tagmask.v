// -----------------------------------------------------------------------------
// Computes the GCM tag mask AES_enc(K, J0) with fast-path J0 for 96-bit IVs.
// Supports optional sharing of an external aes_core instance.
// -----------------------------------------------------------------------------
module gcm_tagmask #(
    parameter SHARED_AES = 0
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key_in,
    input  wire         key_we,
    input  wire         aes256_en,
    input  wire [95:0]  iv_in,
    input  wire         iv_we,
    input  wire         start,
    output wire [127:0] mask,
    output wire         mask_valid,
    output wire         busy,
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
    localparam ST_ISSUE_NEXT = 3'd3;
    localparam ST_WAIT_RES   = 3'd4;

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

    reg         start_pending_reg;
    reg         start_pending_next;

    reg [95:0]  iv_reg;
    reg [95:0]  iv_next;

    reg [127:0] block_reg;
    reg [127:0] block_next;

    reg [127:0] mask_reg;
    reg [127:0] mask_next;
    reg         mask_valid_reg;
    reg         mask_valid_next;

    wire [255:0] sanitized_key    = aes256_en ? key_in : {128'h0, key_in[127:0]};
    wire         sanitized_keylen = aes256_en;

    wire         have_grant = (SHARED_AES != 0) ? aes_gnt : 1'b1;

    wire         core_init = (state_reg == ST_KEY_INIT);
    wire         core_next = (state_reg == ST_ISSUE_NEXT);

    wire         core_ready;
    wire [127:0] core_result;
    wire         core_result_valid;

    assign mask       = mask_reg;
    assign mask_valid = mask_valid_reg;
    assign busy       = (state_reg != ST_IDLE) || key_init_pending_reg || start_pending_reg;

    assign aes_block  = (SHARED_AES != 0) ? block_reg : 128'h0;
    assign aes_key    = (SHARED_AES != 0) ? key_active_reg : 256'h0;
    assign aes_keylen = (SHARED_AES != 0) ? keylen_active_reg : 1'b0;
    assign aes_init   = (SHARED_AES != 0) ? core_init : 1'b0;
    assign aes_next   = (SHARED_AES != 0) ? core_next : 1'b0;
    assign aes_req    = (SHARED_AES != 0) ? (queue_valid_reg | key_init_pending_reg | start_pending_reg | (state_reg != ST_IDLE)) : 1'b0;

    // ------------------------------------------------------------------
    // Sequential state update
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
            start_pending_reg    <= 1'b0;
            iv_reg               <= 96'h0;
            block_reg            <= 128'h0;
            mask_reg             <= 128'h0;
            mask_valid_reg       <= 1'b0;
        end else begin
            state_reg            <= state_next;
            key_active_reg       <= key_active_next;
            keylen_active_reg    <= keylen_active_next;
            key_queue_reg        <= key_queue_next;
            keylen_queue_reg     <= keylen_queue_next;
            queue_valid_reg      <= queue_valid_next;
            key_init_pending_reg <= key_init_pending_next;
            start_pending_reg    <= start_pending_next;
            iv_reg               <= iv_next;
            block_reg            <= block_next;
            mask_reg             <= mask_next;
            mask_valid_reg       <= mask_valid_next;
        end
    end

    // ------------------------------------------------------------------
    // Combinational control
    // ------------------------------------------------------------------
    always @* begin
        state_next            = state_reg;
        key_active_next       = key_active_reg;
        keylen_active_next    = keylen_active_reg;
        key_queue_next        = key_queue_reg;
        keylen_queue_next     = keylen_queue_reg;
        queue_valid_next      = queue_valid_reg;
        key_init_pending_next = key_init_pending_reg;
        start_pending_next    = start_pending_reg | start;
        iv_next               = iv_reg;
        block_next            = block_reg;
        mask_next             = mask_reg;
        mask_valid_next       = 1'b0;

        if (iv_we) begin
            iv_next = iv_in;
        end

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
                end else if (start_pending_next) begin
                    if (have_grant) begin
                        block_next         = {iv_reg, 32'h00000001};
                        state_next         = ST_ISSUE_NEXT;
                        start_pending_next = 1'b0;
                    end
                end
            end

            ST_KEY_INIT: begin
                state_next = ST_WAIT_INIT;
            end

            ST_WAIT_INIT: begin
                if (core_ready) begin
                    if (start_pending_next) begin
                        block_next         = {iv_reg, 32'h00000001};
                        state_next         = ST_ISSUE_NEXT;
                        start_pending_next = 1'b0;
                    end else begin
                        state_next = ST_IDLE;
                    end
                end
            end

            ST_ISSUE_NEXT: begin
                state_next = ST_WAIT_RES;
            end

            ST_WAIT_RES: begin
                if (core_result_valid) begin
                    mask_next       = core_result;
                    mask_valid_next = 1'b1;

                    if (queue_valid_reg) begin
                        key_active_next       = key_queue_reg;
                        keylen_active_next    = keylen_queue_reg;
                        queue_valid_next      = 1'b0;
                        key_init_pending_next = 1'b1;
                    end

                    state_next = ST_IDLE;
                end
            end

            default: begin
                state_next = ST_IDLE;
            end
        endcase
    end

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

endmodule
