// -----------------------------------------------------------------------------
// GHASH subkey generator: computes H = AES(K, 0^128) whenever a new key arrives
// -----------------------------------------------------------------------------
module h_subkey (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key_in,
    input  wire         key_we,
    input  wire         aes256_en,
    output wire [127:0] H,
    output wire         H_valid
);

    localparam ST_IDLE       = 3'd0;
    localparam ST_ISSUE_INIT = 3'd1;
    localparam ST_WAIT_INIT  = 3'd2;
    localparam ST_ISSUE_NEXT = 3'd3;
    localparam ST_WAIT_RES   = 3'd4;

    reg [2:0] state_reg;
    reg [2:0] state_next;

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

    reg         compute_pending_reg;
    reg         compute_pending_next;

    reg [127:0] h_reg;
    reg [127:0] h_next;
    reg         h_valid_reg;
    reg         h_valid_next;

    wire        core_init;
    wire        core_next;
    wire        core_ready;
    wire [127:0] core_result;
    wire        core_result_valid;

    wire [255:0] sanitized_key    = aes256_en ? key_in : {128'h0, key_in[127:0]};
    wire         sanitized_keylen = aes256_en;

    assign H       = h_reg;
    assign H_valid = h_valid_reg;

    assign core_init = (state_reg == ST_ISSUE_INIT);
    assign core_next = (state_reg == ST_ISSUE_NEXT);

    // ------------------------------------------------------------------
    // State and data register update
    // ------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_reg           <= ST_IDLE;
            key_active_reg      <= 256'h0;
            keylen_active_reg   <= 1'b0;
            key_queue_reg       <= 256'h0;
            keylen_queue_reg    <= 1'b0;
            queue_valid_reg     <= 1'b0;
            compute_pending_reg <= 1'b0;
            h_reg               <= 128'h0;
            h_valid_reg         <= 1'b0;
        end else begin
            state_reg           <= state_next;
            key_active_reg      <= key_active_next;
            keylen_active_reg   <= keylen_active_next;
            key_queue_reg       <= key_queue_next;
            keylen_queue_reg    <= keylen_queue_next;
            queue_valid_reg     <= queue_valid_next;
            compute_pending_reg <= compute_pending_next;
            h_reg               <= h_next;
            h_valid_reg         <= h_valid_next;
        end
    end

    // ------------------------------------------------------------------
    // Next-state and control logic
    // ------------------------------------------------------------------
    always @* begin
        state_next           = state_reg;
        key_active_next      = key_active_reg;
        keylen_active_next   = keylen_active_reg;
        key_queue_next       = key_queue_reg;
        keylen_queue_next    = keylen_queue_reg;
        queue_valid_next     = queue_valid_reg;
        compute_pending_next = compute_pending_reg;
        h_next               = h_reg;
        h_valid_next         = 1'b0;

        if (key_we) begin
            if ((state_reg == ST_IDLE) && !compute_pending_reg) begin
                key_active_next      = sanitized_key;
                keylen_active_next   = sanitized_keylen;
                compute_pending_next = 1'b1;
                queue_valid_next     = 1'b0;
            end else begin
                key_queue_next    = sanitized_key;
                keylen_queue_next = sanitized_keylen;
                queue_valid_next  = 1'b1;
            end
        end

        if ((state_reg == ST_IDLE) && !compute_pending_next && queue_valid_next) begin
            key_active_next      = key_queue_next;
            keylen_active_next   = keylen_queue_next;
            compute_pending_next = 1'b1;
            queue_valid_next     = 1'b0;
        end

        case (state_reg)
            ST_IDLE: begin
                if (compute_pending_next) begin
                    state_next           = ST_ISSUE_INIT;
                    compute_pending_next = 1'b0;
                end
            end

            ST_ISSUE_INIT: begin
                state_next = ST_WAIT_INIT;
            end

            ST_WAIT_INIT: begin
                if (core_ready) begin
                    state_next = ST_ISSUE_NEXT;
                end
            end

            ST_ISSUE_NEXT: begin
                state_next = ST_WAIT_RES;
            end

            ST_WAIT_RES: begin
                if (core_result_valid) begin
                    h_next       = core_result;
                    h_valid_next = 1'b1;

                    if (queue_valid_next) begin
                        key_active_next      = key_queue_next;
                        keylen_active_next   = keylen_queue_next;
                        compute_pending_next = 1'b1;
                        queue_valid_next     = 1'b0;
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
    // AES core instance (encryption path only)
    // ------------------------------------------------------------------
    aes_core u_aes_core (
        .clk          (clk),
        .reset_n      (rst_n),
        .encdec       (1'b1),
        .init         (core_init),
        .next         (core_next),
        .ready        (core_ready),
        .key          (key_active_reg),
        .keylen       (keylen_active_reg),
        .block        (128'h0),
        .result       (core_result),
        .result_valid (core_result_valid)
    );

endmodule
