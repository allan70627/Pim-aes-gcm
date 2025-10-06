`default_nettype none

// -----------------------------------------------------------------------------
// Streaming GHASH core: Y_i = (Y_{i-1} XOR X_i) * H mod (x^128 + x^7 + x^2 + x + 1)
// -----------------------------------------------------------------------------
module ghash_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         init,
    input  wire [127:0] H,
    input  wire         din_valid,
    output wire         din_ready,
    input  wire [127:0] din_data,
    input  wire         din_last,
    output wire [127:0] Y,
    output wire         Y_valid
);

    localparam ST_IDLE  = 2'd0;
    localparam ST_START = 2'd1;
    localparam ST_WAIT  = 2'd2;

    reg [1:0]   state_reg;
    reg [1:0]   state_next;
    reg [127:0] y_reg;
    reg [127:0] y_next;
    reg [127:0] H_reg;
    reg [127:0] H_next;
    reg [127:0] operand_reg;
    reg [127:0] operand_next;
    reg         last_reg;
    reg         last_next;
    reg         Y_valid_reg;
    reg         Y_valid_next;
    reg         mul_start;

    wire        mul_done;
    wire [255:0] mul_product;
    wire [127:0] mul_reduced;

    assign din_ready = (state_reg == ST_IDLE) && !init;
    assign Y         = y_reg;
    assign Y_valid   = Y_valid_reg;

    // ------------------------------------------------------------------
    // Sequential state updates
    // ------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_reg     <= ST_IDLE;
            y_reg         <= 128'h0;
            H_reg         <= 128'h0;
            operand_reg   <= 128'h0;
            last_reg      <= 1'b0;
            Y_valid_reg   <= 1'b0;
        end else begin
            state_reg     <= state_next;
            y_reg         <= y_next;
            H_reg         <= H_next;
            operand_reg   <= operand_next;
            last_reg      <= last_next;
            Y_valid_reg   <= Y_valid_next;
        end
    end

    // ------------------------------------------------------------------
    // Control logic
    // ------------------------------------------------------------------
    always @* begin
        state_next   = state_reg;
        y_next       = y_reg;
        H_next       = H_reg;
        operand_next = operand_reg;
        last_next    = last_reg;
        Y_valid_next = 1'b0;
        mul_start    = 1'b0;

        if (init) begin
            state_next   = ST_IDLE;
            y_next       = 128'h0;
            H_next       = H;
            operand_next = 128'h0;
            last_next    = 1'b0;
        end else begin
            case (state_reg)
                ST_IDLE: begin
                    if (din_valid && din_ready) begin
                        operand_next = y_reg ^ din_data;
                        last_next    = din_last;
                        state_next   = ST_START;
                    end
                end

                ST_START: begin
                    mul_start  = 1'b1;
                    state_next = ST_WAIT;
                end

                ST_WAIT: begin
                    if (mul_done) begin
                        y_next       = mul_reduced;
                        Y_valid_next = last_reg;
                        last_next    = 1'b0;
                        state_next   = ST_IDLE;
                    end
                end

                default: begin
                    state_next = ST_IDLE;
                end
            endcase
        end
    end

    // ------------------------------------------------------------------
    // GF(2^128) multiply and reduction
    // ------------------------------------------------------------------
    gf128_mul u_gf128_mul (
        .clk   (clk),
        .rst_n (rst_n),
        .start (mul_start),
        .a     (operand_reg),
        .b     (H_reg),
        .busy  (),
        .done  (mul_done),
        .p     (mul_product)
    );

    gf128_reduce u_gf128_reduce (
        .p (mul_product),
        .r (mul_reduced)
    );

endmodule

`default_nettype wire
