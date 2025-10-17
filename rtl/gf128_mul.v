`default_nettype none

// -----------------------------------------------------------------------------
// GF(2^128) carry-less multiplier (iterative, MSB-first processing)
// -----------------------------------------------------------------------------
module gf128_mul (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [127:0] a,
    input  wire [127:0] b,
    output wire         busy,
    output wire         done,
    output wire [255:0] p
);

    reg         busy_reg;
    reg         busy_next;
    reg         done_reg;
    reg         done_next;

    reg [7:0]   bit_cnt_reg;
    reg [7:0]   bit_cnt_next;
    reg [255:0] acc_reg;
    reg [255:0] acc_next;
    reg [255:0] a_shift_reg;
    reg [255:0] a_shift_next;
    reg [127:0] b_shift_reg;
    reg [127:0] b_shift_next;
    reg [255:0] p_reg;
    reg [255:0] p_next;

    reg [255:0] acc_tmp;

    assign busy = busy_reg;
    assign done = done_reg;
    assign p    = p_reg;

    // ------------------------------------------------------------------
    // Sequential state updates
    // ------------------------------------------------------------------
    wire mul_en = start | busy_reg | done_reg;  // update on start, while busy, and one cycle to clear done

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy_reg     <= 1'b0;
            done_reg     <= 1'b0;
            bit_cnt_reg  <= 8'd0;
            acc_reg      <= 256'h0;
            a_shift_reg  <= 256'h0;
            b_shift_reg  <= 128'h0;
            p_reg        <= 256'h0;
        end else if (mul_en) begin
            busy_reg     <= busy_next;
            done_reg     <= done_next;
            bit_cnt_reg  <= bit_cnt_next;
            acc_reg      <= acc_next;
            a_shift_reg  <= a_shift_next;
            b_shift_reg  <= b_shift_next;
            p_reg        <= p_next;
        end
    end

    // ------------------------------------------------------------------
    // Next-state logic
    // ------------------------------------------------------------------
    always @* begin
        busy_next     = busy_reg;
        done_next     = 1'b0;
        bit_cnt_next  = bit_cnt_reg;
        acc_next      = acc_reg;
        a_shift_next  = a_shift_reg;
        b_shift_next  = b_shift_reg;
        p_next        = p_reg;
        acc_tmp       = acc_reg;

        if (!busy_reg) begin
            if (start) begin
                busy_next     = 1'b1;
                bit_cnt_next  = 8'd0;
                acc_next      = 256'h0;
                a_shift_next  = {1'b0, a, 127'b0};
                b_shift_next  = b;
            end
        end else begin
            if (b_shift_reg[127]) begin
                acc_tmp = acc_tmp ^ a_shift_reg;
            end

            acc_next     = acc_tmp;
            a_shift_next = {1'b0, a_shift_reg[255:1]};
            b_shift_next = {b_shift_reg[126:0], 1'b0};

            if (bit_cnt_reg == 8'd127) begin
                busy_next    = 1'b0;
                done_next    = 1'b1;
                p_next       = acc_tmp;
            end else begin
                bit_cnt_next = bit_cnt_reg + 8'd1;
            end
        end
    end

endmodule

`default_nettype wire
