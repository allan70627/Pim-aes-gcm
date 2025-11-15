`timescale 1ns/1ps
`default_nettype none

// Limb multiplier: A (130 bits) * B (128 bits) -> 258 bits
// Iterative shift-add multiplier, 1 bit of B per cycle (128 cycles)
module mult_130x128_limb(
    input  wire         clk,
    input  wire         reset_n,
    input  wire         start,
    input  wire [129:0] a_in,       // 130-bit (A)
    input  wire [127:0] b_in,       // 128-bit (B)
    output reg [257:0] product_out, // 258-bit
    output reg          busy,
    output reg          done
);
    reg [257:0] acc;
    reg [257:0] a_shift;   // holds A aligned for add (258 bits)
    reg [127:0] b_reg;
    reg [7:0]  bit_idx;
    reg running;

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            acc         <= 258'b0;
            a_shift     <= 258'b0;
            b_reg       <= 128'b0;
            bit_idx     <= 8'd0;
            product_out <= 258'b0;
            busy        <= 1'b0;
            done        <= 1'b0;
            running     <= 1'b0;
        end else begin
            // default: clear done pulse
            done <= 1'b0;

            if (start && !running) begin
                // capture operands, begin iterative multiply
                acc     <= 258'b0;
                a_shift <= {128'b0, a_in}; // align 130-bit A into 258-bit shifter
                b_reg   <= b_in;
                bit_idx <= 8'd0;
                busy    <= 1'b1;
                running <= 1'b1;
            end else if (running) begin
                // one iteration per cycle: if lsb of b_reg is 1 add a_shift
                if (b_reg[0]) acc <= acc + a_shift;
                a_shift <= a_shift << 1;
                b_reg   <= b_reg >> 1;
                bit_idx <= bit_idx + 1'b1;

                // when we've processed 128 bits of B (0..127), finish
                if (bit_idx == 8'd127) begin
                    product_out <= acc; // final product available this cycle
                    busy        <= 1'b0;
                    done        <= 1'b1; // single-cycle done pulse
                    running     <= 1'b0;
                end
            end
        end
    end
endmodule

`default_nettype wire

