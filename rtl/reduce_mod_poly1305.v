`timescale 1ns/1ps
`default_nettype none

// Reduce value_in (258 bits) modulo p = 2^130 - 5
// Implementation: compute tmp = lo + 5*hi, then conditionally subtract p up to a few times.
// This ensures result < p. Done in one combinational reduction step followed by a single-cycle done pulse.
module reduce_mod_poly1305(
    input  wire         clk,
    input  wire         reset_n,
    input  wire         start,
    input  wire [257:0] value_in,
    output reg [129:0]  value_out,
    output reg          busy,
    output reg          done
);
    // p = 2^130 - 5 (131 bits to hold 2^130)
    localparam [130:0] P = ({1'b1, {130{1'b0}}}) - 131'd5;

    reg [257:0] val_reg;
    reg running;

    // intermediate wide tmp: need up to ~133 bits
    reg [132:0] tmp0, tmp1, tmp2, tmp3, tmp4;

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            val_reg   <= 258'b0;
            value_out <= 130'b0;
            busy      <= 1'b0;
            done      <= 1'b0;
            running   <= 1'b0;
            tmp0      <= 133'b0;
            tmp1      <= 133'b0;
            tmp2      <= 133'b0;
            tmp3      <= 133'b0;
            tmp4      <= 133'b0;
        end else begin
            // default: clear done pulse
            done <= 1'b0;

            if (start && !running) begin
                val_reg <= value_in;
                busy    <= 1'b1;
                running <= 1'b1;
            end else if (running) begin
                // compute lo + 5*hi
                // lo : bits [129:0]; hi : bits [257:130]
                tmp0 <= {3'b0, val_reg[129:0]} + ({5'b0, val_reg[257:130]} * 5);
                // Now do up-to-4 conditional subtractions of p to ensure < p
                // (We widen widths to avoid overflow)
                tmp1 <= (tmp0 >= {2'b0, P}) ? (tmp0 - {2'b0, P}) : tmp0;
                tmp2 <= (tmp1 >= {2'b0, P}) ? (tmp1 - {2'b0, P}) : tmp1;
                tmp3 <= (tmp2 >= {2'b0, P}) ? (tmp2 - {2'b0, P}) : tmp2;
                tmp4 <= (tmp3 >= {2'b0, P}) ? (tmp3 - {2'b0, P}) : tmp3;

                // final result fits in 130 bits
                value_out <= tmp4[129:0];
                busy <= 1'b0;
                done <= 1'b1;
                running <= 1'b0;
            end
        end
    end
endmodule

`default_nettype wire
