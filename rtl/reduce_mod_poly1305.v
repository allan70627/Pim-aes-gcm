`timescale 1ns/1ps
`default_nettype none

module reduce_mod_poly1305(
    input  wire         clk,
    input  wire         reset_n,
    input  wire         start,
    input  wire [257:0] value_in,
    output reg [129:0]  value_out,
    output reg          busy,
    output reg          done
);
    localparam [130:0] P = ({1'b1, {130{1'b0}}}) - 131'd5;

    reg [257:0] val_reg;
    reg [132:0] stage1, stage2;
    reg running;

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            value_out <= 0;
            busy <= 0;
            done <= 0;
            val_reg <= 0;
            stage1 <= 0;
            stage2 <= 0;
            running <= 0;
        end else begin
            done <= 0;

            if (start && !running) begin
                val_reg <= value_in;
                running <= 1;
                busy <= 1;
            end else if (running) begin
                // Stage 1: lo + 5*hi
                stage1 <= {3'b0, val_reg[129:0]} + ({5'b0, val_reg[257:130]} * 5);
                // Stage 2: conditional subtractions
                stage2 <= (stage1 >= {2'b0, P}) ? (stage1 - {2'b0, P}) : stage1;
                value_out <= stage2[129:0];
                running <= 0;
                busy <= 0;
                done <= 1;
            end
        end
    end
endmodule

`default_nettype wire

