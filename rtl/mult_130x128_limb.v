`timescale 1ns/1ps
`default_nettype none

// Optimized 130x128 multiplier: 10-cycle latency
module mult_130x128_limb_fast(
    input  wire         clk,
    input  wire         reset_n,
    input  wire         start,
    input  wire [129:0] a_in,
    input  wire [127:0] b_in,
    output reg  [257:0] product_out,
    output reg          busy,
    output reg          done
);
    // 16 partial products: 8-bit chunks of B
    reg [7:0] b_chunks [0:15];
    reg [129:0] a_reg;
    reg [257:0] partials [0:15];
    reg [3:0] cycle;
    reg running;

    integer i;

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            product_out <= 0;
            busy <= 0;
            done <= 0;
            a_reg <= 0;
            cycle <= 0;
            running <= 0;
            for (i=0;i<16;i=i+1) b_chunks[i]<=0;
        end else begin
            done <= 0;

            if (start && !running) begin
                a_reg <= a_in;
                for(i=0;i<16;i=i+1)
                    b_chunks[i] <= b_in[i*8 +: 8];
                cycle <= 0;
                running <= 1;
                busy <= 1;
            end else if (running) begin
                // Generate partial product each cycle
                partials[cycle] <= a_reg * b_chunks[cycle]; // 130x8 => 138 bits
                cycle <= cycle + 1;

                if (cycle == 4'd9) begin // 10 cycles
                    // accumulate shifted partials
                    product_out <=
                        ({partials[15],120'b0} + {partials[14],112'b0} +
                         {partials[13],104'b0} + {partials[12],96'b0} +
                         {partials[11],88'b0} + {partials[10],80'b0} +
                         {partials[9],72'b0} + {partials[8],64'b0} +
                         {partials[7],56'b0} + {partials[6],48'b0} +
                         {partials[5],40'b0} + {partials[4],32'b0} +
                         {partials[3],24'b0} + {partials[2],16'b0} +
                         {partials[1],8'b0} + partials[0]);
                    busy <= 0;
                    done <= 1;
                    running <= 0;
                end
            end
        end
    end
endmodule

`default_nettype wire
