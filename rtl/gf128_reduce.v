`default_nettype none

// -----------------------------------------------------------------------------
// GF(2^128) reduction modulo x^128 + x^7 + x^2 + x + 1
// -----------------------------------------------------------------------------
module gf128_reduce (
    input  wire [255:0] p,
    output reg  [127:0] r
);

    integer idx;
    reg [255:0] tmp;

    always @* begin
        tmp = p;

        for (idx = 255; idx >= 128; idx = idx - 1) begin
            if (tmp[idx]) begin
                tmp[idx]                 = 1'b0;
                tmp[idx - 128]           = tmp[idx - 128] ^ 1'b1;
                tmp[idx - 128 + 1]       = tmp[idx - 128 + 1] ^ 1'b1;
                tmp[idx - 128 + 2]       = tmp[idx - 128 + 2] ^ 1'b1;
                tmp[idx - 128 + 7]       = tmp[idx - 128 + 7] ^ 1'b1;
            end
        end

        r = tmp[127:0];
    end

endmodule

`default_nettype wire
