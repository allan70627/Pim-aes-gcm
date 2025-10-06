`default_nettype none

module h_subkey (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key_in,
    input  wire         key_we,
    input  wire         aes256_en,
    // Request to centralized AES
    output reg          h_req,
    input  wire         h_ack,
    // Result from centralized AES
    input  wire [127:0] H_in,
    input  wire         H_in_valid,
    output reg  [127:0] H,
    output reg          H_valid,
    output reg          h_busy
);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            h_req   <= 1'b0;
            H       <= 128'h0;
            H_valid <= 1'b0;
            h_busy  <= 1'b0;
        end else begin
            H_valid <= 1'b0; // pulse on new value
            if (key_we) begin
                h_req  <= 1'b1;
                h_busy <= 1'b1;
            end else if (h_ack) begin
                h_req  <= 1'b0;
            end

            if (H_in_valid) begin
                H       <= H_in;
                H_valid <= 1'b1;
                h_busy  <= 1'b0;
            end
        end
    end

endmodule

`default_nettype wire



