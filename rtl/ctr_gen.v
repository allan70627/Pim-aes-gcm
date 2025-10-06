// -----------------------------------------------------------------------------
// CTR generator for AES-GCM
// -----------------------------------------------------------------------------
module ctr_gen (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         load_iv,
    input  wire [95:0]  iv96,
    input  wire         next,
    output wire [127:0] ctr_block,
    output wire         ctr_valid
);

    reg [127:0] ctr_reg;
    reg [127:0] ctr_block_r;
    reg         ctr_valid_r;

    assign ctr_block = ctr_block_r;
    assign ctr_valid = ctr_valid_r;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ctr_reg     <= 128'h0;
            ctr_block_r <= 128'h0;
            ctr_valid_r <= 1'b0;
        end else begin
            ctr_valid_r <= 1'b0;

            if (load_iv) begin
                ctr_reg     <= {iv96, 32'h00000001};
                ctr_block_r <= {iv96, 32'h00000002};
            end else if (next) begin
                ctr_reg     <= {ctr_reg[127:32], ctr_reg[31:0] + 32'd1};
                ctr_block_r <= {ctr_reg[127:32], ctr_reg[31:0] + 32'd1};
                ctr_valid_r <= 1'b1;
            end
        end
    end

endmodule
