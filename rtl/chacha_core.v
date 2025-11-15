module chacha_core(
    input  wire clk,
    input  wire reset_n,
    input  wire init,
    input  wire next,
    input  wire [255:0] key,
    input  wire [63:0] ctr,
    input  wire [63:0] iv,
    input  wire [511:0] data_in,
    output reg  ready,
    output reg  data_out_valid,
    output reg [511:0] data_out
);
    reg [511:0] state_in_reg;
    reg start_block;
    wire block_done;
    wire [511:0] chacha_out;

    always @(posedge clk or negedge reset_n) begin
        if(!reset_n) begin
            ready <= 1;
            data_out_valid <= 0;
            data_out <= 0;
            start_block <= 0;
        end else begin
            data_out_valid <= 0;
            start_block <= 0;
            if((init || next) && ready) begin
                state_in_reg <= {32'h61707865,32'h3320646e,32'h79622d32,32'h6b206574,
                                 key[255:224],key[223:192],key[191:160],key[159:128],
                                 key[127:96],key[95:64],key[63:32],key[31:0],
                                 ctr,iv};
                start_block <= 1;
                ready <= 0;
            end else if(block_done) begin
                data_out <= data_in ^ chacha_out;
                data_out_valid <= 1;
                ready <= 1;
            end
        end
    end

    chacha_block #(.NUM_ROUNDS(20)) u_block(
        .clk(clk), .rst_n(reset_n),
        .start(start_block),
        .state_in(state_in_reg),
        .state_out(chacha_out),
        .done(block_done)
    );
endmodule
