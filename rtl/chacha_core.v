`timescale 1ns/1ps
`default_nettype none
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
    reg [511:0] state;
    reg request_pending;
    wire [511:0] chacha_out;
    wire block_done;
    reg start_block;

    // Build initial state: constants | key | ctr | iv
    wire [511:0] init_state = {
        32'h61707865,32'h3320646e,32'h79622d32,32'h6b206574,
        key[255:224], key[223:192], key[191:160], key[159:128],
        key[127:96], key[95:64], key[63:32], key[31:0],
        ctr, iv
    };

    // chacha_block: parameter inherits default NUM_ROUNDS (20); change parameter if needed
    chacha_block #(.NUM_ROUNDS(20)) BLOCK(
        .clk(clk),
        .rst_n(reset_n),
        .start(start_block),
        .state_in(state),
        .state_out(chacha_out),
        .done(block_done)
    );

    // Internal pending flag
    reg pending_start;

    always @(posedge clk or negedge reset_n) begin
        if(!reset_n) begin
            state <= 512'h0;
            ready <= 1'b1;
            data_out_valid <= 1'b0;
            request_pending <= 1'b0;
            data_out <= 512'h0;
            start_block <= 1'b0;
            pending_start <= 1'b0;
        end else begin
            data_out_valid <= 1'b0;
            start_block <= 1'b0;

            // when host asserts init or next and we are ready, load state and start block
            if((init || next) && ready) begin
                state <= init_state;
                start_block <= 1'b1;
                pending_start <= 1'b1;
                ready <= 1'b0;
            end else if(pending_start && block_done) begin
                // block finished, compute XOR and present data_out
                data_out <= data_in ^ chacha_out;
                data_out_valid <= 1'b1;
                pending_start <= 1'b0;
                ready <= 1'b1;
            end
        end
    end
endmodule

`default_nettype wire
