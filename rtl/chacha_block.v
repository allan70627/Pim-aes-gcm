`timescale 1ns/1ps
`default_nettype none
// chacha_block.v
// One ChaCha round per cycle. Start by pulsing 'start' for 1 cycle with state_in loaded.
// When done pulses 'done' for 1 cycle and state_out contains feed-forwarded output.

// ==================== chacha_block ====================
module chacha_block #(
    parameter NUM_ROUNDS = 20
)(
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    input  wire [511:0] state_in,
    output reg  [511:0] state_out,
    output reg         done
);
    reg [31:0] w[15:0];
    reg [31:0] w_orig[15:0];
    reg [5:0] round_cnt;
    reg running;

    integer i;

    function [31:0] rol;
        input [31:0] x;
        input [4:0] n;
        begin
            rol = (x << n) | (x >> (32-n));
        end
    endfunction

    function [127:0] quarterround;
        input [31:0] a,b,c,d;
        reg [31:0] a1,b1,c1,d1;
        begin
            a1 = a + b; d1 = rol(d ^ a1,16);
            c1 = c + d1; b1 = rol(b ^ c1,12);
            a1 = a1 + b1; d1 = rol(d1 ^ a1,8);
            c1 = c1 + d1; b1 = rol(b1 ^ c1,7);
            quarterround = {a1,b1,c1,d1};
        end
    endfunction

    reg [31:0] na[15:0];

    always @(posedge clk or negedge rst_n) begin
        if(!rst_n) begin
            state_out <= 512'h0;
            done <= 0;
            running <= 0;
            round_cnt <= 0;
            for(i=0;i<16;i=i+1) begin w[i]<=0; w_orig[i]<=0; na[i]<=0; end
        end else begin
            done <= 0;
            if(start && !running) begin
                for(i=0;i<16;i=i+1) begin
                    w[i] <= state_in[511-32*i -:32];
                    w_orig[i] <= state_in[511-32*i -:32];
                end
                round_cnt <= 0;
                running <= 1;
            end else if(running) begin
                if(round_cnt[0]==0) begin
                    // column round
                    {na[0],na[4],na[8],na[12]} = quarterround(w[0],w[4],w[8],w[12]);
                    {na[1],na[5],na[9],na[13]} = quarterround(w[1],w[5],w[9],w[13]);
                    {na[2],na[6],na[10],na[14]}= quarterround(w[2],w[6],w[10],w[14]);
                    {na[3],na[7],na[11],na[15]}= quarterround(w[3],w[7],w[11],w[15]);
                end else begin
                    // diagonal round
                    {na[0],na[5],na[10],na[15]} = quarterround(w[0],w[5],w[10],w[15]);
                    {na[1],na[6],na[11],na[12]} = quarterround(w[1],w[6],w[11],w[12]);
                    {na[2],na[7],na[8],na[13]}  = quarterround(w[2],w[7],w[8],w[13]);
                    {na[3],na[4],na[9],na[14]}  = quarterround(w[3],w[4],w[9],w[14]);
                end
                for(i=0;i<16;i=i+1) w[i] <= na[i];
                if(round_cnt == NUM_ROUNDS-1) begin
                    for(i=0;i<16;i=i+1) state_out[511-32*i -:32] <= w[i]+w_orig[i];
                    running <= 0;
                    done <= 1;
                end
                round_cnt <= round_cnt + 1'b1;
            end
        end
    end
endmodule
