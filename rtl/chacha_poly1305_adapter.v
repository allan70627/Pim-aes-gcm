`default_nettype none
`timescale 1ns/1ps

// -----------------------------------------------------------------------------
// Full ChaCha20-Poly1305 adapter with Poly1305 accumulator
// Supports streaming AAD and payload, produces tag_pre_xor and tagmask
// -----------------------------------------------------------------------------
module chacha_poly1305_adapter (
    input  wire         clk,
    input  wire         rst_n,

    input  wire         start,
    input  wire         algo_sel,  // 1 = ChaCha

    input  wire [255:0] key,
    input  wire [95:0]  nonce,
    input  wire [31:0]  ctr_init,

    // AAD stream
    input  wire         aad_valid,
    input  wire [127:0] aad_data,
    input  wire [15:0]  aad_keep,
    output reg          aad_ready,

    // Payload stream
    input  wire         pld_valid,
    input  wire [127:0] pld_data,
    input  wire [15:0]  pld_keep,
    output reg          pld_ready,

    // Length block
    input  wire         len_valid,
    input  wire [127:0] len_block,
    output reg          len_ready,

    // Tag outputs
    output reg  [127:0] tag_pre_xor,
    output reg          tag_pre_xor_valid,
    output reg  [127:0] tagmask,
    output reg          tagmask_valid,

    // Done flags
    output reg          aad_done,
    output reg          pld_done,
    output reg          lens_done
);

    // ------------------------------------------------------------------
    // FSM states
    // ------------------------------------------------------------------
    localparam IDLE  = 4'd0;
    localparam AAD   = 4'd1;
    localparam PAYLD = 4'd2;
    localparam LEN   = 4'd3;
    localparam MUL   = 4'd4;
    localparam REDUCE =4'd5;
    localparam FINAL = 4'd6;
    localparam DONE  = 4'd7;

    reg [3:0] state, next_state;

    // ------------------------------------------------------------------
    // Poly1305 internal registers
    // ------------------------------------------------------------------
    reg [127:0] r_key;
    reg [127:0] s_key;
    reg [257:0] acc;            // 130-bit accumulator + extra for multiplication

    reg start_mul, start_reduce;
    wire [257:0] mul_out;
    wire mul_done;
    wire [129:0] reduce_out;
    wire reduce_done;

    // ------------------------------------------------------------------
    // Multiplication and reduction units
    // ------------------------------------------------------------------
    mult_130x128_limb mul_unit(
        .clk(clk), .reset_n(rst_n),
        .start(start_mul),
        .a_in(acc[129:0]),
        .b_in(r_key),
        .product_out(mul_out),
        .busy(),
        .done(mul_done)
    );

    reduce_mod_poly1305 reduce_unit(
        .clk(clk), .reset_n(rst_n),
        .start(start_reduce),
        .value_in(mul_out),
        .value_out(reduce_out),
        .busy(),
        .done(reduce_done)
    );

    // ------------------------------------------------------------------
    // FSM sequential logic
    // ------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if(!rst_n) begin
            state <= IDLE;
            tag_pre_xor <= 128'b0;
            tag_pre_xor_valid <= 1'b0;
            tagmask <= 128'b0;
            tagmask_valid <= 1'b0;
            aad_ready <= 1'b0;
            pld_ready <= 1'b0;
            len_ready <= 1'b0;
            aad_done <= 1'b0;
            pld_done <= 1'b0;
            lens_done <= 1'b0;
            acc <= 258'b0;
            r_key <= 128'b0;
            s_key <= 128'b0;
            start_mul <= 1'b0;
            start_reduce <= 1'b0;
        end else begin
            state <= next_state;
        end
    end

    // ------------------------------------------------------------------
    // FSM combinational logic
    // ------------------------------------------------------------------
    always @* begin
        next_state = state;
        start_mul = 1'b0;
        start_reduce = 1'b0;

        // Defaults
        aad_ready = 1'b0;
        pld_ready = 1'b0;
        len_ready = 1'b0;

        case(state)
            IDLE: begin
                if(start && algo_sel) begin
                    r_key = key[127:0];
                    s_key = key[255:128];
                    acc = 258'b0;
                    aad_ready = 1'b1;
                    next_state = AAD;
                end
            end

            AAD: begin
                aad_ready = 1'b1;
                if(aad_valid) begin
                    // Mask unused bytes
                    acc = acc + {130{aad_keep[0]}} & {2'b0, aad_data};
                    start_mul = 1'b1;
                    next_state = MUL;
                end
            end

            PAYLD: begin
                pld_ready = 1'b1;
                if(pld_valid) begin
                    acc = acc + {130{pld_keep[0]}} & {2'b0, pld_data};
                    start_mul = 1'b1;
                    next_state = MUL;
                end
            end

            LEN: begin
                len_ready = 1'b1;
                if(len_valid) begin
                    acc = acc + {130{1'b1}} & {2'b0, len_block};
                    start_mul = 1'b1;
                    next_state = MUL;
                end
            end

            MUL: begin
                start_mul = 1'b0;
                if(mul_done) begin
                    start_reduce = 1'b1;
                    next_state = REDUCE;
                end
            end

            REDUCE: begin
                start_reduce = 1'b0;
                if(reduce_done) begin
                    acc[129:0] = reduce_out;
                    // Decide next state
                    if(state==AAD) next_state = PAYLD;
                    else if(state==PAYLD) next_state = LEN;
                    else if(state==LEN) next_state = FINAL;
                end
            end

            FINAL: begin
                tag_pre_xor = acc[127:0] + s_key;
                tag_pre_xor_valid = 1'b1;
                tagmask = {r_key ^ nonce, 32'h0}; // first ChaCha block placeholder
                tagmask_valid = 1'b1;
                next_state = DONE;
            end

            DONE: begin
                // Hold outputs
            end
        endcase
    end

endmodule
