`timescale 1ns/1ps
`default_nettype none

// -----------------------------------------------------------------------------
// Poly1305 limb multiplier (unchanged)
// -----------------------------------------------------------------------------
module mult_130x128_limb(
    input  wire clk,
    input  wire reset_n,
    input  wire start,
    input  wire [129:0] a_in,
    input  wire [127:0] b_in,
    output reg [257:0] product_out,
    output reg busy,
    output reg done
);
    reg [257:0] acc;
    reg [257:0] a_shift;
    reg [127:0] b_reg;
    reg [7:0] bit_idx;

    always @(posedge clk or negedge reset_n) begin
        if(!reset_n) begin
            product_out <= 258'b0;
            acc <= 258'b0;
            a_shift <= 258'b0;
            b_reg <= 128'b0;
            bit_idx <= 8'd0;
            busy <= 1'b0;
            done <= 1'b0;
        end else begin
            done <= 1'b0;
            if(start && !busy) begin
                a_shift <= {128'b0, a_in};
                b_reg <= b_in;
                acc <= 258'b0;
                bit_idx <= 8'd0;
                busy <= 1'b1;
            end else if(busy) begin
                if(b_reg[0] == 1'b1) acc <= acc + a_shift;
                a_shift <= a_shift << 1;
                b_reg <= b_reg >> 1;
                bit_idx <= bit_idx + 1'b1;
                if(bit_idx == 8'd127) begin
                    product_out <= acc;
                    busy <= 1'b0;
                    done <= 1'b1;
                end
            end
        end
    end
endmodule

// -----------------------------------------------------------------------------
// Poly1305 reduce modulo (unchanged)
// -----------------------------------------------------------------------------
module reduce_mod_poly1305(
    input wire clk,
    input wire reset_n,
    input wire start,
    input wire [257:0] value_in,
    output reg [129:0] value_out,
    output reg busy,
    output reg done
);
    reg [257:0] val_reg;
    reg [129:0] lo;
    reg [127:0] hi;
    reg [130:0] tmp;
    reg state;

    always @(posedge clk or negedge reset_n) begin
        if(!reset_n) begin
            value_out <= 130'b0;
            busy <= 1'b0;
            done <= 1'b0;
            val_reg <= 258'b0;
            state <= 1'b0;
            lo <= 130'b0;
            hi <= 128'b0;
            tmp <= 131'b0;
        end else begin
            done <= 1'b0;
            if(start && !busy) begin
                busy <= 1'b1;
                val_reg <= value_in;
                state <= 1'b1;
            end else if(busy && state) begin
                lo <= val_reg[129:0];
                hi <= val_reg[257:130];
                tmp <= lo + hi * 5;
                if(tmp >= (1'b1 << 130))
                    value_out <= tmp - (1'b1 << 130) + 5;
                else
                    value_out <= tmp[129:0];
                busy <= 1'b0;
                done <= 1'b1;
                state <= 1'b0;
            end
        end
    end
endmodule

// -----------------------------------------------------------------------------
// ChaCha20-Poly1305 adapter (corrected)
// -----------------------------------------------------------------------------
module chacha_poly1305_adapter (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         algo_sel,
    input  wire [255:0] key,
    input  wire [95:0]  nonce,
    input  wire [31:0]  ctr_init,

    input  wire         aad_valid,
    input  wire [127:0] aad_data,
    input  wire [15:0]  aad_keep,
    output reg          aad_ready,

    input  wire         pld_valid,
    input  wire [127:0] pld_data,
    input  wire [15:0]  pld_keep,
    output reg          pld_ready,

    input  wire         len_valid,
    input  wire [127:0] len_block,
    output reg          len_ready,

    output reg  [127:0] tag_pre_xor,
    output reg          tag_pre_xor_valid,
    output reg  [127:0] tagmask,
    output reg          tagmask_valid,

    output reg          aad_done,
    output reg          pld_done,
    output reg          lens_done
);

    localparam IDLE   = 4'd0;
    localparam AAD    = 4'd1;
    localparam PAYLD  = 4'd2;
    localparam LEN    = 4'd3;
    localparam MUL    = 4'd4;
    localparam REDUCE = 4'd5;
    localparam FINAL  = 4'd6;
    localparam DONE   = 4'd7;

    reg [3:0] state, next_state;
    reg [257:0] acc;
    reg [127:0] r_key, s_key;
    reg start_mul, start_reduce;

    reg [2:0] prev_stage; // 0=AAD, 1=PAYLD, 2=LEN

    localparam ST_AAD   = 3'd0;
    localparam ST_PAYLD = 3'd1;
    localparam ST_LEN   = 3'd2;

    wire [257:0] mul_out;
    wire mul_done;
    wire [129:0] reduce_out;
    wire reduce_done;

    // multiplier instance
    mult_130x128_limb mul_unit(
        .clk(clk), .reset_n(rst_n),
        .start(start_mul),
        .a_in(acc[129:0]),
        .b_in(r_key),
        .product_out(mul_out),
        .busy(),
        .done(mul_done)
    );

    // reduction instance
    reduce_mod_poly1305 reduce_unit(
        .clk(clk), .reset_n(rst_n),
        .start(start_reduce),
        .value_in(mul_out),
        .value_out(reduce_out),
        .busy(),
        .done(reduce_done)
    );

    // sequential FSM
    always @(posedge clk or negedge rst_n) begin
        if(!rst_n) begin
            state <= IDLE;
            acc <= 258'b0;
            r_key <= 128'b0;
            s_key <= 128'b0;
            start_mul <= 1'b0;
            start_reduce <= 1'b0;
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
            prev_stage <= ST_AAD;
        end else begin
            state <= next_state;
            start_mul <= 1'b0;     // pulse control
            start_reduce <= 1'b0;  // pulse control
        end
    end

    // combinational FSM
    always @* begin
        next_state = state;
        aad_ready = 1'b0;
        pld_ready = 1'b0;
        len_ready = 1'b0;
        start_mul = 1'b0;
        start_reduce = 1'b0;
        aad_done = 1'b0;
        pld_done = 1'b0;
        lens_done = 1'b0;
        tag_pre_xor_valid = 1'b0;
        tagmask_valid = 1'b0;

        case(state)
            IDLE: begin
                if(start && algo_sel) begin
                    r_key = key[127:0];
                    s_key = key[255:128];
                    acc = 258'b0;
                    aad_ready = 1'b1;
                    next_state = AAD;
                    prev_stage = ST_AAD;
                end
            end

            AAD: begin
                aad_ready = 1'b1;
                if(aad_valid) begin
                    acc = acc + {128'b0, 2'b0, aad_data};
                    start_mul = 1'b1;
                    next_state = MUL;
                    prev_stage = ST_AAD;
                end
            end

            PAYLD: begin
                pld_ready = 1'b1;
                if(pld_valid) begin
                    acc = acc + {128'b0, 2'b0, pld_data};
                    start_mul = 1'b1;
                    next_state = MUL;
                    prev_stage = ST_PAYLD;
                end
            end

            LEN: begin
                len_ready = 1'b1;
                if(len_valid) begin
                    acc = acc + {128'b0, 2'b0, len_block};
                    start_mul = 1'b1;
                    next_state = MUL;
                    prev_stage = ST_LEN;
                end
            end

            MUL: begin
                if(mul_done) begin
                    start_reduce = 1'b1;
                    next_state = REDUCE;
                end
            end

            REDUCE: begin
                if(reduce_done) begin
                    acc[129:0] = reduce_out;
                    case(prev_stage)
                        ST_AAD: begin
                            next_state = PAYLD;
                            aad_done = 1'b1;
                        end
                        ST_PAYLD: begin
                            next_state = LEN;
                            pld_done = 1'b1;
                        end
                        ST_LEN: begin
                            next_state = FINAL;
                            lens_done = 1'b1;
                        end
                    endcase
                end
            end

            FINAL: begin
                tag_pre_xor = acc[127:0] + s_key;
                tag_pre_xor_valid = 1'b1;
                tagmask = {r_key, 32'h0}; // mask simplified
                tagmask_valid = 1'b1;
                next_state = DONE;
            end

            DONE: begin
                // hold outputs
            end
        endcase
    end
endmodule
