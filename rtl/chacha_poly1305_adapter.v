`timescale 1ns/1ps
`default_nettype none

module chacha_poly1305_adapter (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,       // start flow
    input  wire         algo_sel,
    input  wire [255:0] key,
    input  wire [95:0]  nonce,
    input  wire [31:0]  ctr_init,

    // AAD path
    input  wire         aad_valid,
    input  wire [127:0] aad_data,
    input  wire [15:0]  aad_keep,
    output reg          aad_ready,

    // Payload path
    input  wire         pld_valid,
    input  wire [127:0] pld_data,
    input  wire [15:0]  pld_keep,
    output reg          pld_ready,

    // Length block
    input  wire         len_valid,
    input  wire [127:0] len_block,
    output reg          len_ready,

    // Outputs
    output reg  [127:0] tag_pre_xor,
    output reg          tag_pre_xor_valid,
    output reg  [127:0] tagmask,
    output reg          tagmask_valid,

    // Done signals
    output reg          aad_done,
    output reg          pld_done,
    output reg          lens_done
);

    // States
    localparam IDLE = 4'd0, AAD = 4'd1, MUL_WAIT = 4'd2, MUL = 4'd3;
    localparam REDUCE_WAIT = 4'd4, REDUCE = 4'd5, PAYLD = 4'd6;
    localparam LEN = 4'd7, FINAL = 4'd8, DONE = 4'd9;

    localparam ST_AAD = 3'd0, ST_PAYLD = 3'd1, ST_LEN = 3'd2;

    reg [3:0] state, next_state;
    reg [2:0] prev_stage;

    reg [257:0] acc, acc_next;
    reg         acc_next_valid;

    reg [129:0] block_reg;
    reg         block_reg_valid;

    reg [127:0] r_key, s_key;
    reg start_mul_r, start_reduce_r;

    wire [257:0] mul_out;
    wire mul_done;
    wire [129:0] reduce_out;
    wire reduce_done;

    // Multiplier & Reducer units
    mult_130x128_limb mul_unit(
        .clk(clk), .reset_n(rst_n),
        .start(start_mul_r),
        .a_in(acc[129:0]),
        .b_in(r_key),
        .product_out(mul_out),
        .busy(),
        .done(mul_done)
    );

    reduce_mod_poly1305 reduce_unit(
        .clk(clk), .reset_n(rst_n),
        .start(start_reduce_r),
        .value_in(mul_out),
        .value_out(reduce_out),
        .busy(),
        .done(reduce_done)
    );

    // Sequential logic
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            acc <= 0; acc_next <= 0; acc_next_valid <= 0;
            block_reg <= 0; block_reg_valid <= 0;
            r_key <= 0; s_key <= 0;
            start_mul_r <= 0; start_reduce_r <= 0;
            tag_pre_xor <= 0; tag_pre_xor_valid <= 0;
            tagmask <= 0; tagmask_valid <= 0;
            aad_ready <= 0; pld_ready <= 0; len_ready <= 0;
            aad_done <= 0; pld_done <= 0; lens_done <= 0;
            prev_stage <= ST_AAD;
        end else begin
            // Clear single-cycle pulses
            start_mul_r <= 0; start_reduce_r <= 0;
            tag_pre_xor_valid <= 0; tagmask_valid <= 0;

            state <= next_state;

            // Latch keys on start
            if (state == IDLE && start && algo_sel) begin
                r_key <= key[127:0];
                s_key <= key[255:128];
                acc <= 0; acc_next <= 0; acc_next_valid <= 0;
                block_reg_valid <= 0;
                aad_done <= 0; pld_done <= 0; lens_done <= 0;
            end

            // AAD block
            if (state == AAD) begin
                aad_ready <= 1;
                if (aad_valid && !block_reg_valid) begin
                    block_reg <= {1'b1, aad_data};
                    block_reg_valid <= 1;
                    acc_next <= acc + {128'b0, 1'b1, aad_data};
                    acc_next_valid <= 1'b1;
                    prev_stage <= ST_AAD;
                end
            end else aad_ready <= 0;

            // PAYLOAD block
            if (state == PAYLD) begin
                pld_ready <= 1;
                if (pld_valid && !block_reg_valid) begin
                    block_reg <= {1'b1, pld_data};
                    block_reg_valid <= 1;
                    acc_next <= acc + {128'b0, 1'b1, pld_data};
                    acc_next_valid <= 1'b1;
                    prev_stage <= ST_PAYLD;
                end
            end else pld_ready <= 0;

            // LEN block
            if (state == LEN) begin
                len_ready <= 1;
                if (len_valid && !block_reg_valid) begin
                    block_reg <= {1'b1, len_block};
                    block_reg_valid <= 1;
                    acc_next <= acc + {128'b0, 1'b1, len_block};
                    acc_next_valid <= 1'b1;
                    prev_stage <= ST_LEN;
                end
            end else len_ready <= 0;

            // MUL_WAIT
            if (state == MUL_WAIT && acc_next_valid) begin
                acc <= acc_next;
                acc_next_valid <= 0;
                start_mul_r <= 1;
            end

            // REDUCE_WAIT
            if (state == REDUCE_WAIT) start_reduce_r <= 1;

            // REDUCE
            if (state == REDUCE && reduce_done) begin
                acc[129:0] <= reduce_out;
                case(prev_stage)
                    ST_AAD:   begin aad_done <= 1; block_reg_valid <= 0; end
                    ST_PAYLD: begin pld_done <= 1; block_reg_valid <= 0; end
                    ST_LEN:   begin lens_done <= 1; block_reg_valid <= 0; end
                endcase
            end

            // FINAL
            if (state == FINAL) begin
                tag_pre_xor <= acc[127:0] + s_key;
                tag_pre_xor_valid <= 1;
                tagmask <= {r_key, 32'h0};
                tagmask_valid <= 1;
            end
        end
    end

    // Combinational next-state logic (FIXED)
    always @* begin
        next_state = state;
        case (state)
            IDLE: if (start && algo_sel) next_state = AAD;

            AAD: if (block_reg_valid) next_state = MUL_WAIT;

            MUL_WAIT: next_state = MUL;

            MUL: if (mul_done) next_state = REDUCE_WAIT;

            REDUCE_WAIT: next_state = REDUCE;

            REDUCE: if (reduce_done) begin
                case(prev_stage)
                    ST_AAD:   next_state = PAYLD;
                    ST_PAYLD: next_state = LEN; //  Always go to LEN after payload
                    ST_LEN:   next_state = FINAL;
                    default:  next_state = IDLE;
                endcase
            end

            PAYLD: if (block_reg_valid) next_state = MUL_WAIT;

            LEN: if (block_reg_valid) next_state = MUL_WAIT;

            FINAL: next_state = DONE;

            DONE: next_state = DONE;

            default: next_state = IDLE;
        endcase
    end

endmodule
`default_nettype wire
