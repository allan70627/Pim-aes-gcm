`timescale 1ns/1ps
`default_nettype none

module chacha_poly1305_adapter (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         algo_sel,
    input  wire [255:0] key,
    input  wire [95:0]  nonce,
    input  wire [31:0] ctr_init,

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

    // FSM states
    localparam IDLE   = 4'd0;
    localparam AAD    = 4'd1;
    localparam PAYLD  = 4'd2;
    localparam LEN    = 4'd3;
    localparam MUL    = 4'd4;
    localparam REDUCE = 4'd5;
    localparam FINAL  = 4'd6;
    localparam DONE   = 4'd7;

    localparam ST_AAD   = 3'd0;
    localparam ST_PAYLD = 3'd1;
    localparam ST_LEN   = 3'd2;

    reg [3:0] state, next_state;
    reg [2:0] prev_stage;

    reg [257:0] acc;
    reg [127:0] r_key, s_key;

    // start pulses (registered)
    reg start_mul, start_reduce;

    wire [257:0] mul_out;
    wire mul_done;
    wire [129:0] reduce_out;
    wire reduce_done;

    // Multiplier instance
    mult_130x128_limb mul_unit (
        .clk(clk), .reset_n(rst_n),
        .start(start_mul),
        .a_in(acc[129:0]),
        .b_in(r_key),
        .product_out(mul_out),
        .busy(),
        .done(mul_done)
    );

    // Reducer instance
    reduce_mod_poly1305 reduce_unit (
        .clk(clk), .reset_n(rst_n),
        .start(start_reduce),
        .value_in(mul_out),
        .value_out(reduce_out),
        .busy(),
        .done(reduce_done)
    );

    // -----------------------------
    // Sequential FSM / registered actions
    // -----------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            acc <= 0;
            r_key <= 0;
            s_key <= 0;
            start_mul <= 0;
            start_reduce <= 0;
            tag_pre_xor <= 0;
            tag_pre_xor_valid <= 0;
            tagmask <= 0;
            tagmask_valid <= 0;
            aad_ready <= 0;
            pld_ready <= 0;
            len_ready <= 0;
            aad_done <= 0;
            pld_done <= 0;
            lens_done <= 0;
            prev_stage <= ST_AAD;
        end else begin
            // default: clear 1-cycle pulses / valid/done outputs
            start_mul <= 0;
            start_reduce <= 0;
            tag_pre_xor_valid <= 0;
            tagmask_valid <= 0;
            aad_done <= 0;
            pld_done <= 0;
            lens_done <= 0;

            // update state
            state <= next_state;

            // On IDLE + start: capture keys, clear accumulator, set initial prev_stage
            if (state == IDLE && start && algo_sel) begin
                r_key <= key[127:0];
                s_key <= key[255:128];
                acc <= 0;
                prev_stage <= ST_AAD;
            end

            // When in AAD/PAYLD/LEN: sample valid and initiate multiplier with 1-cycle start pulse
            if (state == AAD) begin
                aad_ready <= 1;
                if (aad_valid) begin
                    // register accumulator update and pulse multiplier
                    acc <= acc + {128'b0, 2'b0, aad_data}; // extend to 258 bits
                    start_mul <= 1'b1;
                    prev_stage <= ST_AAD;
                end
            end else aad_ready <= 0;

            if (state == PAYLD) begin
                pld_ready <= 1;
                if (pld_valid) begin
                    acc <= acc + {128'b0, 2'b0, pld_data};
                    start_mul <= 1'b1;
                    prev_stage <= ST_PAYLD;
                end
            end else pld_ready <= 0;

            if (state == LEN) begin
                len_ready <= 1;
                if (len_valid) begin
                    acc <= acc + {128'b0, 2'b0, len_block};
                    start_mul <= 1'b1;
                    prev_stage <= ST_LEN;
                end
            end else len_ready <= 0;

            // When in MUL: wait for mul_done, then pulse reducer (registered)
            if (state == MUL) begin
                if (mul_done) begin
                    start_reduce <= 1'b1;
                end
            end

            // When reducer completes, latch reduced value and assert done pulse for that substage
            if (state == REDUCE) begin
                if (reduce_done) begin
                    acc[129:0] <= reduce_out; // take reduced lower 130 bits
                    case (prev_stage)
                        ST_AAD: begin
                            aad_done <= 1'b1;
                        end
                        ST_PAYLD: begin
                            pld_done <= 1'b1;
                        end
                        ST_LEN: begin
                            lens_done <= 1'b1;
                        end
                    endcase
                end
            end

            // FINAL state outputs (registered)
            if (state == FINAL) begin
                tag_pre_xor <= acc[127:0] + s_key;
                tag_pre_xor_valid <= 1'b1;
                tagmask <= {r_key, 32'h0};
                tagmask_valid <= 1'b1;
            end
        end
    end

    // -----------------------------
    // Combinational next-state logic (no registered pulses here)
    // -----------------------------
    always @* begin
        // default next state is hold
        next_state = state;

        // default combinational ready outputs (these are also set in sequential block to be registered)
        // but keep combinational mirrors so external logic can see immediate readiness if needed
        // (the sequential block drives the actual registered aad_ready/pld_ready/len_ready)
        // We do not drive start_mul/start_reduce here (they are generated in sequential block).
        case (state)
            IDLE: begin
                if (start && algo_sel) begin
                    next_state = AAD;
                end
            end

            AAD: begin
                // when verifier (sequential) sees aad_valid it will pulse start_mul and next_state moves
                if (aad_valid) begin
                    next_state = MUL;
                end
            end

            PAYLD: begin
                if (pld_valid) begin
                    next_state = MUL;
                end
            end

            LEN: begin
                if (len_valid) begin
                    next_state = MUL;
                end
            end

            MUL: begin
                // wait here until multiplier asserts done (mul_done)
                if (mul_done) begin
                    next_state = REDUCE;
                end
            end

            REDUCE: begin
                // wait here until reducer asserts done
                if (reduce_done) begin
                    // next state depends on prev_stage value (captured in sequential block)
                    case (prev_stage)
                        ST_AAD:  next_state = PAYLD;
                        ST_PAYLD: next_state = LEN;
                        ST_LEN:  next_state = FINAL;
                        default: next_state = IDLE;
                    endcase
                end
            end

            FINAL: begin
                next_state = DONE;
            end

            DONE: begin
                // hold outputs
                next_state = DONE;
            end

            default: next_state = IDLE;
        endcase
    end

endmodule
`default_nettype wire
