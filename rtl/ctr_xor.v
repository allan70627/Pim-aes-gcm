`default_nettype none

// -----------------------------------------------------------------------------
// CTR XOR datapath (AES-agnostic)
// - Requests keystream blocks via ks_req
// - Consumes keystream via ks_valid/ks_data
// - XORs with payload stream, preserves backpressure
// - ENC: bytes with keep=0 are forced to 0 in ciphertext
// - DEC: bytes with keep=0 are passed through from input
// -----------------------------------------------------------------------------
module ctr_xor (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         enc_mode,
    // Payload input
    input  wire         din_valid,
    input  wire [127:0] din_data,
    input  wire [15:0]  din_keep,
    input  wire         din_last,
    // Payload output
    input  wire         dout_ready,
    output wire         dout_valid,
    output wire [127:0] dout_data,
    output wire [15:0]  dout_keep,
    output wire         dout_last,
    // Keystream interface
    output wire         ks_req,
    input  wire         ks_valid,
    input  wire [127:0] ks_data
);

    localparam ST_IDLE    = 2'd0;
    localparam ST_WAIT_KS = 2'd1;
    localparam ST_HAVE_KS = 2'd2;

    reg [1:0]   state_reg, state_next;

    // Payload staging
    reg         payload_valid_reg;
    reg [127:0] payload_data_reg;
    reg [15:0]  payload_keep_reg;
    reg         payload_last_reg;
    reg         payload_enc_reg;

    wire accept_payload = din_valid && dout_ready && !payload_valid_reg && !dout_valid_reg;
    wire clear_payload  = (state_reg == ST_HAVE_KS) && ks_valid && (!dout_valid_reg || (dout_valid_reg && dout_ready));

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            payload_valid_reg <= 1'b0;
            payload_data_reg  <= 128'h0;
            payload_keep_reg  <= 16'h0;
            payload_last_reg  <= 1'b0;
            payload_enc_reg   <= 1'b0;
        end else begin
            if (accept_payload) begin
                payload_valid_reg <= 1'b1;
                payload_data_reg  <= din_data;
                payload_keep_reg  <= din_keep;
                payload_last_reg  <= din_last;
                payload_enc_reg   <= enc_mode;
            end else if (clear_payload) begin
                payload_valid_reg <= 1'b0;
            end
        end
    end

    // Output registers
    reg         dout_valid_reg;
    reg [127:0] dout_data_reg;
    reg [15:0]  dout_keep_reg;
    reg         dout_last_reg;

    reg [127:0] xor_result;
    integer i;

    always @* begin
        xor_result = payload_data_reg;
        for (i = 0; i < 16; i = i + 1) begin
            if (payload_keep_reg[i]) begin
                xor_result[i*8 +: 8] = payload_data_reg[i*8 +: 8] ^ ks_data[i*8 +: 8];
            end else if (payload_enc_reg) begin
                xor_result[i*8 +: 8] = 8'h00;
            end else begin
                xor_result[i*8 +: 8] = payload_data_reg[i*8 +: 8];
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            dout_valid_reg <= 1'b0;
            dout_data_reg  <= 128'h0;
            dout_keep_reg  <= 16'h0;
            dout_last_reg  <= 1'b0;
        end else begin
            if (ks_valid && (state_reg == ST_HAVE_KS)) begin
                dout_valid_reg <= 1'b1;
                dout_data_reg  <= xor_result;
                dout_keep_reg  <= payload_keep_reg;
                dout_last_reg  <= payload_last_reg;
            end else if (dout_valid_reg && dout_ready) begin
                dout_valid_reg <= 1'b0;
            end
        end
    end

    assign dout_valid = dout_valid_reg;
    assign dout_data  = dout_data_reg;
    assign dout_keep  = dout_keep_reg;
    assign dout_last  = dout_last_reg;

    // Keystream request FSM
    reg ks_req_reg, ks_req_next;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_reg <= ST_IDLE;
            ks_req_reg <= 1'b0;
        end else begin
            state_reg <= state_next;
            ks_req_reg <= ks_req_next;
        end
    end

    always @* begin
        state_next = state_reg;
        ks_req_next = 1'b0;

        case (state_reg)
            ST_IDLE: begin
                if (payload_valid_reg && !dout_valid_reg) begin
                    ks_req_next = 1'b1;
                    state_next  = ST_WAIT_KS;
                end
            end

            ST_WAIT_KS: begin
                ks_req_next = 1'b1;
                if (ks_valid) begin
                    state_next = ST_HAVE_KS;
                end
            end

            ST_HAVE_KS: begin
                if (ks_valid && (!dout_valid_reg || (dout_valid_reg && dout_ready))) begin
                    state_next = ST_IDLE;
                end
            end

            default: begin
                state_next = ST_IDLE;
            end
        endcase
    end

    assign ks_req = ks_req_next;

endmodule

`default_nettype wire

