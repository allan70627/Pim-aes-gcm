`default_nettype none

// -----------------------------------------------------------------------------
// GCM tagmask helper (AES-agnostic)
// - Forms J0 from 96-bit IV and requests AES(K, J0)
// - Centralized AES/control must provide mask_in/mask_in_valid
// -----------------------------------------------------------------------------
module gcm_tagmask (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [95:0]  iv_in,
    input  wire         iv_we,
    input  wire         start,
    // Request/response handshake to centralized AES
    output reg          tagmask_req,
    input  wire         tagmask_ack,
    input  wire [127:0] mask_in,
    input  wire         mask_in_valid,
    output reg  [127:0] mask,
    output reg          mask_valid,
    output reg          busy
);

    localparam ST_IDLE  = 2'd0;
    localparam ST_WAIT  = 2'd1;

    reg [1:0]   state_reg, state_next;
    reg [95:0]  iv_reg;

    // ------------------------------------------------------------------
    // Sequential state update
    // ------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_reg  <= ST_IDLE;
            iv_reg     <= 96'h0;
            mask       <= 128'h0;
            mask_valid <= 1'b0;
            tagmask_req<= 1'b0;
            busy       <= 1'b0;
        end else begin
            state_reg  <= state_next;
            mask_valid <= 1'b0; // pulse
            if (iv_we) begin
                iv_reg <= iv_in;
            end
            if (mask_in_valid) begin
                mask       <= mask_in;
                mask_valid <= 1'b1;
                busy       <= 1'b0;
            end
        end
    end

    // ------------------------------------------------------------------
    // Combinational control
    // ------------------------------------------------------------------
    always @* begin
        state_next   = state_reg;
        tagmask_req  = 1'b0;
        busy         = (state_reg != ST_IDLE);
        case (state_reg)
            ST_IDLE: begin
                if (start) begin
                    tagmask_req = 1'b1; // request mask for current IV
                    if (tagmask_ack) begin
                        state_next = ST_WAIT;
                    end
                end
            end
            ST_WAIT: begin
                if (mask_in_valid) begin
                    state_next = ST_IDLE;
                end
            end
            default: state_next = ST_IDLE;
        endcase
    end

endmodule

`default_nettype wire
