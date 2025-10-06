// -----------------------------------------------------------------------------
// AES-GCM controller: orchestrates phases and tag handling around datapath.
// -----------------------------------------------------------------------------
module aes_gcm_ctrl (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         enc_mode,
    input  wire [63:0]  len_aad_bits,
    input  wire [63:0]  len_pld_bits,
    input  wire         iv_we,
    input  wire         aad_valid,
    input  wire         aad_ready,
    input  wire         aad_last,
    input  wire [15:0]  aad_keep,
    input  wire         din_valid,
    input  wire         din_ready,
    input  wire         din_last,
    input  wire [15:0]  din_keep,
    input  wire         dout_valid,
    input  wire         dout_ready,
    input  wire         dout_last,
    input  wire [15:0]  dout_keep,
    input  wire [127:0] tag_in,
    input  wire         tag_in_we,
    input  wire [127:0] tag_pre_xor,
    input  wire         tag_pre_xor_valid,
    input  wire [127:0] tagmask,
    input  wire         tagmask_valid,
    input  wire         aad_done,
    input  wire         pld_done,
    input  wire         lens_done,
    output wire         ctr_load_iv,
    output wire         ghash_init,
    output wire         tagmask_start,
    output wire [2:0]   phase,
    output reg  [127:0] tag_out,
    output reg          tag_out_valid,
    output reg          auth_fail
);

    // ------------------------------------------------------------------
    // Phase encodings
    // ------------------------------------------------------------------
    localparam PH_IDLE          = 3'd0;
    localparam PH_ABSORB_AAD    = 3'd1;
    localparam PH_PROCESS_PLD   = 3'd2;
    localparam PH_LENS          = 3'd3;
    localparam PH_TAG           = 3'd4;
    localparam PH_DONE          = 3'd5;

    // ------------------------------------------------------------------
    // Helper to count active bytes in keep masks
    // ------------------------------------------------------------------
    function automatic [4:0] count_keep16;
        input [15:0] keep;
        integer idx;
        begin
            count_keep16 = 5'd0;
            for (idx = 0; idx < 16; idx = idx + 1) begin
                if (keep[idx]) begin
                    count_keep16 = count_keep16 + 5'd1;
                end
            end
        end
    endfunction

    // ------------------------------------------------------------------
    // State and configuration registers
    // ------------------------------------------------------------------
    reg        start_d;
    reg        enc_mode_reg;
    reg [63:0] len_aad_bits_reg;
    reg [63:0] len_pld_bits_reg;
    reg [2:0]  phase_reg;
    reg [2:0]  phase_next_reg;

    reg [63:0] aad_bits_remaining_reg;
    reg        aad_complete_reg;
    reg [63:0] pld_bits_remaining_reg;
    reg        pld_complete_reg;

    reg [127:0] tag_in_reg;
    reg         final_tag_ready_reg;

    reg         lens_done_d;
    reg         iv_we_d;

    // ------------------------------------------------------------------
    // Derived strobes and handshakes
    // ------------------------------------------------------------------
    wire start_pulse = start && !start_d;

    wire aad_handshake = (phase_reg == PH_ABSORB_AAD) && aad_valid && aad_ready;
    wire [4:0] aad_keep_cnt = count_keep16(aad_keep);
    wire [63:0] aad_bits_this = ({59'd0, aad_keep_cnt} << 3);

    wire enc_payload_handshake = enc_mode_reg && (phase_reg == PH_PROCESS_PLD) && dout_valid && dout_ready;
    wire dec_payload_handshake = !enc_mode_reg && (phase_reg == PH_PROCESS_PLD) && din_valid && din_ready;
    wire payload_handshake = enc_payload_handshake || dec_payload_handshake;

    wire [15:0] payload_keep_sel = enc_mode_reg ? dout_keep : din_keep;
    wire        payload_last_sel = enc_mode_reg ? dout_last : din_last;
    wire [4:0]  payload_keep_cnt = count_keep16(payload_keep_sel);
    wire [63:0] payload_bits_this = ({59'd0, payload_keep_cnt} << 3);

    wire aad_phase_done     = (len_aad_bits_reg == 64'd0) ? 1'b1 : (aad_done || aad_complete_reg);
    wire payload_phase_done = (len_pld_bits_reg == 64'd0) ? 1'b1 : (pld_done || pld_complete_reg);
    wire tag_inputs_ready   = (phase_reg == PH_TAG) && tagmask_valid && tag_pre_xor_valid && !final_tag_ready_reg;

    // ------------------------------------------------------------------
    // Phase output for datapath/controller integration
    // ------------------------------------------------------------------
    assign phase = phase_reg;

    // ------------------------------------------------------------------
    // Control pulses to datapath sub-blocks
    // ------------------------------------------------------------------
    assign ghash_init    = start_pulse;
    assign ctr_load_iv   = iv_we && !iv_we_d;
    assign tagmask_start = (phase_reg == PH_LENS) && lens_done && !lens_done_d;

    // ------------------------------------------------------------------
    // Sequential logic
    // ------------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            start_d             <= 1'b0;
            enc_mode_reg        <= 1'b0;
            len_aad_bits_reg    <= 64'd0;
            len_pld_bits_reg    <= 64'd0;
            phase_reg           <= PH_IDLE;
            aad_bits_remaining_reg <= 64'd0;
            aad_complete_reg    <= 1'b1;
            pld_bits_remaining_reg <= 64'd0;
            pld_complete_reg    <= 1'b1;
            tag_in_reg          <= 128'h0;
            final_tag_ready_reg <= 1'b0;
            tag_out             <= 128'h0;
            tag_out_valid       <= 1'b0;
            auth_fail           <= 1'b0;
            lens_done_d         <= 1'b0;
            iv_we_d             <= 1'b0;
        end else begin
            start_d <= start;
            lens_done_d <= lens_done;
            iv_we_d <= iv_we;

            if (tag_in_we) begin
                tag_in_reg <= tag_in;
            end

            if (start_pulse) begin
                enc_mode_reg         <= enc_mode;
                len_aad_bits_reg     <= len_aad_bits;
                len_pld_bits_reg     <= len_pld_bits;
                aad_bits_remaining_reg <= len_aad_bits;
                pld_bits_remaining_reg <= len_pld_bits;
                aad_complete_reg     <= (len_aad_bits == 64'd0);
                pld_complete_reg     <= (len_pld_bits == 64'd0);
                final_tag_ready_reg  <= 1'b0;
                tag_out_valid        <= 1'b0;
                tag_out             <= 128'h0;
                auth_fail            <= 1'b0;
            end else begin
                // Default clearing for single-cycle pulses
                tag_out_valid <= 1'b0;

                if (phase_reg == PH_ABSORB_AAD) begin
                    if (aad_handshake) begin
                        if (aad_bits_remaining_reg <= aad_bits_this) begin
                            aad_bits_remaining_reg <= 64'd0;
                            aad_complete_reg      <= 1'b1;
                        end else begin
                            aad_bits_remaining_reg <= aad_bits_remaining_reg - aad_bits_this;
                            if (aad_last) begin
                                aad_complete_reg <= 1'b1;
                            end
                        end
                    end

                    if (aad_done) begin
                        aad_bits_remaining_reg <= 64'd0;
                        aad_complete_reg      <= 1'b1;
                    end
                end

                if (phase_reg == PH_PROCESS_PLD) begin
                    if (payload_handshake) begin
                        if (pld_bits_remaining_reg <= payload_bits_this) begin
                            pld_bits_remaining_reg <= 64'd0;
                            pld_complete_reg       <= 1'b1;
                        end else begin
                            pld_bits_remaining_reg <= pld_bits_remaining_reg - payload_bits_this;
                            if (payload_last_sel) begin
                                pld_complete_reg <= 1'b1;
                            end
                        end
                    end

                    if (pld_done) begin
                        pld_bits_remaining_reg <= 64'd0;
                        pld_complete_reg       <= 1'b1;
                    end
                end

                if (tag_inputs_ready) begin
                    tag_out             <= tag_pre_xor ^ tagmask;
                    final_tag_ready_reg <= 1'b1;

                    if (enc_mode_reg) begin
                        tag_out_valid <= 1'b1;
                        auth_fail     <= 1'b0;
                    end else begin
                        auth_fail     <= ((tag_pre_xor ^ tagmask) != tag_in_reg);
                    end
                end
            end

            phase_reg <= phase_next_reg;
        end
    end

    // ------------------------------------------------------------------
    // Next-state logic (combinational)
    // ------------------------------------------------------------------
    always @* begin
        phase_next_reg = phase_reg;

        case (phase_reg)
            PH_IDLE: begin
                if (start_pulse) begin
                    if (len_aad_bits != 64'd0) begin
                        phase_next_reg = PH_ABSORB_AAD;
                    end else if (len_pld_bits != 64'd0) begin
                        phase_next_reg = PH_PROCESS_PLD;
                    end else begin
                        phase_next_reg = PH_LENS;
                    end
                end
            end

            PH_ABSORB_AAD: begin
                if (aad_phase_done) begin
                    if (len_pld_bits_reg != 64'd0) begin
                        phase_next_reg = PH_PROCESS_PLD;
                    end else begin
                        phase_next_reg = PH_LENS;
                    end
                end
            end

            PH_PROCESS_PLD: begin
                if (payload_phase_done) begin
                    phase_next_reg = PH_LENS;
                end
            end

            PH_LENS: begin
                if (lens_done) begin
                    phase_next_reg = PH_TAG;
                end
            end

            PH_TAG: begin
                if (tag_inputs_ready) begin
                    phase_next_reg = PH_DONE;
                end
            end

            PH_DONE: begin
                if (start_pulse) begin
                    if (len_aad_bits != 64'd0) begin
                        phase_next_reg = PH_ABSORB_AAD;
                    end else if (len_pld_bits != 64'd0) begin
                        phase_next_reg = PH_PROCESS_PLD;
                    end else begin
                        phase_next_reg = PH_LENS;
                    end
                end
            end

            default: begin
                phase_next_reg = PH_IDLE;
            end
        endcase
    end

endmodule


