module aes_gcm_top (
    input  wire         clk,
    input  wire         rst_n,
    // CSR interface
    input  wire [255:0] key_in,
    input  wire         key_we,
    input  wire         aes256_en,
    input  wire [95:0]  iv_in,
    input  wire         iv_we,
    input  wire [63:0]  len_aad_bits,
    input  wire [63:0]  len_pld_bits,
    input  wire         start,
    input  wire         enc_mode,
    input  wire         framed_mode,
    input  wire [127:0] tag_in,
    input  wire         tag_in_we,
    output wire [127:0] tag_out,
    output wire         tag_out_valid,
    output wire         auth_fail,
    // AAD stream in
    input  wire         aad_valid,
    output wire         aad_ready,
    input  wire         aad_last,
    input  wire [127:0] aad_data,
    input  wire [15:0]  aad_keep,
    // Payload in
    input  wire         din_valid,
    output wire         din_ready,
    input  wire         din_last,
    input  wire [127:0] din_data,
    input  wire [15:0]  din_keep,
    // Payload out
    output wire         dout_valid,
    input  wire         dout_ready,
    output wire         dout_last,
    output wire [127:0] dout_data,
    output wire [15:0]  dout_keep
);

    // ------------------------------------------------------------------
    // Internal wiring between controller and datapath
    // ------------------------------------------------------------------
    wire [127:0] tag_pre_xor;
    wire         tag_pre_xor_valid;
    wire [127:0] tagmask;
    wire         tagmask_valid;
    wire         aad_done;
    wire         pld_done;
    wire         lens_done;

    // Controller-only wires (datapath currently self-drives; reserved)
    wire         ctr_load_iv;
    wire         ghash_init;
    wire         tagmask_start;
    wire [2:0]   phase;

    // ------------------------------------------------------------------
    // Datapath instance (single aes_core, GHASH, CTR, tagmask)
    // ------------------------------------------------------------------
    aes_gcm_datapath u_datapath (
        .clk              (clk),
        .rst_n            (rst_n),
        .key_in           (key_in),
        .key_we           (key_we),
        .aes256_en        (aes256_en),
        .iv_in            (iv_in),
        .iv_we            (iv_we),
        .len_aad_bits     (len_aad_bits),
        .len_pld_bits     (len_pld_bits),
        .start            (start),
        .enc_mode         (enc_mode),
        // AAD stream
        .aad_valid        (aad_valid),
        .aad_ready        (aad_ready),
        .aad_last         (aad_last),
        .aad_data         (aad_data),
        .aad_keep         (aad_keep),
        // Payload in
        .din_valid        (din_valid),
        .din_ready        (din_ready),
        .din_last         (din_last),
        .din_data         (din_data),
        .din_keep         (din_keep),
        // Payload out
        .dout_valid       (dout_valid),
        .dout_ready       (dout_ready),
        .dout_last        (dout_last),
        .dout_data        (dout_data),
        .dout_keep        (dout_keep),
        // Tag/Mask and phase done
        .tag_pre_xor      (tag_pre_xor),
        .tag_pre_xor_valid(tag_pre_xor_valid),
        .tagmask          (tagmask),
        .tagmask_valid    (tagmask_valid),
        .aad_done         (aad_done),
        .pld_done         (pld_done),
        .lens_done        (lens_done)
    );

    // ------------------------------------------------------------------
    // Controller instance (drives phases and tag/auth)
    // framed_mode is ignored for now
    // ------------------------------------------------------------------
    aes_gcm_ctrl u_ctrl (
        .clk               (clk),
        .rst_n             (rst_n),
        .start             (start),
        .enc_mode          (enc_mode),
        .len_aad_bits      (len_aad_bits),
        .len_pld_bits      (len_pld_bits),
        .iv_we             (iv_we),
        // AAD handshakes
        .aad_valid         (aad_valid),
        .aad_ready         (aad_ready),
        .aad_last          (aad_last),
        .aad_keep          (aad_keep),
        // Payload handshakes
        .din_valid         (din_valid),
        .din_ready         (din_ready),
        .din_last          (din_last),
        .din_keep          (din_keep),
        .dout_valid        (dout_valid),
        .dout_ready        (dout_ready),
        .dout_last         (dout_last),
        .dout_keep         (dout_keep),
        // Tag IO
        .tag_in            (tag_in),
        .tag_in_we         (tag_in_we),
        .tag_pre_xor       (tag_pre_xor),
        .tag_pre_xor_valid (tag_pre_xor_valid),
        .tagmask           (tagmask),
        .tagmask_valid     (tagmask_valid),
        // Done strobes from datapath
        .aad_done          (aad_done),
        .pld_done          (pld_done),
        .lens_done         (lens_done),
        // Control outputs (reserved for future datapath control)
        .ctr_load_iv       (ctr_load_iv),
        .ghash_init        (ghash_init),
        .tagmask_start     (tagmask_start),
        .phase             (phase),
        // Status / outputs
        .tag_out           (tag_out),
        .tag_out_valid     (tag_out_valid),
        .auth_fail         (auth_fail)
    );

endmodule
