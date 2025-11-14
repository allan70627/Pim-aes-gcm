`default_nettype none
module chacha20_poly1305_core (
    input  wire         clk,
    input  wire         rst_n,

    // configuration
    input  wire [255:0] key,
    input  wire [95:0]  nonce,
    input  wire [31:0]  ctr_init,
    input  wire         cfg_we,

    // keystream request/response
    input  wire         ks_req,
    output wire         ks_valid,
    output wire [511:0] ks_data,

    // AAD stream (from top)
    input  wire         aad_valid,
    input  wire [127:0] aad_data,
    input  wire [15:0]  aad_keep,
    output wire         aad_ready,

    // payload stream (ciphertext) - 128-bit chunks
    input  wire         pld_valid,
    input  wire [127:0]  pld_data,
    input  wire [15:0]  pld_keep,
    output wire         pld_ready,

    // lengths block (len_aad_bits || len_ct_bits)
    input  wire         len_valid,
    input  wire [127:0] len_block,
    output wire         len_ready,

    // tag outputs (to be muxed into AES top)
    output wire [127:0] tag_pre_xor,
    output wire         tag_pre_xor_valid,
    output wire [127:0] tagmask,
    output wire         tagmask_valid,

    // new outputs for controller
    output wire         aad_done,
    output wire         pld_done,
    output wire         lens_done
);

    // -------------------------------------------------
    // Internal signals
    // -------------------------------------------------
    reg aad_done_reg, pld_done_reg, lens_done_reg;

    // ks unit
    chacha_keystream_unit u_ks (
        .clk(clk), .rst_n(rst_n),
        .chacha_key(key), .chacha_nonce(nonce), .chacha_ctr_init(ctr_init), .cfg_we(cfg_we),
        .ks_req(ks_req), .ks_valid(ks_valid), .ks_data(ks_data)
    );

    // poly adapter
    chacha_poly1305_adapter u_poly (
        .clk(clk), .rst_n(rst_n),
        .start(cfg_we),
        .algo_sel(1'b1),
        .key(key), .nonce(nonce), .ctr_init(ctr_init),
        .aad_valid(aad_valid), .aad_data(aad_data), .aad_keep(aad_keep), .aad_ready(aad_ready),
        .pld_valid(pld_valid), .pld_data(pld_data), .pld_keep(pld_keep), .pld_ready(pld_ready),
        .len_valid(len_valid), .len_block(len_block), .len_ready(len_ready),
        .tag_pre_xor(tag_pre_xor), .tag_pre_xor_valid(tag_pre_xor_valid),
        .tagmask(tagmask), .tagmask_valid(tagmask_valid),
        .aad_done(aad_done_reg), .pld_done(pld_done_reg), .lens_done(lens_done_reg)
    );

    // -------------------------------------------------
    // Tie adapter done signals to top outputs
    // -------------------------------------------------
    assign aad_done  = aad_done_reg;
    assign pld_done  = pld_done_reg;
    assign lens_done = lens_done_reg;

endmodule
`default_nettype wire
