`timescale 1ns/1ps
`default_nettype none

module chacha20_poly1305_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] key,
    input  wire [95:0]  nonce,
    input  wire [31:0]  ctr_init,
    input  wire         cfg_we,
    input  wire         ks_req,
    output wire         ks_valid,
    output wire [511:0] ks_data,
    input  wire         aad_valid,
    input  wire [127:0] aad_data,
    input  wire [15:0]  aad_keep,
    output wire         aad_ready,
    input  wire         pld_valid,
    input  wire [127:0] pld_data,
    input  wire [15:0]  pld_keep,
    output wire         pld_ready,
    input  wire         len_valid,
    input  wire [127:0] len_block,
    output wire         len_ready,
    output wire [127:0] tag_pre_xor,
    output wire         tag_pre_xor_valid,
    output wire [127:0] tagmask,
    output wire         tagmask_valid,
    output wire         aad_done,
    output wire         pld_done,
    output wire         lens_done,
    input  wire         algo_sel
);

    // internal done wires
    wire aad_done_reg, pld_done_reg, lens_done_reg;

    // ChaCha keystream wires
    wire        ks_valid_chacha;
    wire [511:0] ks_data_chacha;

    chacha_keystream_unit u_ks (
        .clk(clk), .rst_n(rst_n),
        .chacha_key(key),
        .chacha_nonce(nonce),
        .chacha_ctr_init(ctr_init),
        .cfg_we(cfg_we),
        .ks_req(ks_req),
        .ks_valid(ks_valid_chacha),
        .ks_data(ks_data_chacha)
    );

    chacha_poly1305_adapter u_poly (
        .clk(clk), .rst_n(rst_n),
        .start(cfg_we & algo_sel),
        .algo_sel(algo_sel),
        .key(key),
        .nonce(nonce),
        .ctr_init(ctr_init),
        .aad_valid(aad_valid),
        .aad_data(aad_data),
        .aad_keep(aad_keep),
        .aad_ready(aad_ready),
        .pld_valid(pld_valid),
        .pld_data(pld_data),
        .pld_keep(pld_keep),
        .pld_ready(pld_ready),
        .len_valid(len_valid),
        .len_block(len_block),
        .len_ready(len_ready),
        .tag_pre_xor(tag_pre_xor),
        .tag_pre_xor_valid(tag_pre_xor_valid),
        .tagmask(tagmask),
        .tagmask_valid(tagmask_valid),
        .aad_done(aad_done_reg),
        .pld_done(pld_done_reg),
        .lens_done(lens_done_reg)
    );

    assign aad_done  = algo_sel ? aad_done_reg  : 1'b0;
    assign pld_done  = algo_sel ? pld_done_reg  : 1'b0;
    assign lens_done = algo_sel ? lens_done_reg : 1'b0;

    assign ks_valid = ks_valid_chacha;
    assign ks_data  = ks_data_chacha;

endmodule

`default_nettype wire
