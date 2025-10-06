`default_nettype none

module aes_gcm_top (
  input  wire         clk, rst_n,
  // AAD stream in
  input  wire         aad_valid, input  wire aad_last, output wire aad_ready,
  input  wire [127:0] aad_data,  input  wire [15:0] aad_keep,
  // Payload in
  input  wire         din_valid, input  wire din_last, output wire din_ready,
  input  wire [127:0] din_data,  input  wire [15:0] din_keep,
  // Payload out
  output wire         dout_valid, output wire dout_last, input  wire dout_ready,
  output wire [127:0] dout_data,  output wire [15:0] dout_keep,
  // CSRs (simplified for bring-up)
  input  wire [255:0] key_in,   input  wire key_we, input wire aes256_en,
  input  wire [95:0]  iv_in,    input  wire iv_we,
  input  wire [63:0]  len_aad_bits, len_pld_bits,
  input  wire         start,    input  wire enc_mode, input wire framed_mode,
  input  wire [127:0] tag_in,   input  wire tag_in_we,
  output wire [127:0] tag_out,  output wire tag_out_valid,
  output wire         auth_fail
);
  // bring-up: simple pass-through on payload; AAD consumed immediately
  assign aad_ready   = 1'b1;

  assign din_ready   = dout_ready;
  assign dout_valid  = din_valid;
  assign dout_last   = din_last;
  assign dout_data   = din_data;
  assign dout_keep   = din_keep;

  assign tag_out       = 128'h0;
  assign tag_out_valid = 1'b0;
  assign auth_fail     = 1'b0;
endmodule

`default_nettype wire
