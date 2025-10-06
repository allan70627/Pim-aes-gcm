// -----------------------------------------------------------------------------
// Builds the 128-bit length block (len(AAD)||len(CT)) for GHASH per SP 800-38D.
// -----------------------------------------------------------------------------
module gcm_lenblock (
    input  wire [63:0]  len_aad_bits,
    input  wire [63:0]  len_ct_bits,
    output wire [127:0] len_block
);

    assign len_block = {len_aad_bits, len_ct_bits};

endmodule
