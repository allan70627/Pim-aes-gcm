// Behavioral ChaCha core stub for simulation only.
// Produces a deterministic 512-bit "keystream" block when init/next asserted,
// and asserts data_out_valid one cycle after request.

module chacha_core (
    input  wire         clk,
    input  wire         reset_n,
    input  wire         init,
    input  wire         next,
    input  wire         keylen,        // ignored in stub
    input  wire [255:0] key,
    input  wire [63:0]  ctr,           // lower 64 bits from wrapper
    input  wire [63:0]  iv,            // upper 64 bits (we pass nonce pieces)
    input  wire [4:0]   rounds,        // ignored in stub
    input  wire [511:0] data_in,       // optional - passed through if desired

    output reg          ready,
    output reg [511:0]  data_out,
    output reg          data_out_valid
);

  // Simple internal register version of key to produce keystream
  reg [255:0] key_reg;
  reg [127:0] counter_reg;

  always @(posedge clk or negedge reset_n) begin
    if (!reset_n) begin
      key_reg <= 256'h0;
      counter_reg <= 128'h0;
      ready <= 1'b1;
      data_out <= 512'h0;
      data_out_valid <= 1'b0;
    end else begin
      data_out_valid <= 1'b0; // default deassert
      if (init || next) begin
        ready <= 1'b0;
        // on request, latch key and update counter
        key_reg <= key;
        counter_reg <= counter_reg + 1;
        // produce a deterministic pseudo-keystream: concat of key halves XORed with ctr/iv
        data_out <= {
            key_reg[255:128] ^ {64'h0, ctr},
            key_reg[127:0]   ^ {64'h0, iv},
            key_reg[255:128] ^ {64'h0, counter_reg[63:0]},
            key_reg[127:0]   ^ {64'h0, counter_reg[127:64]}
        };
        // make keystream available next cycle
        data_out_valid <= 1'b1;
        ready <= 1'b1;
      end
    end
  end

endmodule
