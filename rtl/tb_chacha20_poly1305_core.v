`timescale 1ns/1ps
`default_nettype none

module tb_chacha20_poly1305_core;

    // Clock & Reset
    reg clk = 0;
    reg rst_n = 0;
    always #5 clk = ~clk; // 100 MHz

    // DUT signals
    reg  [255:0] key;
    reg  [95:0]  nonce;
    reg  [31:0]  ctr_init;
    reg  cfg_we;
    reg  ks_req;
    wire ks_valid;
    wire [511:0] ks_data;

    reg  [127:0] aad_data;
    reg  [15:0]  aad_keep;
    reg  aad_valid;
    wire aad_ready;

    reg  [127:0] pld_data;
    reg  [15:0]  pld_keep;
    reg  pld_valid;
    wire pld_ready;

    reg  [127:0] len_block;
    reg  len_valid;
    wire len_ready;

    wire [127:0] tag_pre_xor;
    wire tag_pre_xor_valid;
    wire [127:0] tagmask;
    wire tagmask_valid;

    wire aad_done, pld_done, lens_done;
    reg  algo_sel;

    integer cycle_count = 0;
    integer i;

    // DUT instance
    chacha20_poly1305_core dut (
        .clk(clk), .rst_n(rst_n),
        .key(key), .nonce(nonce), .ctr_init(ctr_init),
        .cfg_we(cfg_we), .ks_req(ks_req),
        .ks_valid(ks_valid), .ks_data(ks_data),
        .aad_valid(aad_valid), .aad_data(aad_data), .aad_keep(aad_keep), .aad_ready(aad_ready),
        .pld_valid(pld_valid), .pld_data(pld_data), .pld_keep(pld_keep), .pld_ready(pld_ready),
        .len_valid(len_valid), .len_block(len_block), .len_ready(len_ready),
        .tag_pre_xor(tag_pre_xor), .tag_pre_xor_valid(tag_pre_xor_valid),
        .tagmask(tagmask), .tagmask_valid(tagmask_valid),
        .aad_done(aad_done), .pld_done(pld_done), .lens_done(lens_done),
        .algo_sel(algo_sel)
    );

    // Clock cycle counter
    always @(posedge clk) cycle_count = cycle_count + 1;

    // TB procedure
    initial begin
        rst_n = 0; cfg_we = 0; ks_req = 0; aad_valid = 0; pld_valid = 0; len_valid = 0; algo_sel = 1;
        key = 256'h00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff;
        nonce = 96'hdeadbeefcafebabe11223344;
        ctr_init = 32'h0;
        #20;
        rst_n = 1;
        #20;

        $display("[TB] Starting test...");

        // Configure core
        cfg_we = 1; #10; cfg_we = 0;
        $display("[%0t] Configuring core with key=%h", $time, key);

        // Request keystream
        ks_req = 1; #10; ks_req = 0;
        wait(ks_valid);
        $display("[%0t] Got keystream block (ks_valid=%b):\nks_data = %h", $time, ks_valid, ks_data);

        // -------------------------------
        // Send 10 AAD blocks properly
        for (i = 0; i < 10; i = i + 1) begin
            aad_data = $random;
            aad_keep = 16'hffff;
            aad_valid = 1;
            // Wait until DUT is ready
            wait(aad_ready);
            @(posedge clk);  // latch the block
            aad_valid = 0;
            // Wait for this block to be processed
            wait(aad_done);
            $display("[%0t] AAD[%0d] processed: %h", $time, i, aad_data);
        end

        // -------------------------------
        // Send 10 Payload blocks properly
        for (i = 0; i < 10; i = i + 1) begin
            pld_data = $random;
            pld_keep = 16'hffff;
            pld_valid = 1;
            wait(pld_ready);
            @(posedge clk); // latch
            pld_valid = 0;
            wait(pld_done);
            $display("[%0t] PAYLOAD[%0d] processed: %h", $time, i, pld_data);
        end

        // -------------------------------
        // Send length block properly
        len_block = 128'h00000000000000000000000000000080;
        len_valid = 1;
        wait(len_ready);
        @(posedge clk);
        len_valid = 0;
        wait(lens_done);
        $display("[%0t] Length block processed: %h", $time, len_block);

        // Wait for final tag
        wait(tag_pre_xor_valid && tagmask_valid);
        $display("[%0t] TAG PRE-XOR  = %h", $time, tag_pre_xor);
        $display("[%0t] TAG MASK     = %h", $time, tagmask);

        $display("[TB] Total cycles = %0d", cycle_count);
        $display("[TB] TEST COMPLETE.");
        $finish;
    end

endmodule

`default_nettype wire

