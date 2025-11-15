`timescale 1ns/1ps
`default_nettype none

module tb_chacha20_poly1305_core;

    // Clock & reset
    reg clk = 0;
    reg rst_n = 0;

    // Core signals
    reg [255:0] key;
    reg [95:0]  nonce;
    reg [31:0]  ctr_init;
    reg         cfg_we;
    reg         ks_req;
    wire        ks_valid;
    wire [511:0] ks_data;

    reg         aad_valid;
    reg [127:0] aad_data;
    reg [15:0]  aad_keep;
    wire        aad_ready;

    reg         pld_valid;
    reg [127:0] pld_data;
    reg [15:0]  pld_keep;
    wire        pld_ready;

    reg         len_valid;
    reg [127:0] len_block;
    wire        len_ready;

    wire [127:0] tag_pre_xor;
    wire         tag_pre_xor_valid;
    wire [127:0] tagmask;
    wire         tagmask_valid;
    wire aad_done, pld_done, lens_done;

    reg algo_sel;

    // Instantiate DUT
    chacha20_poly1305_core dut (
        .clk(clk),
        .rst_n(rst_n),
        .key(key),
        .nonce(nonce),
        .ctr_init(ctr_init),
        .cfg_we(cfg_we),
        .ks_req(ks_req),
        .ks_valid(ks_valid),
        .ks_data(ks_data),
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
        .aad_done(aad_done),
        .pld_done(pld_done),
        .lens_done(lens_done),
        .algo_sel(algo_sel)
    );

    // Clock
    always #5 clk = ~clk;

    // Cycle counter
    integer cycle_count = 0;
    always @(posedge clk) cycle_count <= cycle_count + 1;

    // Test vectors
    reg [127:0] aad_mem [0:4];  // 5 AAD blocks
    reg [127:0] pld_mem [0:4];  // 5 Payload blocks
    integer i;

    initial begin
        $display("[TB] Starting test...");
        rst_n = 0;
        cfg_we = 0;
        ks_req = 0;
        aad_valid = 0;
        pld_valid = 0;
        len_valid = 0;
        algo_sel = 1;
        key = 256'h00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff;
        nonce = 96'h0102030405060708090a0b0c;
        ctr_init = 32'h0;

        // Prepare data
        aad_mem[0] = 128'hdeadbeef0123456789abcdef00112233;
        aad_mem[1] = 128'h112233445566778899aabbccddeeff00;
        aad_mem[2] = 128'hcafebabefeedface0123456789abcdef;
        aad_mem[3] = 128'h00112233445566778899aabbccddeeff;
        aad_mem[4] = 128'h102030405060708090a0b0c0d0e0f10;

        pld_mem[0] = 128'h11111111222222223333333344444444;
        pld_mem[1] = 128'h55555555666666667777777788888888;
        pld_mem[2] = 128'h99999999aaaaaaaabbbbbbbbcccccccc;
        pld_mem[3] = 128'hddddddddffffffff0000000011111111;
        pld_mem[4] = 128'h22223333444455556666777788889999;

        #20;
        rst_n = 1;
        #20;

        // Configure core
        $display("[%0t] Configuring core", $time);
        cfg_we = 1;
        #10;
        cfg_we = 0;

        // Request keystream
        $display("[%0t] Requesting keystream", $time);
        ks_req = 1;
        #10;
        ks_req = 0;

        wait(ks_valid);
        $display("[%0t] Got keystream block:\nks_data = %h", $time, ks_data);

        // --- Send AAD blocks ---
        for (i = 0; i < 5; i = i + 1) begin
            @(posedge clk);
            aad_valid = 1;
            aad_data  = aad_mem[i];
            aad_keep  = 16'hffff;
            $display("[%0t] Sending AAD[%0d]: %h", $time, i, aad_mem[i]);
            wait(aad_ready);
            @(posedge clk);
            aad_valid = 0;
            wait(aad_done);
            $display("[%0t] AAD[%0d] processed", $time, i);
        end

        // --- Send payload blocks ---
        for (i = 0; i < 5; i = i + 1) begin
            @(posedge clk);
            pld_valid = 1;
            pld_data  = pld_mem[i];
            pld_keep  = 16'hffff;
            $display("[%0t] Sending Payload[%0d]: %h", $time, i, pld_mem[i]);
            wait(pld_ready);
            @(posedge clk);
            pld_valid = 0;
            wait(pld_done);
            $display("[%0t] Payload[%0d] processed", $time, i);
        end

        // --- Send LEN block ---
        @(posedge clk);
        len_valid = 1;
        len_block = {64'd80, 64'd80};  // 5 blocks * 16 bytes = 80 bytes each
        $display("[%0t] Sending LEN block: %h", $time, len_block);
        wait(len_ready);
        @(posedge clk);
        len_valid = 0;
        wait(lens_done);
        $display("[%0t] LEN block accepted", $time);

        // --- Wait for final tag ---
        wait(tag_pre_xor_valid && tagmask_valid);
        $display("[%0t] TAG PRE-XOR  = %h", $time, tag_pre_xor);
        $display("[%0t] TAG MASK     = %h", $time, tagmask);

        $display("[TB] TEST COMPLETE. Total cycles = %0d", cycle_count);
        $finish;
    end

endmodule
