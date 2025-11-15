`timescale 1ns/1ps
`default_nettype none

module tb_chacha20_poly1305_core;

    reg clk;
    reg rst_n;
    reg [255:0] key;
    reg [95:0] nonce;
    reg [31:0] ctr_init;
    reg cfg_we;
    reg ks_req;
    reg aad_valid;
    reg [127:0] aad_data;
    reg [15:0] aad_keep;
    reg pld_valid;
    reg [127:0] pld_data;
    reg [15:0] pld_keep;
    reg len_valid;
    reg [127:0] len_block;
    reg algo_sel;

    wire ks_valid;
    wire [511:0] ks_data;
    wire aad_ready;
    wire pld_ready;
    wire len_ready;
    wire [127:0] tag_pre_xor;
    wire tag_pre_xor_valid;
    wire [127:0] tagmask;
    wire tagmask_valid;
    wire aad_done;
    wire pld_done;
    wire lens_done;

    integer cycle_counter;

    // DUT instantiation
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

    // Clock generation
    initial clk = 0;
    always #5 clk = ~clk;

    // Cycle counter
    initial cycle_counter = 0;
    always @(posedge clk) cycle_counter = cycle_counter + 1;

    // VCD dump
    initial begin
        $dumpfile("chacha20_poly1305_tb.vcd");
        $dumpvars(0, tb_chacha20_poly1305_core);
    end

    // Test procedure
    initial begin
        // Initial reset
        rst_n = 0; cfg_we = 0; ks_req = 0; algo_sel = 1;
        key = 256'h0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
        nonce = 96'habcdef1234567890abcdef12;
        ctr_init = 32'h0;
        aad_valid = 0; aad_data = 0; aad_keep = 0;
        pld_valid = 0; pld_data = 0; pld_keep = 0;
        len_valid = 0; len_block = 0;

        #20 rst_n = 1;  // release reset

        // Load configuration
        @(posedge clk); cfg_we = 1;
        @(posedge clk); cfg_we = 0;

        // Request keystream
        ks_req <= 1;
        @(posedge clk);
        ks_req <= 0;

        // Wait for keystream to become valid
        wait(ks_valid);
        @(posedge clk);

        $display("[Cycle %0d] Keystream block generated:", cycle_counter);
        $display("  Slice0: %h", ks_data[127:0]);
        $display("  Slice1: %h", ks_data[255:128]);
        $display("  Slice2: %h", ks_data[383:256]);
        $display("  Slice3: %h", ks_data[511:384]);

        // --- Feed 5 AAD blocks ---
        reg [127:0] aad_mem [0:4];
        integer i;
        aad_mem[0] = 128'h00112233445566778899aabbccddeeff;
        aad_mem[1] = 128'h102030405060708090a0b0c0d0e0f00;
        aad_mem[2] = 128'h11111111222222223333333344444444;
        aad_mem[3] = 128'hdeadbeefdeadbeefcafebabecafebabe;
        aad_mem[4] = 128'hffffffff00000000ffffffff00000000;

        for(i=0; i<5; i=i+1) begin
            wait(aad_ready);
            aad_valid <= 1;
            aad_data <= aad_mem[i];
            aad_keep <= 16'hFFFF;
            @(posedge clk);
            aad_valid <= 0;

            wait(aad_done || !block_reg_valid);
            $display("[Cycle %0d] AAD block %0d processed | data: %h", cycle_counter, i, aad_mem[i]);
        end

        // --- Feed 5 Payload blocks ---
        reg [127:0] pld_mem [0:4];
        pld_mem[0] = 128'h01010101010101010101010101010101;
        pld_mem[1] = 128'h11111111111111111111111111111111;
        pld_mem[2] = 128'h22222222222222222222222222222222;
        pld_mem[3] = 128'h33333333333333333333333333333333;
        pld_mem[4] = 128'h44444444444444444444444444444444;

        for(i=0; i<5; i=i+1) begin
            wait(pld_ready);
            pld_valid <= 1;
            pld_data <= pld_mem[i];
            pld_keep <= 16'hFFFF;
            @(posedge clk);
            pld_valid <= 0;

            wait(pld_done || !block_reg_valid);
            $display("[Cycle %0d] Payload block %0d processed | data: %h", cycle_counter, i, pld_mem[i]);
        end

        // --- Feed 1 LEN block ---
        wait(len_ready);
        len_valid <= 1;
        len_block <= 128'h00000000000000000000000000000100; // 256 bits
        @(posedge clk);
        len_valid <= 0;

        wait(lens_done);
        $display("[Cycle %0d] LEN block processed | data: %h", cycle_counter, len_block);

        // Wait for tag outputs
        wait(tag_pre_xor_valid && tagmask_valid);
        $display("[Cycle %0d] Final Tag Pre-XOR: %h", cycle_counter, tag_pre_xor);
        $display("[Cycle %0d] Final Tagmask: %h", cycle_counter, tagmask);

        $finish;
    end

endmodule

`default_nettype wire
