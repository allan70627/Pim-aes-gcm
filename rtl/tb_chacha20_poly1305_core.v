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
    integer i;

    reg [127:0] aad_blocks[0:4];
    reg [127:0] payload_blocks[0:4];

    reg [127:0] ciphertext;
    reg [127:0] ks_segment;

    // Clock
    initial clk = 0;
    always #5 clk = ~clk;

    // VCD
    initial begin
        $dumpfile("chacha20_poly1305_tb.vcd");
        $dumpvars(0, tb_chacha20_poly1305_core);
    end

    initial cycle_counter = 0;
    always @(posedge clk) cycle_counter = cycle_counter + 1;

    // Fixed test vectors
    initial begin
        aad_blocks[0] = 128'h00112233445566778899AABBCCDDEEFF;
        aad_blocks[1] = 128'h102132435465768798A9BACBDCEDFE0F;
        aad_blocks[2] = 128'h2031425364758697A8B9CADBEBFC0D1E;
        aad_blocks[3] = 128'h30415263748596A7B8C9DADBECF0E1F2;
        aad_blocks[4] = 128'h405162738495A6B7C8DADBECEF1F2031;

        payload_blocks[0] = 128'hAAAABBBBCCCCDDDDEEEEFFFF00001111;
        payload_blocks[1] = 128'h11112222333344445555666677778888;
        payload_blocks[2] = 128'h9999AAAABBBBCCCCDDDDEEEEFFFF0000;
        payload_blocks[3] = 128'h00001111222233334444555566667777;
        payload_blocks[4] = 128'h1234567890ABCDEF1234567890ABCDEF;
    end

    // DUT
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

    initial begin
        rst_n = 0; cfg_we = 0; ks_req = 0; algo_sel = 1;
        key = 256'h0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
        nonce = 96'habcdef1234567890abcdef12;
        ctr_init = 32'h0;
        aad_valid = 0; aad_data = 0; aad_keep = 0;
        pld_valid = 0; pld_data = 0; pld_keep = 0;
        len_valid = 0; len_block = 0;

        #20 rst_n = 1;  // Release reset

        // Configure DUT
        @(posedge clk); cfg_we = 1;
        @(posedge clk); cfg_we = 0;

        // Request one keystream block
        @(posedge clk); ks_req = 1;
        @(posedge clk); ks_req = 0;
        wait(ks_valid);
        $display("[Cycle %0d] Keystream block: %h", cycle_counter, ks_data);

        // Feed AAD blocks
        for (i = 0; i < 5; i = i + 1) begin
            wait(aad_ready);
            aad_valid <= 1;
            aad_data <= aad_blocks[i];
            aad_keep <= 16'hFFFF;
            @(posedge clk);
            aad_valid <= 0;
            wait(aad_done);
            $display("[Cycle %0d] AAD block %0d processed | data: %h", cycle_counter, i, aad_blocks[i]);
        end

        // Feed Payload blocks and compute ciphertext using 128-bit keystream segments
        for (i = 0; i < 4; i = i + 1) begin
            wait(pld_ready);
            pld_valid <= 1;
            pld_data <= payload_blocks[i];
            pld_keep <= 16'hFFFF;
            @(posedge clk);
            pld_valid <= 0;
            wait(pld_done);

            // Take 128-bit slice of keystream
            ks_segment = ks_data[127 + i*128 -: 128];
            ciphertext = payload_blocks[i] ^ ks_segment;
            $display("[Cycle %0d] Payload block %0d | Plaintext: %h | Ciphertext: %h | Keystream used: %h",
                      cycle_counter, i, payload_blocks[i], ciphertext, ks_segment);
        end

        // Fifth block uses first 128-bit of new keystream (simulate next block)
        @(posedge clk); ks_req = 1;
        @(posedge clk); ks_req = 0;
        wait(ks_valid);
        ks_segment = ks_data[127:0];
        ciphertext = payload_blocks[4] ^ ks_segment;
        $display("[Cycle %0d] Payload block 4 | Plaintext: %h | Ciphertext: %h | Keystream used: %h",
                  cycle_counter, payload_blocks[4], ciphertext, ks_segment);

        // Feed length block
        wait(len_ready);
        len_valid <= 1;
        len_block <= 128'h00000000000000000000000000000100;
        @(posedge clk);
        len_valid <= 0;
        wait(lens_done);
        $display("[Cycle %0d] LEN block processed | data: %h", cycle_counter, len_block);

        // Wait for tag outputs
        wait(tag_pre_xor_valid && tagmask_valid);
        $display("Final Tag Pre-XOR: %h", tag_pre_xor);
        $display("Final Tagmask: %h", tagmask);

        $display("Simulation finished. Total cycles: %0d", cycle_counter);
        $finish;
    end

endmodule

`default_nettype wire
