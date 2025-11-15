`timescale 1ns/1ps
`default_nettype none

module tb_chacha20_poly1305_core;

    reg clk, rst_n;

    // ChaCha/Poly1305 inputs
    reg  [255:0] key;
    reg  [95:0]  nonce;
    reg  [31:0]  ctr_init;
    reg          cfg_we;
    reg          ks_req;

    reg          aad_valid;
    reg  [127:0] aad_data;
    reg  [15:0]  aad_keep;

    reg          pld_valid;
    reg  [127:0] pld_data;
    reg  [15:0]  pld_keep;

    reg          len_valid;
    reg  [127:0] len_block;

    reg          algo_sel; // 1 = ChaCha20-Poly1305 mode

    // Outputs
    wire         ks_valid;
    wire [511:0] ks_data;
    wire         aad_ready, pld_ready, len_ready;
    wire [127:0] tag_pre_xor;
    wire         tag_pre_xor_valid;
    wire [127:0] tagmask;
    wire         tagmask_valid;
    wire         aad_done, pld_done, lens_done;

    // Clock
    initial clk = 0;
    always #5 clk = ~clk;

    // DUT
    chacha20_poly1305_core dut(
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

    integer cycle;

    // =====================================================
    // RESET + SETUP
    // =====================================================
    initial begin
        cycle = 0;

        rst_n = 0;

        cfg_we = 0;
        ks_req = 0;

        aad_valid = 0;
        aad_data  = 0;
        aad_keep  = 16'hFFFF;

        pld_valid = 0;
        pld_data  = 0;
        pld_keep  = 16'hFFFF;

        len_valid = 0;
        len_block = 0;

        algo_sel  = 1'b1;   // Use ChaCha20-Poly1305

        key = 256'h000102030405060708090A0B0C0D0E0F_101112131415161718191A1B1C1D1E1F;
        nonce = 96'h000000090000004A00000000;
        ctr_init = 32'h00000001;

        repeat(20) @(posedge clk);
        rst_n = 1;

        $display("[TB] Starting test...");
        repeat(10) @(posedge clk);

        configure_core();
        request_keystream();
        send_aad_block(128'hDEADBEEF0123456789ABCDEF00112233);
        send_payload_block(128'h11111111222222223333333344444444);
        send_length_block(128'd128); // example length block

        wait_for_tag();
        $display("[TB] TEST COMPLETE.");
        $finish;
    end

    // Cycle counter
    always @(posedge clk) cycle <= cycle + 1;

    // =====================================================
    // TASKS
    // =====================================================

    task configure_core();
        begin
            $display("[%0t] Configuring core", $time);
            cfg_we <= 1;
            @(posedge clk);
            cfg_we <= 0;
        end
    endtask

    task request_keystream();
        begin
            $display("[%0t] Requesting keystream", $time);
            ks_req <= 1;
            @(posedge clk);
            ks_req <= 0;

            wait(ks_valid);
            $display("[%0t] Got keystream block:", $time);
            $display("ks_data = %h", ks_data);
        end
    endtask

    task send_aad_block(input [127:0] b);
        begin
            $display("[%0t] Sending AAD block: %h", $time, b);
            aad_data  <= b;
            aad_valid <= 1;

            wait(aad_ready);
            @(posedge clk);
            aad_valid <= 0;

            wait(aad_done);
            $display("[%0t] AAD processing done", $time);
        end
    endtask

    task send_payload_block(input [127:0] b);
        begin
            $display("[%0t] Sending payload: %h", $time, b);
            pld_data  <= b;
            pld_valid <= 1;

            wait(pld_ready);
            @(posedge clk);
            pld_valid <= 0;

            wait(pld_done);
            $display("[%0t] Payload processing done", $time);
        end
    endtask

    task send_length_block(input [127:0] b);
        begin
            $display("[%0t] Sending LEN block: %h", $time, b);
            len_block <= b;
            len_valid <= 1;

            wait(len_ready);
            @(posedge clk);
            len_valid <= 0;

            wait(lens_done);
            $display("[%0t] Length block accepted", $time);
        end
    endtask

    task wait_for_tag();
        begin
            $display("[%0t] Waiting for final Poly1305 tag...", $time);
            wait(tag_pre_xor_valid);

            $display("[%0t] TAG PRE-XOR  = %h", $time, tag_pre_xor);
            $display("[%0t] TAG MASK     = %h", $time, tagmask);

            wait(tagmask_valid);
            $display("[%0t] TagMask valid", $time);
        end
    endtask

endmodule

`default_nettype wire

