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

    // Clock generation
    initial clk = 0;
    always #5 clk = ~clk;

    // VCD dump
    initial begin
        $dumpfile("chacha20_poly1305_tb.vcd");
        $dumpvars(0, tb_chacha20_poly1305_core);
    end

    // Cycle counter for printing
    integer cycle;
    initial cycle = 0;
    always @(posedge clk) cycle = cycle + 1;

    // Test procedure
    initial begin
        // Initialize signals
        rst_n = 0; cfg_we = 0; ks_req = 0; algo_sel = 1;
        key = 256'h0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
        nonce = 96'habcdef1234567890abcdef12;
        ctr_init = 32'h0;
        aad_valid = 0; aad_data = 0; aad_keep = 0;
        pld_valid = 0; pld_data = 0; pld_keep = 0;
        len_valid = 0; len_block = 0;

        #20 rst_n = 1;  // Release reset

        // Start ChaCha/Poly1305 operation
        @(posedge clk);
        cfg_we = 1;  // Start signal for adapter
        @(posedge clk);
        cfg_we = 0;

        // Request keystream block
        @(posedge clk);
        ks_req = 1;
        @(posedge clk);
        ks_req = 0;

        // Feed AAD blocks
        repeat (3) begin
            @(posedge clk);
            if(aad_ready) begin
                aad_valid = 1;
                aad_data = $random;
                aad_keep = 16'hFFFF;
            end
            @(posedge clk);
            aad_valid = 0;
        end

        // Wait for AAD done
        wait(aad_done);

        // Feed payload blocks
        repeat (5) begin
            @(posedge clk);
            if(pld_ready) begin
                pld_valid = 1;
                pld_data = $random;
                pld_keep = 16'hFFFF;
            end
            @(posedge clk);
            pld_valid = 0;
        end

        // Wait for payload done
        wait(pld_done);

        // Feed LEN block
        @(posedge clk);
        if(len_ready) begin
            len_valid = 1;
            len_block = 128'h00000000000000000000000000000100;
        end
        @(posedge clk);
        len_valid = 0;

        // Wait for LEN done
        wait(lens_done);

        // Wait for tag output
        wait(tag_pre_xor_valid && tagmask_valid);
        $display("Final Tag Pre-XOR: %h", tag_pre_xor);
        $display("Final Tagmask: %h", tagmask);

        // Wait a few cycles to see ks_data
        repeat(5) @(posedge clk);

        $finish;
    end

    // Cycle-by-cycle monitor
    always @(posedge clk) begin
        $display("Cycle: %0d | ks_valid: %b | aad_ready: %b | pld_ready: %b | len_ready: %b | aad_done: %b | pld_done: %b | lens_done: %b",
                 cycle, ks_valid, aad_ready, pld_ready, len_ready, aad_done, pld_done, lens_done);
        if(ks_valid) $display("   ks_data[127:0]: %h ...", ks_data[127:0]);
    end

endmodule

`default_nettype wire
