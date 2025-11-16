`timescale 1ns/1ps
`default_nettype none

module tb_chacha20_poly1305_core;

    // Clock & reset
    reg clk;
    reg rst_n;
    initial clk = 0;
    always #1 clk = ~clk;

    // DUT signals
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
    wire tag_pre_xor_valid;
    wire [127:0] tagmask;
    wire tagmask_valid;
    wire aad_done, pld_done, lens_done;

    reg algo_sel;

    integer i;
    integer cycle_counter;
    integer start_cycle;

    // Arrays for AAD and payload blocks (Verilog style)
    reg [127:0] aad_mem0, aad_mem1, aad_mem2, aad_mem3, aad_mem4;
    reg [127:0] pld_mem0, pld_mem1, pld_mem2, pld_mem3, pld_mem4;

    // Registers to store encrypted/decrypted payload
    reg [127:0] pld_out;

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

    // Initialize memory
    initial begin
        aad_mem0 = 128'h00112233445566778899aabbccddeeff;
        aad_mem1 = 128'h0102030405060708090a0b0c0d0e0f10;
        aad_mem2 = 128'h1112131415161718191a1b1c1d1e1f20;
        aad_mem3 = 128'h2122232425262728292a2b2c2d2e2f30;
        aad_mem4 = 128'h3132333435363738393a3b3c3d3e3f40;

        pld_mem0 = 128'hffeeddccbbaa99887766554433221100;
        pld_mem1 = 128'h0f0e0d0c0b0a09080706050403020100;
        pld_mem2 = 128'h1234567890abcdef1234567890abcdef;
        pld_mem3 = 128'hdeadbeefdeadbeefdeadbeefdeadbeef;
        pld_mem4 = 128'hcafebabecafebabecafebabecafebabe;
    end

    // Clock counter
    initial cycle_counter = 0;
    always @(posedge clk) cycle_counter = cycle_counter + 1;

    // VCD dump for GTKWave
    initial begin
        $dumpfile("tb_chacha20_poly1305_core.vcd");
        $dumpvars(0, tb_chacha20_poly1305_core);
    end

    initial begin
        // Reset
        rst_n = 0;
        cfg_we = 0;
        ks_req = 0;
        aad_valid = 0;
        pld_valid = 0;
        len_valid = 0;
        algo_sel = 1'b1;
        #20;
        rst_n = 1;

        // Configure key/nonce/ctr
        key = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
        nonce = 96'h000000090000004a00000000;
        ctr_init = 32'h1;
        cfg_we = 1;
        @(posedge clk);
        cfg_we = 0;

        $display("\n[INFO] Key = %h", key);

        // Request one keystream block
        start_cycle = cycle_counter;
        ks_req = 1;
        @(posedge clk);
        ks_req = 0;

        // Wait for ks_valid
        wait (ks_valid);
        $display("[Cycle %0d] Keystream block (512-bit) generated in %0d cycles:", cycle_counter, cycle_counter - start_cycle);
        $display("  KS[127:0]   = %h", ks_data[127:0]);
        $display("  KS[255:128] = %h", ks_data[255:128]);
        $display("  KS[383:256] = %h", ks_data[383:256]);
        $display("  KS[511:384] = %h", ks_data[511:384]);

        // --- Feed AAD blocks ---
        for(i=0; i<5; i=i+1) begin
            @(posedge clk);
            start_cycle = cycle_counter;
            aad_valid = 1;
            case(i)
                0: aad_data = aad_mem0;
                1: aad_data = aad_mem1;
                2: aad_data = aad_mem2;
                3: aad_data = aad_mem3;
                4: aad_data = aad_mem4;
            endcase
            aad_keep = 16'hFFFF;
            $display("[Cycle %0d] Feeding AAD block %0d: %h", cycle_counter, i, aad_data);
            @(posedge clk);
            aad_valid = 0;

            wait (aad_done == 1);
            @(posedge clk);
            $display("[Cycle %0d] AAD block %0d processed in %0d cycles", cycle_counter, i, cycle_counter - start_cycle);
        end

        // --- Feed Payload blocks ---
        for(i=0; i<5; i=i+1) begin
            @(posedge clk);
            start_cycle = cycle_counter;
            pld_valid = 1;
            case(i)
                0: pld_data = pld_mem0;
                1: pld_data = pld_mem1;
                2: pld_data = pld_mem2;
                3: pld_data = pld_mem3;
                4: pld_data = pld_mem4;
            endcase
            pld_keep = 16'hFFFF;
            $display("[Cycle %0d] Feeding Payload block %0d: %h", cycle_counter, i, pld_data);
            @(posedge clk);
            pld_valid = 0;

            wait (pld_done == 1);
            @(posedge clk);

            // XOR payload with keystream slice (for demonstration)
            case(i)
                0: pld_out = pld_data ^ ks_data[127:0];
                1: pld_out = pld_data ^ ks_data[255:128];
                2: pld_out = pld_data ^ ks_data[383:256];
                3: pld_out = pld_data ^ ks_data[511:384];
                4: pld_out = pld_data ^ 128'h0;
            endcase

            $display("[Cycle %0d] Payload block %0d encrypted = %h | Cycles = %0d", cycle_counter, i, pld_out, cycle_counter - start_cycle);
        end

        // --- Feed LEN block ---
        @(posedge clk);
        start_cycle = cycle_counter;
        len_valid = 1;
        len_block = 128'h00000000000000000000000000000100;
        $display("[Cycle %0d] Feeding LEN block: %h", cycle_counter, len_block);
        @(posedge clk);
        len_valid = 0;

        wait (lens_done == 1);
        @(posedge clk);
        $display("[Cycle %0d] LEN block processed in %0d cycles | data = %h", cycle_counter, cycle_counter - start_cycle, len_block);

        // Wait for tag
        wait(tag_pre_xor_valid && tagmask_valid);
        $display("[Cycle %0d] Tag_pre_xor = %h", cycle_counter, tag_pre_xor);
        $display("[Cycle %0d] Tagmask      = %h", cycle_counter, tagmask);

        $display("\nTotal simulation cycles: %0d", cycle_counter);
        $display("Testbench finished.");
        $stop;
    end

endmodule

`default_nettype wire
