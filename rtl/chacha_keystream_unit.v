module chacha_keystream_unit (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [255:0] chacha_key,
    input  wire [95:0]  chacha_nonce,
    input  wire [31:0]  chacha_ctr_init,
    input  wire         cfg_we,
    input  wire         ks_req,
    output reg          ks_valid,
    output reg  [511:0] ks_data
);
    reg [255:0] key_reg;
    reg [95:0]  nonce_reg;
    reg [31:0]  ctr_reg;

    always @(posedge clk or negedge rst_n) begin
        if(!rst_n) begin
            key_reg <= 0; nonce_reg <= 0; ctr_reg <= 0;
        end else if(cfg_we) begin
            key_reg <= chacha_key;
            nonce_reg <= chacha_nonce;
            ctr_reg <= chacha_ctr_init;
        end
    end

    wire [511:0] core_data_out;
    wire core_data_valid, core_ready;
    reg core_next_reg;

    wire [63:0] ctr64 = {ctr_reg,nonce_reg[31:0]};
    wire [63:0] iv64  = nonce_reg[95:32];

    reg core_next_pulse;

    always @(posedge clk or negedge rst_n) begin
        if(!rst_n) begin
            core_next_reg <= 0; core_next_pulse <= 0;
            ks_valid <= 0; ks_data <= 0; ctr_reg <= 0;
        end else begin
            ks_valid <= 0;
            if(core_next_pulse) begin core_next_reg <= 0; core_next_pulse <= 0; end
            if(ks_req && core_ready) begin
                core_next_reg <= 1; core_next_pulse <= 1;
            end
            if(core_data_valid) begin
                ks_data <= core_data_out;
                ks_valid <= 1;
                ctr_reg <= ctr_reg + 1;
            end
        end
    end

    chacha_core u_ks_core(
        .clk(clk), .reset_n(rst_n),
        .init(1'b0),
        .next(core_next_reg),
        .key(key_reg),
        .ctr(ctr64),
        .iv(iv64),
        .data_in(512'h0),
        .ready(core_ready),
        .data_out(core_data_out),
        .data_out_valid(core_data_valid)
    );
endmodule

`default_nettype wire
