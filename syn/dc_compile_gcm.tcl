# ======== DC L-2016.03: aes_gcm_top ========
set_host_options -max_cores 8
set_app_var sh_enable_page_mode true

# --- TSMC PDK NLDM roots ---
set TSMC_PDK_PATH [list \
  /eda/tsmc_pdk/tcbn40ulpbwp40_c170815_130d \
  /opt/lib/tsmc/211005/tcbn40ulpbwp40_c170815_130d/TSMCHOME/digital/Front_End/timing_power_noise/NLDM/tcbn40ulpbwp40_c170815_130d \
]

# --- Target/Link libraries ---
set target_library [list \
  tcbn40ulpbwp40_c170815tt1p1v25c.db \
  tcbn40ulpbwp40_c170815ffg1p21vm40c.db \
]
set_app_var search_path [concat [list \
    ../rtl \
    ../rtl/third_party/secworks_aes/src/rtl \
    .] $TSMC_PDK_PATH]
set_app_var target_library  $target_library
set_app_var link_library    "* $target_library"

# --- Read RTL (SystemVerilog OK) ---
set my_rtl [concat \
  [glob -nocomplain ../rtl/*.v] \
  [glob -nocomplain ../rtl/third_party/secworks_aes/src/rtl/*.v] \
]
if {[llength $my_rtl] == 0} { echo "ERROR: No RTL found"; exit 1 }

analyze -format sverilog $my_rtl
elaborate aes_gcm_top
current_design aes_gcm_top
link

# --- Clocks & IO constraints ---
create_clock -period 2.5 -name core_clk [get_ports clk]   ;# 400 MHz (tight)
catch { set_operating_conditions tt1p1v25c }

set_clock_uncertainty 0.10 [get_clocks core_clk]
set_input_delay  0.50 -clock core_clk [remove_from_collection [all_inputs] {clk rst_n}]
set_output_delay 0.50 -clock core_clk [all_outputs]
set_false_path -from [get_ports rst_n]
set_dont_touch_network [get_ports clk]
set_fix_multiple_port_nets -all -buffer_constants
set_max_fanout 16 [current_design]

compile_ultra -no_autoungroup

# --- Reports ---
file mkdir reports
report_timing -delay_type max -max_paths 10  > reports/aes_gcm_top.timing.rpt
report_area                                  > reports/aes_gcm_top.area.rpt
set_power_analysis_mode -method toggle_rate -toggle_rate 0.10
report_power                                 > reports/aes_gcm_top.power.vecless.rpt

# --- Netlist/SDC out ---
file mkdir ../netlist
write -format verilog -hier -output ../netlist/aes_gcm_top.syn.v
write_sdc ../netlist/aes_gcm_top.sdc

echo "DONE: aes_gcm_top synthesized."
