# DC L-2016.03 synthesis for aes_gcm_top
set_host_options -max_cores 8
set_app_var sh_enable_page_mode true

# EDIT THESE to your .db path(s)
set_app_var target_library  [list /path/to/tech_tt.db]
set_app_var link_library    "* $target_library"

# search path includes secworks under src/rtl
set_app_var search_path [list ../rtl ../rtl/third_party/secworks_aes/src/rtl . $search_path]

# Read our top (others can be added later)
read_verilog ../rtl/aes_gcm_top.v

# (optional) also read the secworks core now, but it's not required until we instantiate it:
# read_verilog [glob ../rtl/third_party/secworks_aes/src/rtl/*.v]

elaborate aes_gcm_top
link

# Clocks/IO
create_clock -period 2.5 -name core_clk [get_ports clk] ;# 400 MHz example
set_clock_uncertainty 0.10 [get_clocks core_clk]
set_input_delay  0.5 -clock core_clk [remove_from_collection [all_inputs] {clk rst_n}]
set_output_delay 0.5 -clock core_clk [all_outputs]
set_false_path -from [get_ports rst_n]
set_dont_touch_network [get_ports clk]
set_fix_multiple_port_nets -all -buffer_constants
set_max_fanout 16 [current_design]

compile_ultra

file mkdir reports
report_timing -max_paths 10 > reports/aes_gcm_top.timing.rpt
report_area                 > reports/aes_gcm_top.area.rpt
set_power_analysis_mode -method toggle_rate -toggle_rate 0.1
report_power               > reports/aes_gcm_top.power.vecless.rpt

file mkdir ../netlist
write -format verilog -hier -output ../netlist/aes_gcm_top.syn.v
write_sdc ../netlist/aes_gcm_top.sdc
# DC L-2016.03 synthesis for aes_gcm_top
set_host_options -max_cores 8
set_app_var sh_enable_page_mode true

# EDIT THESE to your .db path(s)
set_app_var target_library  [list /path/to/tech_tt.db]
set_app_var link_library    "* $target_library"

# search path includes secworks under src/rtl
set_app_var search_path [list ../rtl ../rtl/third_party/secworks_aes/src/rtl . $search_path]

# Read our top (others can be added later)
read_verilog ../rtl/aes_gcm_top.v

# (optional) also read the secworks core now, but it's not required until we instantiate it:
# read_verilog [glob ../rtl/third_party/secworks_aes/src/rtl/*.v]

elaborate aes_gcm_top
link

# Clocks/IO
create_clock -period 2.5 -name core_clk [get_ports clk] ;# 400 MHz example
set_clock_uncertainty 0.10 [get_clocks core_clk]
set_input_delay  0.5 -clock core_clk [remove_from_collection [all_inputs] {clk rst_n}]
set_output_delay 0.5 -clock core_clk [all_outputs]
set_false_path -from [get_ports rst_n]
set_dont_touch_network [get_ports clk]
set_fix_multiple_port_nets -all -buffer_constants
set_max_fanout 16 [current_design]

compile_ultra

file mkdir reports
report_timing -max_paths 10 > reports/aes_gcm_top.timing.rpt
report_area                 > reports/aes_gcm_top.area.rpt
set_power_analysis_mode -method toggle_rate -toggle_rate 0.1
report_power               > reports/aes_gcm_top.power.vecless.rpt

file mkdir ../netlist
write -format verilog -hier -output ../netlist/aes_gcm_top.syn.v
write_sdc ../netlist/aes_gcm_top.sdc
