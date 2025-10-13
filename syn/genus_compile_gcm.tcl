# ==========================================
# Genus single-corner TT synth for aes_gcm_top
# Fast area/power sanity runs (no MMMC)
# ==========================================

# ---- User-editable section -----------------------------------------------
if { [info exists ::env(TSMC_PDK_PATH)] } {
  set TSMC_PDK_PATH $::env(TSMC_PDK_PATH)
} else {
  set TSMC_PDK_PATH \
    "/opt/lib/tsmc/211005/tcbn40ulpbwp40_c170815_130d/TSMCHOME/digital/Front_End/timing_power_noise/NLDM/tcbn40ulpbwp40_c170815_130d"
}

# Choose ONE typical-corner Liberty for speed/consistency
set TT_LIB  tcbn40ulpbwp40_c170815tt1p1v25c.lib

# Timing targets (example: 400 MHz)
set CLK_NAME  core_clk
set CLK_PORT  clk
set CLK_PER   2.5
set CLK_UNC   0.10
set IN_DLY    0.5
set OUT_DLY   0.5

# Top and paths (script is expected to run from syn/)
set TOP                aes_gcm_top
set RTL_DIR            ../rtl
set AES_THIRDPARTY_DIR $RTL_DIR/third_party/secworks_aes/src/rtl
set REPORTS_DIR        reports
set NETLIST_DIR        ../netlist

# Optional: multi-CPU
# set_db max_cpus 8

# ---- Setup ----------------------------------------------------------------
if { [llength $TSMC_PDK_PATH] > 1 } {
  set_db lib_search_path $TSMC_PDK_PATH
} else {
  set_db lib_search_path [list $TSMC_PDK_PATH]
}

# Read ONLY the TT liberty
set found_tt 0
foreach libdir $TSMC_PDK_PATH {
  set libpath [file join $libdir $TT_LIB]
  if { [file exists $libpath] } {
    read_libs $libpath
    set found_tt 1
    break
  }
}
if { !$found_tt } {
  puts "ERROR: Could not find $TT_LIB under lib_search_path: $TSMC_PDK_PATH"
  exit 1
}

# (Optional) If your .lib defines specific operating conditions, pick one explicitly.
# Otherwise the nominal OC will be used (as your earlier log showed).
# Example:
#   set_db operating_conditions _nominal_

set_db hdl_search_path [list $RTL_DIR $AES_THIRDPARTY_DIR .]

# ---- Read/Elaborate -------------------------------------------------------
read_hdl $RTL_DIR/$TOP.v
# read_hdl [glob -nocomplain $AES_THIRDPARTY_DIR/*.v]

elaborate $TOP
link
check_design

# ---- Constraints ----------------------------------------------------------
create_clock -period $CLK_PER -name $CLK_NAME [get_ports $CLK_PORT]
set_clock_uncertainty $CLK_UNC [get_clocks $CLK_NAME]

# Apply I/O delays to all except clk and rst_n
set_input_delay  $IN_DLY  -clock $CLK_NAME [remove_from_collection [all_inputs] [list $CLK_PORT rst_n]]
set_output_delay $OUT_DLY -clock $CLK_NAME [all_outputs]

set_false_path -from [get_ports rst_n]
set_dont_touch_network [get_ports $CLK_PORT]
set_max_fanout 16 [current_design]


# ---- Optional vectorless power defaults -----------------------------------
# Uncomment for quick power numbers without activity files:
# set_switching_activity -static_probability 0.5 -toggle_rate 0.1 [all_inputs]
# Better: provide real activity
# read_saif -input ../sim/aes_gcm.saif -strip_path <tb_path>/<dut_path>
# or:
# read_vcd  ../sim/aes_gcm.vcd -timescale ns -scope <tb_path> -strip_path <dut_path>
# set_power_analysis_mode time_based

# ---- Synthesize -----------------------------------------------------------
syn_generic         ;# high-level optimizations
syn_map             ;# technology mapping to the .lib
# syn_opt           ;# (optional) post-map timing/area/power optimization
check_design

# ---- Reports --------------------------------------------------------------
file mkdir $REPORTS_DIR
report_timing -max_paths 10                        > $REPORTS_DIR/${TOP}.timing.rpt
report area                                        > $REPORTS_DIR/${TOP}.area.rpt
report power                                       > $REPORTS_DIR/${TOP}.power.rpt

# ---- Outputs --------------------------------------------------------------
file mkdir $NETLIST_DIR
write_hdl -mapped -hierarchy -output $NETLIST_DIR/${TOP}.syn.v
write_sdc                          $NETLIST_DIR/${TOP}.sdc

puts "INFO: Single-corner TT synthesis done for $TOP."
puts "INFO: Netlist/SDC -> $NETLIST_DIR, Reports -> $REPORTS_DIR"
exit
