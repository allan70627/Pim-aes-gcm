# Cadence Genus synthesis for aes_gcm_top

# ---- User-editable section -----------------------------------------------
# If your Liberty libs are under an env var, export it before running Genus:
#   Linux:  export TSMC_PDK_PATH=/path/to/TSMCHOME/.../NLDM/tcbn40ulpbwp40_c170815_130d
#   Windows: setx TSMC_PDK_PATH "C:\\path\\to\\...\\NLDM\\tcbn40ulpbwp40_c170815_130d"

if { [info exists ::env(TSMC_PDK_PATH)] } {
  set TSMC_PDK_PATH $::env(TSMC_PDK_PATH)
} else {
  # Fallback example path — update to your installation
  set TSMC_PDK_PATH \
    "/opt/lib/tsmc/211005/tcbn40ulpbwp40_c170815_130d/TSMCHOME/digital/Front_End/timing_power_noise/NLDM/tcbn40ulpbwp40_c170815_130d"
}

# Liberty libraries (use .lib for Genus). Replace with your corners as needed.
set LIBS [list \
  tcbn40ulpbwp40_c170815tt1p1v25c.lib \
  tcbn40ulpbwp40_c170815ffg1p21vm40c.lib \
]

# Timing targets (example: 400 MHz)
set CLK_NAME  core_clk
set CLK_PORT  clk
set CLK_PER   2.5
set CLK_UNC   0.10
set IN_DLY    0.5
set OUT_DLY   0.5

# Top and paths (script is expected to run from syn/)
set TOP          aes_gcm_top
set RTL_DIR      ../rtl
set AES_THIRDPARTY_DIR $RTL_DIR/third_party/secworks_aes/src/rtl
set REPORTS_DIR  reports
set NETLIST_DIR  ../netlist

# Optional: multi-CPU (Genus will parallelize by default; adjust if desired)
# set_db max_cpus 8

# ---- Setup ----------------------------------------------------------------
if { [llength $TSMC_PDK_PATH] > 1 } {
  set_db lib_search_path $TSMC_PDK_PATH
} else {
  set_db lib_search_path [list $TSMC_PDK_PATH]
}

set db_loaded_libs 0
foreach lib $LIBS {
  set loaded 0
  foreach libdir $TSMC_PDK_PATH {
    set libpath [file join $libdir $lib]
    if { [file exists $libpath] } {
      read_libs $libpath
      incr db_loaded_libs
      set loaded 1
      break
    }
  }
  if { !$loaded } {
    puts "WARN: Liberty not found in any lib_search_path: $lib"
  }
}
if { $db_loaded_libs == 0 } {
  puts "ERROR: No Liberty libraries were found/read. Check TSMC_PDK_PATH and LIBS."
}

set_db hdl_search_path [list $RTL_DIR $AES_THIRDPARTY_DIR .]

# ---- Read/Elaborate -------------------------------------------------------
read_hdl $RTL_DIR/$TOP.v
# If/when you instantiate the AES core, uncomment to read its RTL:
# read_hdl [glob -nocomplain $AES_THIRDPARTY_DIR/*.v]

elaborate $TOP
link

# ---- Constraints ----------------------------------------------------------
create_clock -period $CLK_PER -name $CLK_NAME [get_ports $CLK_PORT]
set_clock_uncertainty $CLK_UNC [get_clocks $CLK_NAME]

# Apply I/O delays to all except clk and rst_n
set_input_delay  $IN_DLY  -clock $CLK_NAME [remove_from_collection [all_inputs] {${CLK_PORT} rst_n}]
set_output_delay $OUT_DLY -clock $CLK_NAME [all_outputs]

set_false_path -from [get_ports rst_n]
set_dont_touch_network [get_ports $CLK_PORT]
set_fix_multiple_port_nets -all -buffer_constants
set_max_fanout 16 [current_design]

# Optional vector-less activity (uncomment if you want power with default activity)
# set_switching_activity -static_probability 0.5 -toggle_rate 0.1 [all_inputs]

# ---- Synthesize -----------------------------------------------------------
synthesize -to_mapped -effort high

# ---- Reports --------------------------------------------------------------
file mkdir $REPORTS_DIR
report_timing -max_paths 10 > $REPORTS_DIR/${TOP}.timing.rpt
report area                        > $REPORTS_DIR/${TOP}.area.rpt
report power                       > $REPORTS_DIR/${TOP}.power.vecless.rpt

# ---- Outputs --------------------------------------------------------------
file mkdir $NETLIST_DIR
write_hdl -mapped -hierarchy -output $NETLIST_DIR/${TOP}.syn.v
write_sdc $NETLIST_DIR/${TOP}.sdc

puts "INFO: Genus synthesis completed for $TOP. Netlist/SDC in $NETLIST_DIR."
