# =====================================================================
# Genus single-corner TT synthesis for aes_gcm_top  (no MMMC)
# TSMC 40ULP 1.1V @ 25C  
# Expected run dir: syn/   
# =====================================================================

# --- default = aes_gcm_top; override with env TOP ---
if {[info exists ::env(TOP)]} {
  set DESIGN_NAME $::env(TOP)
} else {
  set DESIGN_NAME aes_gcm_top
}


# Your liberty directory and file (confirmed from your find output)
set LIB_DIR  "/opt/lib/tsmc/211005/tcbn40ulpbwp40_c170815_130d/TSMCHOME/digital/Front_End/timing_power_noise/NLDM/tcbn40ulpbwp40_c170815_130d"
set TT_LIB   "tcbn40ulpbwp40_c170815tt1p1v25c.lib"

# Clock & IO timing (example: 400 MHz = 2.5 ns period)
set CLK_PORT    clk
set CLK_NAME    core_clk
set CLK_PERIOD  2.5
set CLK_UNCERT  0.10
set IN_DELAY    0.5
set OUT_DELAY   0.5

# Project layout
set RTL_DIR            ../rtl
set AES_THIRDPARTY_DIR $RTL_DIR/third_party/secworks_aes/src/rtl
set REPORTS_DIR        reports
set NETLIST_DIR        ../netlist

# -------- Library load ------------------------------------------------
set_db lib_search_path [list $LIB_DIR]
set libpath [file join $LIB_DIR $TT_LIB]
if {![file exists $libpath]} {
  puts "ERROR: Liberty not found: $libpath"
  exit 1
}
read_libs $libpath
# Also set as mapping/link library
set_db library [list $libpath]

# --- Enable use of ICG cells (names seen in your logs) ---
set icg_list {}
foreach patt { *CKLHQD20BWP40 *CKLHQD24BWP40 *CKLNQD20BWP40 *CKLNQD24BWP40 } {
  set found [get_lib_cells $patt]
  if {[llength $found] > 0} { lappend icg_list {*}$found }
}
if {[llength $icg_list] > 0} {
  catch { remove_attribute $icg_list dont_use }
  puts "INFO: Enabled ICG cells (cleared dont_use): $icg_list"
} else {
  puts "NOTE: No CKL* ICG cells found; skipping dont_use removal."
}

# --- Try enabling auto clock gating (guard for your Genus build) ---
set _cg_on 0
if {!$_cg_on} { if {![catch { set_db lp_insert_clock_gating true }]}     { set _cg_on 1 ; puts "INFO: lp_insert_clock_gating enabled" } }
if {!$_cg_on} { if {![catch { set_db power_clock_gating true }]}          { set _cg_on 1 ; puts "INFO: power_clock_gating enabled" } }
if {!$_cg_on} { if {![catch { set_db design_power_optimization true }]}   {               puts "INFO: design_power_optimization enabled (may include gating)" } }

# Optional: minimum flops per gate (ignore if unsupported)
if {[catch { set_db clock_gating_min_flops 4 } err]} {
   puts "NOTE: 'clock_gating_min_flops' unsupported on this Genus; skipping."
}

# -------- RTL read & elaborate ---------------------------------------
set_db hdl_language sv
set_db init_hdl_search_path [list $RTL_DIR $AES_THIRDPARTY_DIR .]
set_db hdl_unconnected_value 0

# Collect files
set proj_files  [glob -nocomplain $RTL_DIR/*.v]
set aes_files   [glob -nocomplain $AES_THIRDPARTY_DIR/*.v]
if {[llength $proj_files] == 0} {
  puts "ERROR: No RTL found in $RTL_DIR"
  exit 1
}

# Preprocessor defines used by your design
set defs {SYNTHESIS AES_GCM AES AES_CORE SECWORKS_AES USE_GHASH}

read_hdl -sv -define $defs $proj_files
if {[llength $aes_files] > 0} {
  read_hdl -sv $aes_files
} else {
  puts "WARN: No secworks AES files found at $AES_THIRDPARTY_DIR"
}

elaborate $DESIGN_NAME
check_design

# -------- Constraints --------------------------------------------------
create_clock -name $CLK_NAME -period $CLK_PERIOD [get_ports $CLK_PORT]
set_clock_uncertainty $CLK_UNCERT [get_clocks $CLK_NAME]

# Apply I/O delays to all except clk and rst_n
set in_excl  [list $CLK_PORT rst_n]
set_input_delay  $IN_DELAY  -clock $CLK_NAME [remove_from_collection [all_inputs]  [get_ports $in_excl]]
set_output_delay $OUT_DELAY -clock $CLK_NAME [all_outputs]

# Auto-pick a reasonable driving cell (INVX* preferred, fallback BUFX*)
proc _pick_mid_strength {pattern prefer} {
  set cells [get_lib_cells $pattern]
  set ranked {}
  foreach c $cells {
    if {[regexp -nocase {X([0-9]+)} $c -> drv]} { lappend ranked [list [expr {$drv}] $c] }
  }
  if {[llength $ranked] == 0} { return "" }
  set ranked [lsort -integer -index 0 $ranked]
  foreach item $ranked { if {[lindex $item 0] == $prefer} { return [lindex $item 1] } }
  set mid [expr {[llength $ranked] / 2}]
  return [lindex [lindex $ranked $mid] 1]
}
set _drv_cell [_pick_mid_strength "*INVX*" 4]
if {$_drv_cell eq ""} { set _drv_cell [_pick_mid_strength "*BUFX*" 4] }
if {$_drv_cell ne ""} {
  puts "INFO: Using driving cell: $_drv_cell"
  set in_excl  [list $CLK_PORT rst_n]
  set_driving_cell -lib_cell $_drv_cell [remove_from_collection [all_inputs] [get_ports $in_excl]]
} else {
  puts "WARN: No INVX*/BUFX* cells found; skipping set_driving_cell."
}
unset -nocomplain _drv_cell

# Keep your existing:
# set_load 0.02 [all_outputs]
catch { set_clock_transition 0.05 [get_clocks $CLK_NAME] }



# Common cleanup
set_false_path -from [get_ports rst_n]
set_dont_touch_network [get_ports $CLK_PORT]
set_max_fanout 16 [current_design]

# -------- Synthesis ----------------------------------------------------
syn_generic
syn_map
syn_opt
check_design

# Adjust these paths to where your sim dumps VCD/SAIF
"""
set SAIF_PATH  "../waves/${DESIGN_NAME}.saif"
set VCD_PATH   "../waves/${DESIGN_NAME}.vcd"
set TOP_INST   "/$DESIGN_NAME"         ;

set _activity_loaded 0
if {[file exists $SAIF_PATH]} {
  puts "INFO: Reading SAIF: $SAIF_PATH"
  if {![catch { read_saif -input $SAIF_PATH -instance $TOP_INST } emsg]} {
    set _activity_loaded 1
    catch { set_db power_analysis_mode time_based }
  } else {
    puts "WARN: read_saif failed: $emsg"
  }
} elseif {[file exists $VCD_PATH]} {
  puts "INFO: SAIF not found; attempting to read VCD: $VCD_PATH"
  # Some Genus versions support read_vcd; guard it
  if {![catch { read_vcd -file $VCD_PATH -scope $TOP_INST } emsg]} {
    set _activity_loaded 1
    catch { set_db power_analysis_mode time_based }
  } else {
    puts "WARN: read_vcd failed: $emsg"
  }
} else {
  puts "NOTE: No SAIF/VCD found; falling back to vectorless power."
}

# If nothing loaded, optional vectorless mode.
if {!$_activity_loaded} {
  catch { set_db power_analysis_mode averaged }
}
"""
# -------- Switching activity (SAIF/VCD) --------------------------------
set SAIF_PATH  "../waves/${DESIGN_NAME}.saif"
set VCD_PATH   "../waves/${DESIGN_NAME}.vcd"
set TOP_INST   "/$DESIGN_NAME"

set _activity_loaded 0
if {[file exists $SAIF_PATH]} {
  puts "INFO: Reading SAIF: $SAIF_PATH"
  if {![catch { read_saif -input $SAIF_PATH -instance $TOP_INST } emsg]} {
    set _activity_loaded 1
    # Some Genus builds support this; yours may not. Guard it.
    if {[catch { set_db power_analysis_mode time_based } _e]} {
      puts "NOTE: 'power_analysis_mode' unsupported here; using default vector-based power."
    }
  } else {
    puts "WARN: read_saif failed: $emsg"
  }
} elseif {[file exists $VCD_PATH]} {
  puts "INFO: SAIF not found; attempting VCD: $VCD_PATH"
  if {![catch { read_vcd -file $VCD_PATH -scope $TOP_INST } emsg]} {
    set _activity_loaded 1
    if {[catch { set_db power_analysis_mode time_based } _e]} {
      puts "NOTE: 'power_analysis_mode' unsupported here; using default vector-based power."
    }
  } else {
    puts "WARN: read_vcd failed: $emsg"
  }
} else {
  puts "NOTE: No SAIF/VCD found; falling back to vectorless power."
}

if {!$_activity_loaded} {
  # Explicit vectorless path; guard the knob as well.
  catch { set_db power_enable_analysis true }
  if {[catch { set_db power_analysis_mode averaged } _e]} {
    puts "NOTE: Using tool default vectorless mode (no SAIF/VCD)."
  }
}
# -------- Switching activity (SAIF/VCD) --------------------------------
set SAIF_PATH  "../waves/${DESIGN_NAME}.saif"
set VCD_PATH   "../waves/${DESIGN_NAME}.vcd"
set TOP_INST   "/$DESIGN_NAME"

set _activity_loaded 0
if {[file exists $SAIF_PATH]} {
  puts "INFO: Reading SAIF: $SAIF_PATH"
  if {![catch { read_saif -input $SAIF_PATH -instance $TOP_INST } emsg]} {
    set _activity_loaded 1
    # Some Genus builds support this; yours may not. Guard it.
    if {[catch { set_db power_analysis_mode time_based } _e]} {
      puts "NOTE: 'power_analysis_mode' unsupported here; using default vector-based power."
    }
  } else {
    puts "WARN: read_saif failed: $emsg"
  }
} elseif {[file exists $VCD_PATH]} {
  puts "INFO: SAIF not found; attempting VCD: $VCD_PATH"
  if {![catch { read_vcd -file $VCD_PATH -scope $TOP_INST } emsg]} {
    set _activity_loaded 1
    if {[catch { set_db power_analysis_mode time_based } _e]} {
      puts "NOTE: 'power_analysis_mode' unsupported here; using default vector-based power."
    }
  } else {
    puts "WARN: read_vcd failed: $emsg"
  }
} else {
  puts "NOTE: No SAIF/VCD found; falling back to vectorless power."
}

if {!$_activity_loaded} {
  # Explicit vectorless path; guard the knob as well.
  catch { set_db power_enable_analysis true }
  if {[catch { set_db power_analysis_mode averaged } _e]} {
    puts "NOTE: Using tool default vectorless mode (no SAIF/VCD)."
  }
}


file mkdir $REPORTS_DIR
file mkdir $NETLIST_DIR

# Multi-driver nets (portable)
if {![catch {report_nets -help} _]} {
  if {![catch {report_nets -multi_driver} _md]} {
    set fp [open "$REPORTS_DIR/multidriven.rpt" w]; puts $fp $_md; close $fp
  } elseif {![catch {report_nets -multi_drivers} _md2]} {
    set fp [open "$REPORTS_DIR/multidriven.rpt" w]; puts $fp $_md2; close $fp
  } else {
    puts "NOTE: multi-driver nets option not available on this Genus."
  }
}

report_hierarchy            > $REPORTS_DIR/hierarchy.rpt
report_timing -max_paths 10 > $REPORTS_DIR/${DESIGN_NAME}.timing.rpt
report_area                 > $REPORTS_DIR/${DESIGN_NAME}.area.rpt
report_power                > $REPORTS_DIR/${DESIGN_NAME}.power.rpt

write_netlist $DESIGN_NAME  > $NETLIST_DIR/${DESIGN_NAME}.syn.v
write_sdc     $DESIGN_NAME  > $NETLIST_DIR/${DESIGN_NAME}.sdc
write_script  $DESIGN_NAME  > $NETLIST_DIR/replay_genus.tcl

puts "INFO: Synthesis DONE for $DESIGN_NAME"
puts "INFO: Netlist/SDC -> $NETLIST_DIR"
puts "INFO: Reports     -> $REPORTS_DIR"
exit
