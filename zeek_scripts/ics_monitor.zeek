# zeek_scripts/ics_monitor.zeek
# ────────────────────────────────────────────────────────
# Load ICS analyzers and emit structured logs.
# Run with: sudo /opt/zeek/bin/zeek -C -i any zeek_scripts/ics_monitor.zeek
# The -C flag suppresses the checksum-offloading warning on WSL-2.

@load base/protocols/conn
@load base/misc/find-checksum-offloading

# Suppress the checksum noise common on WSL-2 virtual NICs
redef ignore_checksums = T;

# Use JSON for all logs (easier to parse in Python)
redef LogAscii::use_json = F;   # keep TSV — our parser expects it

# Rotate logs every hour
redef Log::default_rotation_interval = 1hr;

# ── Load ICS analyzers if installed ──────────────────────
# These are installed via:  zkg install icsnpp-modbus
# Comment out any that are not yet installed.

@load packages/icsnpp-modbus
# @load icsnpp/icsnpp-dnp3        # uncomment after: zkg install icsnpp-dnp3
# @load icsnpp/icsnpp-enip        # uncomment after: zkg install icsnpp-enip

# ── OT port tagging ──────────────────────────────────────
# Mark connections to known OT ports in conn.log service field.

const OT_PORTS: set[port] = {
    502/tcp,    # Modbus TCP (real PLC)
    5020/tcp,   # Modbus TCP (Conpot test port)
    20000/tcp,  # DNP3
    102/tcp,    # S7comm (Siemens)
    44818/tcp,  # EtherNet/IP
    47808/udp,  # BACnet
    6969/udp,   # TFTP (Conpot)
    2121/tcp,   # FTP (Conpot)
};

event connection_established(c: connection) {
    if (c$id$resp_p in OT_PORTS) {
        # Log to stdout so we see it in the terminal
        print fmt("[OT-CONN] %s:%d → %s:%d  (%s)",
            c$id$orig_h, c$id$orig_p,
            c$id$resp_h, c$id$resp_p,
            c$id$resp_p);
    }
}

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
    print fmt("[MODBUS ] src=%s  func=%d  is_request=%s",
        c$id$orig_h, headers$function_code, is_orig);
}
