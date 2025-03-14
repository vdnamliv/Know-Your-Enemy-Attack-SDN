#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
probe_scan.py
-------------
Run a SINGLE scanning batch from Mininet host h1 to other hosts.

Usage (inside xterm h1):
    python probe_scan.py
"""

import subprocess
import time

def run_single_batch(targets, rate, count, ports):
    """
    Runs a single batch scan from h1 to given targets on specified ports.
    'rate' is the hping3 -i argument (e.g. 'u100000' => microseconds).
    'count' is the number of packets to send.
    'ports' is a list of TCP ports to scan.
    """
    for tgt in targets:
        for p in ports:
            # hping3 -S => SYN packets
            # e.g. hping3 10.0.0.5 -S -p 80 -c 100 -i u100000
            cmd_list = [
                "hping3", tgt,
                "-S",
                "-p", str(p),
                "-c", str(count),
                "-i", rate
            ]
            print("[*] Scanning %s:%d -> rate=%s count=%d"
                  % (tgt, p, rate, count))
            proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            # If you want to see the output of hping3, uncomment:
            # print out, err
            time.sleep(0.5)  # short pause between scans

def main():
    # Example: we have hosts h2..h30 => 10.0.0.2..10.0.0.30
    targets = ["10.0.0.%d" % i for i in range(2, 31)]
    
    # Single batch parameters
    # Adjust them each time you want a new scenario
    rate  = "u100000"   # microseconds between packets (e.g. 0.1s => "u100000")
    count = 50          # number of packets for each port
    ports = [80]        # or multiple ports like [22, 80, 443]
    
    print("[INFO] Starting single-batch scan from h1...")
    run_single_batch(targets, rate, count, ports)
    print("[INFO] Done scanning. Now exit h1 xterm or adjust parameters again.")

if __name__ == "__main__":
    main()
