#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from scapy.all import *
import csv

def main():
    # Read the pcap
    packets = rdpcap("scan_capture.pcap")

    # We'll keep track of each outbound SYN in a list, storing
    #   (index, seq, status, responseType).
    # 'status' initially is "pending", changed to "success"/"fail".
    # 'seq' is the TCP sequence number for matching with ack of the reply.
    syn_list = []

    # We'll have an incremental index for each outbound SYN from attacker -> target
    i = 0

    # 1) Collect outbound SYN packets
    for p in packets:
        if p.haslayer(IP) and p.haslayer(TCP):
            ipL = p[IP]
            tcpL = p[TCP]

            # Condition: from attacker => we guess attacker is 10.0.0.1
            #   SYN=1, ACK=0 => outgoing connection request
            if ipL.src == "10.0.0.1" and ipL.dst == "10.0.1.10":
                if tcpL.flags == 0x02:  # 0x02 == SYN bit only
                    syn_list.append({
                        'index': i,
                        'seq': tcpL.seq,
                        'status': "pending",
                        'rsp': None
                    })
                    i += 1

    # 2) Look for inbound responses from target => attacker
    for p in packets:
        if p.haslayer(IP) and p.haslayer(TCP):
            ipL = p[IP]
            tcpL = p[TCP]

            # Condition: from target => attacker
            if ipL.src == "10.0.1.10" and ipL.dst == "10.0.0.1":
                # check the ack number
                ack_num = tcpL.ack
                flags = tcpL.flags
                # We'll match syn_list entry whose (seq + 1) == ack_num
                for syn_entry in syn_list:
                    if syn_entry['status'] == "pending":
                        if syn_entry['seq'] + 1 == ack_num:
                            # Found a match
                            if (flags & 0x12) == 0x12:
                                # 0x12 => SYN+ACK
                                syn_entry['status'] = "success"
                                syn_entry['rsp'] = "SYN+ACK"
                            elif flags & 0x04:
                                # RST
                                syn_entry['status'] = "fail"
                                syn_entry['rsp'] = "RST"
                            else:
                                # Some other weird flag
                                syn_entry['status'] = "fail"
                                syn_entry['rsp'] = "Other"
                            break  # done

    # 3) All 'pending' left => no response => fail
    for entry in syn_list:
        if entry['status'] == "pending":
            entry['status'] = "fail"
            entry['rsp'] = "NoResponse"

    # 4) Write to CSV
    with open("scan_parsed.csv", "wb") as f:
        writer = csv.writer(f)
        writer.writerow(["ReqIndex", "SeqNum", "Status", "ResponseType"])
        for entry in syn_list:
            writer.writerow([
                entry['index'],
                entry['seq'],
                entry['status'],
                entry['rsp']
            ])

    print("Done. See 'scan_parsed.csv' for per-request results.")

if __name__ == "__main__":
    main()
