#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function
import subprocess
import time
import re
import os
import sys

# Hàm lấy raw flow table từ switch
def get_raw_flows(switch="s1"):
    try:
        result = subprocess.check_output(
            ["/usr/bin/ovs-ofctl", "dump-flows", switch],
            stderr=subprocess.STDOUT
        )
        return result.decode("utf-8")
    except subprocess.CalledProcessError as e:
        print("\n[ERROR] Lỗi khi lấy flow table: {}".format(e.output))
        return ""

# Hàm gom các dòng flow
def split_multiline_flows(raw_data):
    lines = raw_data.splitlines()
    lines = [ln for ln in lines if ln.strip() and not ln.startswith("NXST_FLOW reply")]
    combined_flows = []
    current_flow = []

    for ln in lines:
        ln_stripped = ln.strip()
        if ln_stripped.startswith("cookie=0x"):
            if current_flow:
                combined_flows.append(" ".join(current_flow))
                current_flow = []
            current_flow.append(ln_stripped)
        else:
            current_flow.append(ln_stripped)

    if current_flow:
        combined_flows.append(" ".join(current_flow))
    return combined_flows

# Hàm parse flow entry
def parse_flow_entry(flow_str):
    pattern = (
        r"cookie=0x(?P<cookie>[0-9A-Fa-f]+),\s*"
        r"duration=(?P<duration>[\d\.]+)s,\s*"
        r"table=(?P<table>\d+),\s*"
        r"n_packets=(?P<n_packets>\d+),\s*"
        r"n_bytes=(?P<n_bytes>\d+),\s*"
        r"idle_timeout=(?P<idle_timeout>\d+),\s*"
        r"hard_timeout=(?P<hard_timeout>\d+),\s*"
        r"(?:idle_age=\d+,\s*)?"
        r"priority=(?P<priority>\d+)"
        r"(?:,(?P<protocol>[a-zA-Z]+))?"
        r"(?:,in_port=\"?(?P<in_port>[^\s,]+)\"?)?"
        r"(?:,vlan_tci=0x(?P<vlan_tci>[0-9A-Fa-f]+))?"
        r"(?:,dl_src=(?P<dl_src>[0-9A-Fa-f:]+))?"
        r"(?:,dl_dst=(?P<dl_dst>[0-9A-Fa-f:]+))?"
        r"(?:,arp_spa=(?P<arp_spa>[\d\.]+))?"
        r"(?:,arp_tpa=(?P<arp_tpa>[\d\.]+))?"
        r"(?:,arp_op=(?P<arp_op>\d+))?"
        r"(?:,nw_src=(?P<nw_src>[\d\.]+))?"
        r"(?:,nw_dst=(?P<nw_dst>[\d\.]+))?"
        r".*?actions=(?P<actions>.+)"
    )
    m = re.search(pattern, flow_str)
    if m:
        return m.groupdict()
    return None

# Hàm gửi ICMP spoofed
def send_icmp_spoof(src_ip, dst_ip):
    cmd = [
        "hping3",
        "--icmp", dst_ip,
        "-a", src_ip,
        "-c", "5",
    ]
    try:
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)
    except Exception as e:
        print("Lỗi khi gửi ICMP: {}".format(e))

# Hàm kiểm tra quy tắc Access Control (dựa trên controller)
def is_allowed_access(src_sub, dst_sub):
    deny_pairs = [
        (1, 2), (2, 1),  # 10.0.1.x <-> 10.0.2.x
        (3, 4), (4, 3),  # 10.0.3.x <-> 10.0.4.x
        (4, 5), (5, 4),  # 10.0.4.x <-> 10.0.5.x
    ]
    return (src_sub, dst_sub) not in deny_pairs

# Hàm xây dựng Subnetwork Access Matrix
def build_subnet_matrix(switch="s1"):
    subnets = range(6)
    matrix = [["DENY" for _ in subnets] for _ in subnets]

    # Đặt ALLOW cho các cặp cùng subnet
    for i in subnets:
        matrix[i][i] = "ALLOW"

    # Gửi ICMP và phân tích flow table cho các cặp khác subnet
    for src_sub in subnets:
        for dst_sub in subnets:
            if src_sub == dst_sub:  # Bỏ qua vì đã đặt ALLOW
                continue

            src_ip = "10.0.{}.1".format(src_sub)
            dst_ip = "10.0.{}.1".format(dst_sub)

            # Trường hợp đặc biệt: đích là h1 (10.0.0.1)
            if dst_sub == 0:
                matrix[src_sub][dst_sub] = "ALLOW" if is_allowed_access(src_sub, dst_sub) else "DENY"
                print("Kiểm tra logic: {} -> {} = {}".format(src_ip, dst_ip, matrix[src_sub][dst_sub]))
                continue

            # Xóa flow table trước mỗi lần gửi
            subprocess.call(["ovs-ofctl", "del-flows", switch])

            # Gửi gói ICMP spoofed
            print("Gửi ICMP: {} -> {}".format(src_ip, dst_ip))
            send_icmp_spoof(src_ip, dst_ip)

            # Lấy và parse flow table
            raw_data = get_raw_flows(switch)
            flow_list = split_multiline_flows(raw_data)
            flows = [parse_flow_entry(f) for f in flow_list if parse_flow_entry(f)]

            # Tìm flow tương ứng
            found = False
            for flow in flows:
                if (flow["nw_src"] == src_ip and 
                    flow["nw_dst"] == dst_ip and 
                    flow["protocol"] == "icmp"):
                    actions = flow["actions"]
                    if "output" in actions and int(flow["n_packets"]) > 0:
                        matrix[src_sub][dst_sub] = "ALLOW"
                    found = True
                    break
            if not found:
                matrix[src_sub][dst_sub] = "DENY"

    # In matrix
    print("========== Subnetwork Access Matrix ==========")
    print("       ", end="")
    for j in subnets:
        print(" {:>2}".format(j), end="")
    print("")
    for i in subnets:
        print("sub{:>2}".format(i), end=" ")
        for j in subnets:
            val = matrix[i][j]
            cell = "✓" if val == "ALLOW" else "✗"
            print("  {}".format(cell), end="")
        print("")
    print("==============================================")

    return matrix

if __name__ == "__main__":
    switch = "s1"
    if len(sys.argv) > 1:
        switch = sys.argv[1]
    
    # Xóa flow table cũ ban đầu
    subprocess.call(["ovs-ofctl", "del-flows", switch])
    print("Đã xóa flow table cũ trên {}".format(switch))
    
    # Xây dựng matrix
    build_subnet_matrix(switch)
