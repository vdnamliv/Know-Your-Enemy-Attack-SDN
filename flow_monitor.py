#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
import subprocess
import time
import re
import os
import sys
import pandas as pd
from datetime import datetime

def get_raw_flows(switch="s1"):
    """
    Thực thi ovs-ofctl dump-flows <switch> và trả về chuỗi kết quả thô.
    """
    try:
        result = subprocess.check_output(
            ["/usr/bin/ovs-ofctl", "dump-flows", switch],
            stderr=subprocess.STDOUT
        )
        # Ở Python 2.7, result là bytes => decode sang str
        return result.decode("utf-8")
    except subprocess.CalledProcessError as e:
        print("\n[ERROR] Lỗi khi lấy flow table: {}".format(e.output))
        return ""

def split_multiline_flows(raw_data):
    """
    Gom các dòng liên quan đến cùng một flow thành 1 chuỗi duy nhất.
    """
    lines = raw_data.splitlines()
    # Bỏ các dòng trống hoặc chứa "NXST_FLOW reply"
    lines = [ln for ln in lines if ln.strip() and not ln.startswith("NXST_FLOW reply")]
    combined_flows = []
    current_flow = []

    for ln in lines:
        ln_stripped = ln.strip()
        if ln_stripped.startswith("cookie=0x"):
            # flow mới
            if current_flow:
                combined_flows.append(" ".join(current_flow))
                current_flow = []
            current_flow.append(ln_stripped)
        else:
            current_flow.append(ln_stripped)

    if current_flow:
        combined_flows.append(" ".join(current_flow))

    return combined_flows

def parse_flow_entry(flow_str):
    """
    Trích xuất thông tin cơ bản từ 1 dòng flow. Ví dụ:
    cookie=0x0, duration=29.470s, table=0, n_packets=2, ...
    priority=65535,arp,in_port="s1-eth1",vlan_tci=0x0000,...
    actions=output:"s1-eth2"

    Chú ý: OVS đôi khi thay đổi thứ tự fields. Regex này cố gắng 
    match nhiều field optional, *nếu* có.
    """
    pattern = (
        r"cookie=0x(?P<cookie>[0-9A-Fa-f]+),\s*"
        r"duration=(?P<duration>[\d\.]+)s,\s*"
        r"table=(?P<table>\d+),\s*"
        r"n_packets=(?P<n_packets>\d+),\s*"
        r"n_bytes=(?P<n_bytes>\d+),\s*"
        r"idle_timeout=(?P<idle_timeout>\d+),\s*"
        r"hard_timeout=(?P<hard_timeout>\d+),\s*"
        r"(?:idle_age=\d+,\s*)?"  # có thể có idle_age=xx,
        r"priority=(?P<priority>\d+)"            # priority=65535
        r"(?:,(?P<protocol>[a-zA-Z]+))?"         # vd ",arp" hoặc ",ip" ...
        r"(?:,in_port=\"?(?P<in_port>[^\s,]+)\"?)?"   # in_port="s1-eth1"
        r"(?:,vlan_tci=0x(?P<vlan_tci>[0-9A-Fa-f]+))?" # vlan_tci=0x0000
        r"(?:,dl_src=(?P<dl_src>[0-9A-Fa-f:]+))?"     # dl_src=1a:c9:...
        r"(?:,dl_dst=(?P<dl_dst>[0-9A-Fa-f:]+))?"     # dl_dst=0a:a2:...
        r"(?:,arp_spa=(?P<arp_spa>[\d\.]+))?"         # arp_spa=10.0.0.254
        r"(?:,arp_tpa=(?P<arp_tpa>[\d\.]+))?"
        r"(?:,arp_op=(?P<arp_op>\d+))?"
        r"(?:,nw_src=(?P<nw_src>[\d\.]+))?"
        r"(?:,nw_dst=(?P<nw_dst>[\d\.]+))?"
        r".*?actions=(?P<actions>.+)"
    )

    m = re.search(pattern, flow_str)
    if not m:
        # in ra debug nếu muốn
        #print("Không match: {}".format(flow_str))
        return None

    return m.groupdict()

def display_and_save_flows(flow_data, switch="s1"):
    """
    Hiển thị flows ra màn hình & lưu CSV.
    """
    if not flow_data:
        print("Không có flow nào.\n")
        return

    df = pd.DataFrame(flow_data.values())

    # Đảm bảo cột
    needed_cols = [
        "cookie","duration","table","n_packets","n_bytes",
        "idle_timeout","hard_timeout","priority","protocol","in_port",
        "vlan_tci","dl_src","dl_dst","arp_spa","arp_tpa","arp_op",
        "nw_src","nw_dst","actions"
    ]
    for col in needed_cols:
        if col not in df.columns:
            df[col] = ""

    # Chuyển kiểu
    def to_int(x):
        try:
            return int(x)
        except:
            return 0
    def to_float(x):
        try:
            return float(x)
        except:
            return 0.0

    df["priority"] = df["priority"].apply(to_int)
    df["table"]    = df["table"].apply(to_int)
    df["n_packets"]= df["n_packets"].apply(to_int)
    df["n_bytes"]  = df["n_bytes"].apply(to_int)
    df["duration"] = df["duration"].apply(to_float)

    # Sắp xếp
    df = df.sort_values(by=["table","priority","duration"], ascending=[True,False,True])

    # Clear screen
    try:
        os.system("clear")
    except:
        pass

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("📡 Flow table on {} - {}\n".format(switch, now_str))
    print(df.to_string(index=False))
    print("=" * 130)

    # Lưu CSV => append
    csv_name = "{}_flows.csv".format(switch)
    write_header = not os.path.isfile(csv_name)
    df.to_csv(csv_name, mode='a', header=write_header, index=False, encoding='utf-8')
    print("[Saved flows to {}]\n".format(csv_name))

def monitor_flows(switch="s1", interval=2):
    prev_flows = {}

    while True:
        raw_data = get_raw_flows(switch)
        flow_list = split_multiline_flows(raw_data)
        current_flows = {}

        for flow_str in flow_list:
            fdata = parse_flow_entry(flow_str)
            if fdata:
                # Dùng cookie+table+priority+nw_src+nw_dst... làm key
                key = "c={} tbl={} prio={} {}/{}".format(
                    fdata.get("cookie","-"),
                    fdata.get("table","?"),
                    fdata.get("priority","?"),
                    fdata.get("nw_src","-"),
                    fdata.get("nw_dst","-")
                )
                current_flows[key] = fdata

        display_and_save_flows(current_flows, switch)

        # So sánh new / removed flows
        new_flows = {k:v for k,v in current_flows.items() if k not in prev_flows}
        removed_flows = {k:v for k,v in prev_flows.items() if k not in current_flows}

        if new_flows:
            print("🔹 [NEW FLOWS]")
            for k, v in new_flows.items():
                print("  ➕ {} => actions={}".format(k, v.get("actions","")))

        if removed_flows:
            print("🔻 [REMOVED FLOWS]")
            for k, v in removed_flows.items():
                print("  ❌ {}".format(k))

        prev_flows = current_flows
        time.sleep(interval)

if __name__ == "__main__":
    sw = "s1"
    if len(sys.argv) > 1:
        sw = sys.argv[1]
    monitor_flows(switch=sw, interval=3)
