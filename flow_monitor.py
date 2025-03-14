#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import time
import re
import os
import sys
import pandas as pd

def get_raw_flows(switch="s1"):
    """
    Thực thi ovs-ofctl dump-flows và trả về chuỗi kết quả thô
    (bao gồm nhiều dòng).
    """
    try:
        result = subprocess.check_output(
            ["/usr/bin/ovs-ofctl", "dump-flows", switch],
            stderr=subprocess.STDOUT
        ).decode("utf-8")  # chuyển từ byte sang string
        return result
    except subprocess.CalledProcessError as e:
        print("\n[ERROR] Lỗi khi lấy flow table: {}".format(e.output))
        return ""

def split_multiline_flows(raw_data):
    """
    Gom các dòng liên quan đến cùng một flow thành một chuỗi duy nhất.
    Trả về danh sách các flow (mỗi flow là 1 string).
    """
    lines = raw_data.splitlines()
    # Bỏ các dòng trống hoặc chứa "NXST_FLOW reply"
    lines = [
        ln for ln in lines
        if ln.strip() and not ln.startswith("NXST_FLOW reply")
    ]

    # Kết quả sẽ là list flow, mỗi flow là 1 string đầy đủ
    combined_flows = []
    current_flow = []

    for ln in lines:
        ln_stripped = ln.strip()
        # Mỗi flow mới thường bắt đầu với "cookie=0x"
        # => nếu thấy dòng bắt đầu với cookie=0x => flow mới
        if ln_stripped.startswith("cookie=0x"):
            # nếu current_flow không rỗng => append flow cũ
            if current_flow:
                combined_flows.append(" ".join(current_flow))
                current_flow = []
            current_flow.append(ln_stripped)
        else:
            # dòng nối tiếp flow cũ
            # đôi khi OVS in ra " cookie=0x..." thay vì "cookie=0x..."
            # nên ta xử lý " cookie=0x" tương tự
            current_flow.append(ln_stripped)

    # flow cuối cùng
    if current_flow:
        combined_flows.append(" ".join(current_flow))

    return combined_flows

def parse_flow_entry(flow_str):
    """
    Trích xuất thông tin từ chuỗi flow (đã được ghép 1 dòng).
    """
    pattern = (
        r"cookie=0x(?P<cookie>[0-9a-fA-F]+),\s*"
        r"duration=(?P<duration>[\d.]+)s,\s*"
        r"table=(?P<table>\d+),\s*"
        r"n_packets=(?P<n_packets>\d+),\s*"
        r"n_bytes=(?P<n_bytes>\d+),\s*"
        r"idle_timeout=(?P<idle_timeout>\d+),\s*"
        r"hard_timeout=(?P<hard_timeout>\d+),\s*"
        r"(?:idle_age=\d+,\s*)?"  # idle_age=.. có thể xuất hiện
        r"priority=(?P<priority>\d+)(?:,)?(?P<protocol>[a-zA-Z]+)?,?"
        r".*?in_port=?\"?(?P<in_port>[^\s,]+)\"?,?"
        r".*?nw_src=(?P<nw_src>[\d.]+)?,?"
        r".*?nw_dst=(?P<nw_dst>[\d.]+)?,?"
        r".*?actions=(?P<actions>.+)"
    )

    m = re.search(pattern, flow_str)
    if not m:
        return None

    # Lưu kết quả vào dictionary
    gd = m.groupdict()
    # Xử lý protocol=null
    if gd.get("protocol"):
        gd["protocol"] = gd["protocol"].strip()
    return gd

def display_flows(flow_data):
    """ Hiển thị danh sách flows dưới dạng bảng Pandas """
    if not flow_data:
        print("Không có flow nào.")
        return

    df = pd.DataFrame(flow_data.values())
    # Kiểm tra cột => tránh KeyError nếu thiếu
    columns = ["cookie","duration","priority","protocol","in_port","nw_src","nw_dst","actions","n_packets"]
    for col in columns:
        if col not in df.columns:
            df[col] = ""

    df = df[columns]
    df = df.rename(columns={
        "cookie": "Cookie",
        "duration": "Duration (s)",
        "priority": "Priority",
        "protocol": "Protocol",
        "in_port": "In Port",
        "nw_src": "Source IP",
        "nw_dst": "Destination IP",
        "actions": "Actions",
        "n_packets": "Packets"
    })
    # Sắp xếp theo Priority giảm dần, Duration tăng dần
    df = df.sort_values(by=["Priority", "Duration (s)"], ascending=[False, True])

    os.system("clear")
    print("📡 Đang theo dõi flow table...\n")
    print(df.to_string(index=False))
    print("=" * 110)

def monitor_flows(switch="s1", interval=2):
    prev_flows = {}

    while True:
        raw_data = get_raw_flows(switch)
        flow_list = split_multiline_flows(raw_data)

        current_flows = {}
        for flow_str in flow_list:
            flow_data = parse_flow_entry(flow_str)
            if flow_data:
                # Tạo key để so sánh
                key = "{}:{}->{}({})".format(
                    flow_data.get("cookie","-"),
                    flow_data.get("nw_src","-"),
                    flow_data.get("nw_dst","-"),
                    flow_data.get("protocol","-")
                )
                current_flows[key] = flow_data

        # Hiển thị
        display_flows(current_flows)

        # So sánh với prev_flows
        new_flows = {k:v for k,v in current_flows.items() if k not in prev_flows}
        removed_flows = {k:v for k,v in prev_flows.items() if k not in current_flows}

        if new_flows:
            print("\n🔹 [NEW FLOWS DETECTED]")
            for k, v in new_flows.items():
                print("➕ {}: {}".format(k, v))

        if removed_flows:
            print("\n🔻 [REMOVED FLOWS]")
            for k, v in removed_flows.items():
                print("❌ {}: {}".format(k, v))

        prev_flows = current_flows.copy()
        time.sleep(interval)

if __name__ == "__main__":
    monitor_flows()
