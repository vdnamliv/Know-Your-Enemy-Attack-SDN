#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
POX Controller:
1) L2 Learning switch (ARP, ICMP, v.v.).
2) TRW-CB scanning detection:
   - Nếu nhận được TCP SYN từ cổng FAKE_OPEN_PORTS (ví dụ: 80, 443, 8080) => tính là success.
   - Nếu nhận được TCP SYN từ cổng khác, hoặc nhận gói TCP RST => tính là fail.
   - Mỗi success tăng SUCCESS_INC credits, mỗi fail giảm FAIL_DEC credits.
   - Nếu tỉ lệ thất bại >= 0.55 hoặc credits <= 0, host sẽ bị block (cài drop flow).
No timer cho "no response" => ta tự quyết định cổng đóng = fail ngay.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4, tcp
import time
from collections import defaultdict

log = core.getLogger()

# -------------------- TRW-CB Parameters --------------------
BASE_CREDITS = 10       # Initial credits for each host
SUCCESS_INC  = 2        # Increase credits on success
FAIL_DEC     = 1        # Decrease credits on fail
FAIL_RATIO_THRESHOLD = 0.55  # If fail ratio >= 0.55, host is considered scanning

# Fake open ports – chỉ giả lập rằng các cổng này mở
FAKE_OPEN_PORTS = [80, 443, 8080]

# Flow timeouts
IDLE_TIMEOUT = 30
HARD_TIMEOUT = 60

# MAC learning timeout (nếu cần)
MAC_LEARN_TIMEOUT = 120

class TRWCBState(object):
    """ Lưu trữ trạng thái TRW-CB cho mỗi host (theo IP nguồn). """
    def __init__(self):
        self.success = 0
        self.fail = 0
        self.credits = BASE_CREDITS

class KYELearningSwitch(object):
    """
    POX Controller kết hợp L2 learning và TRW-CB.
    - L2 Learning: học địa chỉ MAC để chuyển tiếp gói tin.
    - TRW-CB: khi nhận gói TCP SYN:
         + Nếu đích (destination port) thuộc FAKE_OPEN_PORTS => tính là success
         + Nếu không thuộc => tính là fail.
      Ngoài ra, nếu nhận gói TCP RST thì cũng tính là fail.
      Sau đó, cập nhật số liệu và kiểm tra ngưỡng (fail ratio, credits) để quyết định block host.
    """
    def __init__(self, connection, transparent=False):
        self.connection = connection
        self.transparent = transparent

        # L2 table: mac -> (port, last_learn_time)
        self.mac_table = {}

        # TRW-CB state: ip_stats[src_ip] = TRWCBState()
        self.ip_stats = defaultdict(TRWCBState)

        connection.addListeners(self)
        log.info("[KYE] Switch %s is up", connection)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            return

        inport = event.port

        # Bỏ qua LLDP
        if packet.type == ethernet.LLDP_TYPE:
            return

        # L2 learning: học MAC của nguồn
        self._l2_learn(packet, inport)

        # Nếu là ARP, flood
        arpp = packet.find('arp')
        if arpp:
            self._l2_forward(event, packet)
            return

        # Nếu không phải IPv4, flood
        ipp = packet.find('ipv4')
        if not ipp:
            self._flood_packet(event)
            return

        # Nếu là TCP, xử lý TRW-CB
        tcpp = packet.find('tcp')
        if tcpp:
            self._handle_tcp_trwcb(event, packet, ipp, tcpp)
        else:
            # ICMP hoặc UDP => chỉ thực hiện L2 forwarding
            self._l2_forward(event, packet)

    # -------------------- L2 Learning --------------------
    def _l2_learn(self, packet, inport):
        src_mac = packet.src
        self.mac_table[src_mac] = (inport, time.time())

    def _l2_forward(self, event, packet):
        dst_mac = packet.dst
        inport = event.port

        if dst_mac.is_multicast:
            self._flood_packet(event)
        else:
            if dst_mac in self.mac_table:
                outport, _ = self.mac_table[dst_mac]
                if outport == inport:
                    self._drop_packet(event)
                else:
                    self._install_l2_flow(event, packet, outport)
            else:
                self._flood_packet(event)

    def _flood_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def _drop_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        self.connection.send(msg)

    def _install_l2_flow(self, event, packet, outport):
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, event.port)
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 10
        fm.actions.append(of.ofp_action_output(port=outport))
        fm.data = event.ofp
        self.connection.send(fm)

    # -------------------- TRW-CB Detection --------------------
    def _handle_tcp_trwcb(self, event, eth_pkt, ip_pkt, tcp_pkt):
        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)
        dport = tcp_pkt.dstport

        # Xác định nếu là SYN không có ACK
        syn_flag = (tcp_pkt.SYN and not tcp_pkt.ACK)
        # Nếu có flag RST, xem như thất bại
        rst_flag = tcp_pkt.RST

        if syn_flag:
            if dport in FAKE_OPEN_PORTS:
                self._trwcb_success(src_ip)
                self._install_tcp_flow(ip_pkt.srcip, ip_pkt.dstip)
                log.debug("[FAKE-OPEN] Host %s, port %d => success", src_ip, dport)
            else:
                self._trwcb_fail(src_ip)
                log.debug("[FAKE-CLOSED] Host %s, port %d => fail", src_ip, dport)
            self._l2_forward(event, eth_pkt)

        elif rst_flag:
            # Gói RST được tính là thất bại
            self._trwcb_fail(src_ip)
            log.debug("[RST] Host %s, port %d => treated as fail", src_ip, dport)
            self._l2_forward(event, eth_pkt)
        else:
            # Các gói khác (ví dụ, ACK, các gói dữ liệu sau SYN+ACK) chỉ được forward
            self._l2_forward(event, eth_pkt)

    def _install_tcp_flow(self, src_ip, dst_ip):
        """
        Cài đặt flow 2 chiều để giảm số lượng PacketIn từ cặp này.
        """
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x0800
        fm.match.nw_proto = 6
        fm.match.nw_src   = src_ip
        fm.match.nw_dst   = dst_ip
        fm.idle_timeout   = IDLE_TIMEOUT
        fm.hard_timeout   = HARD_TIMEOUT
        fm.priority       = 20
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(fm)

        fm2 = of.ofp_flow_mod()
        fm2.match.dl_type = 0x0800
        fm2.match.nw_proto = 6
        fm2.match.nw_src   = dst_ip
        fm2.match.nw_dst   = src_ip
        fm2.idle_timeout   = IDLE_TIMEOUT
        fm2.hard_timeout   = HARD_TIMEOUT
        fm2.priority       = 20
        fm2.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(fm2)

    def _trwcb_success(self, host_ip):
        st = self.ip_stats[host_ip]
        st.success += 1
        st.credits += SUCCESS_INC
        log.debug("[TRW-CB] Success for %s: s=%d, credits=%d", host_ip, st.success, st.credits)
        self._check_block(host_ip)

    def _trwcb_fail(self, host_ip):
        st = self.ip_stats[host_ip]
        st.fail += 1
        st.credits -= FAIL_DEC
        log.debug("[TRW-CB] Fail for %s: f=%d, credits=%d", host_ip, st.fail, st.credits)
        self._check_block(host_ip)

    def _check_block(self, host_ip):
        st = self.ip_stats[host_ip]
        total = st.success + st.fail
        fail_ratio = float(st.fail) / float(total) if total > 0 else 0.0
        log.debug("[TRW-CB] Host %s: success=%d, fail=%d, ratio=%.2f, credits=%d",
                  host_ip, st.success, st.fail, fail_ratio, st.credits)
        if fail_ratio >= FAIL_RATIO_THRESHOLD or st.credits <= 0:
            log.warn("[TRW-CB] BLOCK %s (success=%d, fail=%d, ratio=%.2f, credits=%d)",
                     host_ip, st.success, st.fail, fail_ratio, st.credits)
            self._push_drop_rule(host_ip)

    def _push_drop_rule(self, host_ip):
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x0800
        fm.match.nw_src  = host_ip
        fm.priority      = 100  # ưu tiên cao để drop luôn
        # Không có actions => drop
        fm.idle_timeout  = 300
        fm.hard_timeout  = 600
        self.connection.send(fm)
        log.info("=> Drop all traffic from %s", host_ip)

def launch(transparent=False):
    """
    Sử dụng: ./pox.py log.level --DEBUG kye_controller
    """
    t = (str(transparent).lower() == 'true')
    from pox.core import core
    core.openflow.addListenerByName("ConnectionUp",
                                    lambda e: KYELearningSwitch(e.connection, t))
    log.info("KYE + L2 + TRW-CB (FakeOpen) started.")
