#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
KYE Controller: Combined TRW-CB + Access Control
 - TRW-CB logic for scanning detection
 - Additional Access Control rules:
   10.0.0.x <-> 10.0.2.x = allow
   10.0.0.x <-> 10.0.1.x = allow
   10.0.1.x <-> 10.0.2.x = deny
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4, tcp
from pox.lib.addresses import IPAddr
import time
from collections import defaultdict

log = core.getLogger()

# ---------- TRW-CB Parameters ----------
BASE_CREDITS     = 10
SUCCESS_INC      = 2
FAIL_DEC         = 1
PENDING_TIMEOUT  = 1.0

IDLE_TIMEOUT = 30
HARD_TIMEOUT = 60

class TRWCBState(object):
    def __init__(self):
        self.credits  = BASE_CREDITS
        self.success  = 0
        self.fail     = 0
        self.pending  = 0
        # pending_flows: (server_ip,server_port,client_port)->[timestamps,...]
        self.pending_flows = {}

def subnet(ip):
    # Đơn giản cắt ip, trả về prefix /24
    s = str(ip).split('.')
    # s[0], s[1], s[2] -> "10","0","0",..., gộp => "10.0.0"
    return ".".join(s[:3])  # Ví dụ "10.0.0"

def is_allowed_access(src_ip, dst_ip):
    """
    Trả về True nếu được phép, False nếu bị deny
    Access Control theo yêu cầu:
      10.0.1.x <-> 10.0.2.x = deny
      10.0.0.x <-> 10.0.1.x = allow
      10.0.0.x <-> 10.0.2.x = allow
    """
    src_sub = subnet(src_ip)   # "10.0.0"
    dst_sub = subnet(dst_ip)   # "10.0.1" ...
    # So sánh cặp
    # Kiểm tra cặp (1<->2) => deny
    if (src_sub == "10.0.1" and dst_sub == "10.0.2") \
       or (src_sub == "10.0.2" and dst_sub == "10.0.1"):
        return False
    # ngược lại => allow
    return True

class KYELearningSwitch(object):
    def __init__(self, connection, transparent=False):
        self.connection = connection
        self.transparent = transparent
        # MAC table for L2
        self.mac_table = {}
        # TRW-CB ip_stats: client_ip->TRWCBState
        self.ip_stats = defaultdict(TRWCBState)
        connection.addListeners(self)
        log.info("[KYE] Switch %s is up", connection)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            return

        inport = event.port
        self._l2_learn(packet, inport)

        # Check if IPv4
        ipp = packet.find('ipv4')
        if not ipp:
            # ARP or other => handle normally
            if packet.find('arp'):
                self._l2_forward_arp_icmp(event, packet)
            else:
                self._flood_packet(event)
            return

        # Access Control check
        if not is_allowed_access(ipp.srcip, ipp.dstip):
            # => cài flow drop
            self._install_drop_flow(event, ipp)
            log.debug("[AC] DENY from %s to %s => drop flow installed",
                      ipp.srcip, ipp.dstip)
            return
        else:
            # => allowed => tiếp tục TRW-CB (nếu TCP), else L2
            tcpp = packet.find('tcp')
            if tcpp:
                self._handle_tcp_trwcb(event, packet, ipp, tcpp)
            else:
                # non-TCP => forward via L2
                self._l2_forward_arp_icmp(event, packet)

    def _l2_learn(self, packet, inport):
        src_mac = packet.src
        self.mac_table[src_mac] = (inport, time.time())

    def _l2_forward_arp_icmp(self, event, packet):
        if packet.find('tcp'):
            self._flood_packet(event)
            return

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
                    fm = of.ofp_flow_mod()
                    fm.match = of.ofp_match.from_packet(packet, event.port)
                    fm.idle_timeout = IDLE_TIMEOUT
                    fm.hard_timeout = HARD_TIMEOUT
                    fm.priority = 10
                    fm.actions.append(of.ofp_action_output(port=outport))
                    fm.data = event.ofp
                    self.connection.send(fm)
            else:
                self._flood_packet(event)

    def _install_drop_flow(self, event, ipp):
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(event.parsed, event.port)
        fm.idle_timeout = 5
        fm.hard_timeout = 10
        fm.priority = 20
        fm.data = event.ofp
        # No action => drop
        self.connection.send(fm)

    def _drop_packet(self, event):
        msg = of.ofp_packet_out(data=event.ofp, in_port=event.port)
        self.connection.send(msg)

    def _flood_packet(self, event):
        msg = of.ofp_packet_out(data=event.ofp, in_port=event.port)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    # =========== TRW-CB (unchanged logic, except for /24 checks) ===========
    def _handle_tcp_trwcb(self, event, eth_pkt, ip_pkt, tcp_pkt):
        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)
        src_port = tcp_pkt.srcport
        dst_port = tcp_pkt.dstport

        st = self.ip_stats[src_ip]
        syn_flag = (tcp_pkt.SYN and not tcp_pkt.ACK)
        ack_flag = (tcp_pkt.SYN and tcp_pkt.ACK)
        rst_flag = tcp_pkt.RST

        # check local net /24 thay cho /8
        def inLocalNet(ip):
            # Tùy logic. Giả sử local = 10.0.0.x/24
            # -> or check ip_pkt.srcip.inNetwork("10.0.0.0/24")
            # code cũ => just do quick
            return ip.startswith("10.0.0.")

        if inLocalNet(src_ip):
            # outbound
            if syn_flag:
                if st.credits > 0:
                    st.credits -= 1
                    st.pending += 1
                    key = (dst_ip, dst_port, src_port)
                    if key not in st.pending_flows:
                        st.pending_flows[key] = []
                    st.pending_flows[key].append(time.time())
                    log.debug("[TRW] %s: Outbound SYN->%s:%d, pending=%d, credit=%d, key=%s",
                              src_ip, dst_ip, dst_port, st.pending, st.credits, key)
                    from pox.core import core
                    core.callDelayed(1.0, self._check_no_response, src_ip, key)
                    self._flood_packet(event)
                else:
                    st.fail += 1
                    log.debug("[TRW] %s: No credit => drop => fail=%d, credit=%d",
                              src_ip, st.fail, st.credits)
                    self._drop_packet(event)
            else:
                log.debug("[TRW] Outbound non-SYN from %s => flood", src_ip)
                self._flood_packet(event)
        elif inLocalNet(str(ip_pkt.dstip)):
            # inbound
            local_ip = str(ip_pkt.dstip)
            stLocal = self.ip_stats[local_ip]
            if ack_flag:
                key = (str(ip_pkt.srcip), tcp_pkt.srcport, tcp_pkt.dstport)
                if key in stLocal.pending_flows and stLocal.pending_flows[key]:
                    stLocal.pending -= 1
                    stLocal.success += 1
                    stLocal.credits += SUCCESS_INC
                    stLocal.pending_flows[key].pop(0)
                    if not stLocal.pending_flows[key]:
                        del stLocal.pending_flows[key]
                    log.debug("[TRW] %s: Inbound SYN+ACK => success => pending=%d, credit=%d, success=%d",
                              local_ip, stLocal.pending, stLocal.credits, stLocal.success)
                else:
                    log.debug("[TRW] Inbound SYN+ACK from %s => no pending found?", local_ip)
                self._flood_packet(event)
            elif rst_flag:
                # check if truly from server or from local
                if not inLocalNet(str(ip_pkt.srcip)):
                    # RST from server
                    key = (str(ip_pkt.srcip), tcp_pkt.srcport, tcp_pkt.dstport)
                    if key in stLocal.pending_flows and stLocal.pending_flows[key]:
                        stLocal.pending -= 1
                        stLocal.fail += 1
                        stLocal.credits = max(0, stLocal.credits - FAIL_DEC)
                        stLocal.pending_flows[key].pop(0)
                        if not stLocal.pending_flows[key]:
                            del stLocal.pending_flows[key]
                        log.debug("[TRW] %s: Inbound RST from server => fail => pending=%d, credit=%d, fail=%d",
                                  local_ip, stLocal.pending, stLocal.credits, stLocal.fail)
                    else:
                        log.debug("[TRW] Inbound RST but no pending => ignoring")
                else:
                    log.debug("[TRW] Inbound RST from local => skip fail")
                self._flood_packet(event)
            else:
                log.debug("[TRW] Inbound non-SYN+ACK from %s => flood", local_ip)
                self._flood_packet(event)
        else:
            self._flood_packet(event)

    def _check_no_response(self, src_ip, key):
        st = self.ip_stats[src_ip]
        if key in st.pending_flows and st.pending_flows[key]:
            st.pending -= 1
            st.fail += 1
            st.credits = max(0, st.credits - FAIL_DEC)
            st.pending_flows[key].pop(0)
            if not st.pending_flows[key]:
                del st.pending_flows[key]
            log.debug("[TRW] NO-RESPONSE => fail for %s => pending=%d, credit=%d, fail=%d",
                      src_ip, st.pending, st.credits, st.fail)

def launch(transparent=False):
    t = (str(transparent).lower() == 'true')
    from pox.core import core
    def start_switch(event):
        KYELearningSwitch(event.connection, t)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("[KYE] TRW-CB + AC started.")
