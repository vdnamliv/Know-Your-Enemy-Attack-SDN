#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A merged POX controller that does:
1) L2 Learning switch for normal traffic (incl. ARP, ICMP).
2) TRW-CB scanning detection for TCP (SYN, SYN+ACK, RST):
   - If success => install flow => no further PacketIn
   - If fail => decr credits => possibly block host
   - fail_ratio >= threshold or credits <= 0 => block host

No timer for pending timeouts in this demo (i.e. "no response" not counted as fail).
If you want that feature, add a Timer that checks pending[] after X seconds.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4, tcp
import time
from collections import defaultdict

log = core.getLogger()

# -------------------- TRW-CB Parameters --------------------
BASE_CREDITS = 10
SUCCESS_INC  = 2
FAIL_DEC     = 1
FAIL_RATIO_THRESHOLD = 0.55

# Flow timeouts
IDLE_TIMEOUT = 30
HARD_TIMEOUT = 60

# L2 learning: how long to remember port->MAC?
MAC_LEARN_TIMEOUT = 120

class TRWCBState(object):
    """
    Per-host TRW-CB state:
      - success, fail
      - credits
    """
    def __init__(self):
        self.success = 0
        self.fail = 0
        self.credits = BASE_CREDITS

class PendingConn(object):
    """
    Pending connection A->B waiting for SYN+ACK or RST
    """
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.time_start = time.time()

class KYELearningSwitch(object):
    """
    Single-switch controller that merges:
    1. L2 learning for all non-TCP or ARP traffic.
    2. TRW-CB for TCP traffic => scanning detection
    """

    def __init__(self, connection, transparent=False):
        self.connection = connection
        self.transparent = transparent

        # L2 table: mac -> (port, last_time)
        self.mac_table = {}

        # TRW-CB state per IP
        # ip_stats[src_ip] = TRWCBState(...)
        self.ip_stats = defaultdict(TRWCBState)

        # pending[(src_ip, dst_ip)] = PendingConn(...)
        self.pending = {}

        connection.addListeners(self)
        log.info("[KYE] Switch %s has come up", connection)

    # -------------- Event: PacketIn --------------
    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            return

        inport = event.port
        # Drop LLDP
        if packet.type == ethernet.LLDP_TYPE:
            return

        # 1) L2 learning for all frames
        self._l2_learn(packet, inport)

        # If ARP => handle so ping works
        arpp = packet.find('arp')
        if arpp:
            self._handle_arp(event, packet, arpp)
            return

        ipp = packet.find('ipv4')
        if not ipp:
            # E.g. IPv6 or something else => fallback flooding
            self._flood_packet(event)
            return

        # If TCP => TRW-CB
        tcpp = packet.find('tcp')
        if tcpp:
            self._handle_tcp_trwcb(event, packet, ipp, tcpp)
        else:
            # E.g. ICMP => forward by L2
            self._l2_forward(event, packet)
        # End _handle_PacketIn

    # -------------- L2 LEARNING --------------
    def _l2_learn(self, packet, inport):
        """
        Record the mac => inport mapping (like a standard L2 switch).
        """
        src_mac = packet.src
        self.mac_table[src_mac] = (inport, time.time())

    def _l2_forward(self, event, packet):
        """
        Use L2 table if known, else flood
        """
        dst_mac = packet.dst
        inport = event.port

        if dst_mac.is_multicast:
            # Flood
            self._flood_packet(event)
        else:
            if dst_mac in self.mac_table:
                outport, _ = self.mac_table[dst_mac]
                # Avoid sending back on same port => drop
                if outport == inport:
                    self._drop_packet(event)
                else:
                    # Install flow => avoid future PacketIn
                    self._install_l2_flow(event, packet, outport)
            else:
                # Not known => flood
                self._flood_packet(event)

    def _install_l2_flow(self, event, packet, outport):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = HARD_TIMEOUT
        msg.priority = 10
        msg.actions.append(of.ofp_action_output(port=outport))
        msg.data = event.ofp
        self.connection.send(msg)

    def _flood_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def _drop_packet(self, event):
        """
        Just drop this single packet (no flow).
        """
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        self.connection.send(msg)

    # -------------- ARP Handler --------------
    def _handle_arp(self, event, eth_pkt, arp_pkt):
        """
        Simple approach: if ARP is for known host => reply, else flood.
        Alternatively, can let L2 learning do the job (flood).
        """
        # Demo: just forward by L2
        self._l2_forward(event, eth_pkt)

    # -------------- TCP TRW-CB --------------
    def _handle_tcp_trwcb(self, event, eth_pkt, ip_pkt, tcp_pkt):
        """
        TRW-CB:
          - If SYN => add to pending
          - If SYN+ACK => success => remove pending => install flow
          - If RST => fail if there's a matching pending
          - block src if fail_ratio or credits <= 0
        """
        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)
        inport = event.port

        # Check flags
        syn_flag = (tcp_pkt.SYN and not tcp_pkt.ACK)
        synack_flag = (tcp_pkt.SYN and tcp_pkt.ACK)
        rst_flag = tcp_pkt.RST

        if syn_flag:
            # A->B is new => pending
            key = (src_ip, dst_ip)
            if key not in self.pending:
                self.pending[key] = PendingConn(src_ip, dst_ip)
            # forward this packet by L2 => so SYN can go
            self._l2_forward(event, eth_pkt)

        elif synack_flag:
            # B->A => success if pending(A->B)
            key = (dst_ip, src_ip)  # original was A->B
            if key in self.pending:
                del self.pending[key]
                self._trwcb_success(dst_ip)  # "A" is the original src => success
                # Cài flow 2 chiều
                self._install_tcp_flow(event, eth_pkt, src_ip, dst_ip)
            else:
                # not pending => just forward by L2
                self._l2_forward(event, eth_pkt)

        elif rst_flag:
            # RST => fail if match pending
            # Eg: B->A => check pending(A->B)
            key = (dst_ip, src_ip)
            if key in self.pending:
                del self.pending[key]
                self._trwcb_fail(dst_ip)
            self._l2_forward(event, eth_pkt)
        else:
            # Normal TCP traffic => forward
            self._l2_forward(event, eth_pkt)

    def _install_tcp_flow(self, event, eth_pkt, src_ip, dst_ip):
        """
        For a 'successful' connection (SYN+ACK), cài flow 2 chiều => 
        no more PacketIn for A<->B
        We'll do a match on (nw_proto=6, nw_src=src_ip, nw_dst=dst_ip).
        Then forward by L2 logic or just flood. 
        For simplicity => flood. You can do L2 table.
        """
        # Flow for A->B
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x0800       # IPv4
        fm.match.nw_proto = 6          # TCP
        fm.match.nw_src = src_ip
        fm.match.nw_dst = dst_ip
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 20
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(fm)

        # Flow for B->A
        fm2 = of.ofp_flow_mod()
        fm2.match.dl_type = 0x0800
        fm2.match.nw_proto = 6
        fm2.match.nw_src = dst_ip
        fm2.match.nw_dst = src_ip
        fm2.idle_timeout = IDLE_TIMEOUT
        fm2.hard_timeout = HARD_TIMEOUT
        fm2.priority = 20
        fm2.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(fm2)

        log.debug("TRW-CB: installed flow for %s <-> %s", src_ip, dst_ip)

    def _trwcb_success(self, host_ip):
        st = self.ip_stats[host_ip]
        st.success += 1
        st.credits += SUCCESS_INC
        self._check_block(host_ip)

    def _trwcb_fail(self, host_ip):
        st = self.ip_stats[host_ip]
        st.fail += 1
        st.credits -= FAIL_DEC
        self._check_block(host_ip)

    def _check_block(self, host_ip):
        st = self.ip_stats[host_ip]
        s = st.success
        f = st.fail
        total = s + f
        fail_ratio = 0.0
        if total > 0:
            fail_ratio = float(f)/float(total)

        if fail_ratio >= FAIL_RATIO_THRESHOLD or st.credits <= 0:
            # block
            log.warn("[TRW-CB] BLOCK %s (success=%d,fail=%d,ratio=%.2f,credits=%.1f)",
                     host_ip, s, f, fail_ratio, st.credits)
            self._push_drop_rule(host_ip)

    def _push_drop_rule(self, host_ip):
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x0800
        fm.match.nw_src = host_ip
        fm.priority = 100
        # no actions => drop
        fm.idle_timeout = 300
        fm.hard_timeout = 600
        self.connection.send(fm)
        log.info("  => Drop all traffic from %s", host_ip)

# ---------- launch() ----------
def launch(transparent=False):
    """
    Controller entry point.
    usage: ./pox.py log.level --DEBUG kye_controller [transparent=False]
    """
    t = str(transparent).lower() == 'true'
    def start_switch(event):
        log.info("[KYE] Launching on %s", event.connection)
        KYELearningSwitch(event.connection, transparent=t)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("KYE + L2 Learning + TRW-CB started.")
