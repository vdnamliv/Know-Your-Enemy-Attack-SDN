#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
A merged POX controller that does:
1) L2 Learning switch for normal traffic (incl. ARP, ICMP).
2) TRW-CB scanning detection for TCP (SYN, SYN+ACK, RST):
   - If success => install flow => no further PacketIn
   - If fail => decrement credits => possibly block host
   - fail_ratio >= threshold or credits <= 0 => block host

No timer for pending timeouts in this demo ("no response" isn't counted as fail).
If you want that feature, add a Timer that checks pending[] after X seconds.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4, tcp
import time
from collections import defaultdict

log = core.getLogger()

# -------------------- TRW-CB Parameters --------------------
BASE_CREDITS = 10       # Initial credits for each host
SUCCESS_INC  = 2        # Credits added on each successful connection
FAIL_DEC     = 1        # Credits deducted on each failure
FAIL_RATIO_THRESHOLD = 0.55

# Flow timeouts
IDLE_TIMEOUT = 30
HARD_TIMEOUT = 60

# L2 (MAC) learning: how long to remember port->MAC?
MAC_LEARN_TIMEOUT = 120

class TRWCBState(object):
    """
    Per-host TRW-CB state: success count, fail count, current credits.
    """
    def __init__(self):
        self.success = 0
        self.fail = 0
        self.credits = BASE_CREDITS

class PendingConn(object):
    """
    Represents a pending connection A->B waiting for SYN+ACK or RST.
    """
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.time_start = time.time()

class KYELearningSwitch(object):
    """
    Single-switch controller that merges:
      1. L2 learning for all non-TCP or ARP traffic
      2. TRW-CB for TCP traffic => scanning detection
    """

    def __init__(self, connection, transparent=False):
        self.connection = connection
        self.transparent = transparent

        # L2 table: mac -> (port, last_learned_time)
        self.mac_table = {}

        # TRW-CB state per IP, e.g. ip_stats[src_ip] = TRWCBState(...)
        self.ip_stats = defaultdict(TRWCBState)

        # Pending connections: pending[(src_ip, dst_ip)] = PendingConn(...)
        self.pending = {}

        connection.addListeners(self)
        log.info("[KYE] Switch %s has come up", connection)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            return

        # Example: ignore DNS (optional). Just remove if you prefer not to skip DNS.
        if packet.find('dns'):
            return

        inport = event.port

        # Drop LLDP to avoid confusing the controller
        if packet.type == ethernet.LLDP_TYPE:
            return

        # 1) L2 learning for all frames
        self._l2_learn(packet, inport)

        # 2) ARP => handle or flood
        arpp = packet.find('arp')
        if arpp:
            self._handle_arp(event, packet, arpp)
            return

        # 3) If not IPv4 => fallback flood
        ipp = packet.find('ipv4')
        if not ipp:
            self._flood_packet(event)
            return

        # 4) If TCP => apply TRW-CB logic
        tcpp = packet.find('tcp')
        if tcpp:
            self._handle_tcp_trwcb(event, packet, ipp, tcpp)
        else:
            # E.g., ICMP => forward by L2
            self._l2_forward(event, packet)

    # -------------- L2 LEARNING (mac -> port) --------------
    def _l2_learn(self, packet, inport):
        """Record the mac => inport mapping."""
        src_mac = packet.src
        self.mac_table[src_mac] = (inport, time.time())

    def _l2_forward(self, event, packet):
        """Forward via L2 table if known, else flood."""
        dst_mac = packet.dst
        inport = event.port

        # If broadcast/multicast => flood
        if dst_mac.is_multicast:
            self._flood_packet(event)
        else:
            if dst_mac in self.mac_table:
                outport, _t = self.mac_table[dst_mac]
                # Same port => drop
                if outport == inport:
                    self._drop_packet(event)
                else:
                    # Install flow => no future PacketIn for the same flow
                    self._install_l2_flow(event, packet, outport)
            else:
                # Unknown => flood
                self._flood_packet(event)

    def _install_l2_flow(self, event, packet, outport):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = HARD_TIMEOUT
        msg.priority = 10
        msg.actions.append(of.ofp_action_output(port=outport))
        msg.data = event.ofp  # Let this packet go immediately
        self.connection.send(msg)

    def _flood_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def _drop_packet(self, event):
        """Just drop this single packet (no flow-mod)."""
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        # No actions => dropped
        self.connection.send(msg)

    # -------------- ARP Handler --------------
    def _handle_arp(self, event, eth_pkt, arp_pkt):
        """
        For simplicity, we just call L2 forward.
        You could implement ARP replies if desired.
        """
        self._l2_forward(event, eth_pkt)

    # -------------- TCP TRW-CB Logic --------------
    def _handle_tcp_trwcb(self, event, eth_pkt, ip_pkt, tcp_pkt):
        """
        TRW-CB states:
          - If SYN => pending
          - If SYN+ACK => success => remove pending => install flow
          - If RST => fail => remove pending => decrement credits
          - If fail_ratio >= threshold or credits <= 0 => block
        """
        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)
        inport = event.port

        # Check flags
        syn_flag    = (tcp_pkt.SYN and not tcp_pkt.ACK)
        synack_flag = (tcp_pkt.SYN and tcp_pkt.ACK)
        rst_flag    = tcp_pkt.RST

        if syn_flag:
            # A->B is new => pending
            key = (src_ip, dst_ip)
            if key not in self.pending:
                self.pending[key] = PendingConn(src_ip, dst_ip)
            # forward by L2
            self._l2_forward(event, eth_pkt)

        elif synack_flag:
            # B->A => success if pending(A->B)
            key = (dst_ip, src_ip)  # invert
            if key in self.pending:
                del self.pending[key]
                self._trwcb_success(dst_ip)  # "A" is the original src => success
                self._install_tcp_flow(event, eth_pkt, src_ip, dst_ip)
            else:
                # not pending => just forward
                self._l2_forward(event, eth_pkt)

        elif rst_flag:
            # RST => fail if match pending
            key = (dst_ip, src_ip)
            if key in self.pending:
                del self.pending[key]
                self._trwcb_fail(dst_ip)
            self._l2_forward(event, eth_pkt)

        else:
            # Normal traffic => forward
            self._l2_forward(event, eth_pkt)

    def _install_tcp_flow(self, event, eth_pkt, src_ip, dst_ip):
        """
        For a 'successful' connection, install 2 flows (A->B and B->A).
        We'll do match on (dl_type=0x0800, nw_proto=6, nw_src=..., nw_dst=...)
        Then action => flood, or you can do L2 if you prefer.
        """
        # Flow A->B
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

        # Flow B->A
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
        """Increment success + credits."""
        st = self.ip_stats[host_ip]
        st.success += 1
        st.credits += SUCCESS_INC
        self._check_block(host_ip)

    def _trwcb_fail(self, host_ip):
        """Increment fail, decrement credits."""
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
            log.warn("[TRW-CB] BLOCK %s (success=%d, fail=%d, ratio=%.2f, credits=%.1f)",
                     host_ip, s, f, fail_ratio, st.credits)
            self._push_drop_rule(host_ip)

    def _push_drop_rule(self, host_ip):
        """
        Install a high-priority drop rule to block all traffic from host_ip.
        """
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
    Controller entry point:
      ./pox.py log.level --DEBUG kye_controller [transparent=False]
    """
    t = (str(transparent).lower() == 'true')
    def start_switch(event):
        log.info("[KYE] Launching on %s", event.connection)
        KYELearningSwitch(event.connection, transparent=t)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("KYE + L2 Learning + TRW-CB started.")
