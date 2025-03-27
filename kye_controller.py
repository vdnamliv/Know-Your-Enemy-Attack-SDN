#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
POX Controller: TRW-CB using real port 80 on h2.
 - When a TCP SYN is sent (from client to server): if there is available credit,
   then forward the SYN, increment pending counter and decrement credit.
 - When the server returns a SYN+ACK: treat it as success → decrement pending,
   increment success, and add SUCCESS_INC to credit.
 - When an RST is received or if no response is received after a timeout,
   treat it as a failure → decrement pending and decrement credit by FAIL_DEC.
 - The controller does not permanently block the host.
 - No L2 flow is installed for TCP so that all TCP packets (both outbound and inbound)
   generate PacketIn events for TRW-CB processing.

Edited to fix inbound RST logic for hping3:
 - If inbound RST is actually from local client (srcip in local subnet),
   do not count as fail or subtract credit.
 - Only treat inbound RST from a remote (outside 10.0.0.0/24) as fail.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4, tcp
import time
from collections import defaultdict

log = core.getLogger()

# ---------- TRW-CB Parameters ----------
BASE_CREDITS     = 10    # initial credits per host
SUCCESS_INC      = 2     # credits gained on success
FAIL_DEC         = 1     # credits lost on failure
PENDING_TIMEOUT  = 1.0   # seconds to wait for a response before marking as fail

# Flow timeouts for non-TCP flows (ARP/ICMP)
IDLE_TIMEOUT = 30
HARD_TIMEOUT = 60

class TRWCBState(object):
    def __init__(self):
        self.credits  = BASE_CREDITS
        self.success  = 0
        self.fail     = 0
        self.pending  = 0
        # pending_flows: key = (server_ip, server_port, client_port) -> list of timestamps
        self.pending_flows = {}

class KYELearningSwitch(object):
    def __init__(self, connection, transparent=False):
        self.connection = connection
        self.transparent = transparent

        # MAC table for ARP/ICMP: mac -> (inport, last_time)
        self.mac_table = {}
        # ip_stats: client_ip -> TRWCBState (for TCP scanning state)
        self.ip_stats = defaultdict(TRWCBState)

        connection.addListeners(self)
        log.info("[KYE] Switch %s is up", connection)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            return

        inport = event.port

        # L2 learning (for ARP/ICMP)
        self._l2_learn(packet, inport)

        # ARP: process normally (with L2 flow installation)
        if packet.find('arp'):
            self._l2_forward_arp_icmp(event, packet)
            return

        # IPv4: if not TCP, forward (e.g. UDP)
        ipp = packet.find('ipv4')
        if not ipp:
            self._flood_packet(event)
            return

        tcpp = packet.find('tcp')
        if tcpp:
            self._handle_tcp_trwcb(event, packet, ipp, tcpp)
        else:
            self._l2_forward_arp_icmp(event, packet)

    # -------- L2 LEARNING & FORWARDING for non-TCP --------
    def _l2_learn(self, packet, inport):
        src_mac = packet.src
        self.mac_table[src_mac] = (inport, time.time())
        log.debug("[MAC-LEARN] Learned MAC %s at port %d", src_mac, inport)

    def _l2_forward_arp_icmp(self, event, packet):
        # For non-TCP packets (ARP, ICMP), install L2 flows.
        if packet.find('tcp'):
            log.debug("[L2] TCP packet detected, not installing L2 flow; using flood")
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
                    self._install_l2_flow(event, packet, outport)
            else:
                self._flood_packet(event)

    def _install_l2_flow(self, event, packet, outport):
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, event.port)
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 10
        fm.actions.append(of.ofp_action_output(port=outport))
        fm.data = event.ofp
        self.connection.send(fm)
        log.debug("[L2-FLOW] Installed L2 flow for ARP/ICMP => outport=%d", outport)

    def _flood_packet(self, event):
        msg = of.ofp_packet_out(data=event.ofp, in_port=event.port)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def _drop_packet(self, event):
        msg = of.ofp_packet_out(data=event.ofp, in_port=event.port)
        self.connection.send(msg)

    # -------- TRW-CB Processing for TCP (no L2 flows installed) --------
    def _handle_tcp_trwcb(self, event, eth_pkt, ip_pkt, tcp_pkt):
        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)
        src_port = tcp_pkt.srcport
        dst_port = tcp_pkt.dstport

        # We maintain state per client (source IP)
        st = self.ip_stats[src_ip]

        syn_flag = (tcp_pkt.SYN and not tcp_pkt.ACK)
        ack_flag = (tcp_pkt.SYN and tcp_pkt.ACK)  # SYN+ACK
        rst_flag = tcp_pkt.RST

        # Outbound: from local client (10.0.0.x) to server
        if ip_pkt.srcip.inNetwork("10.0.0.0/24"):
            # client -> server
            if syn_flag:
                if st.credits > 0:
                    st.credits -= 1
                    st.pending += 1
                    key = (str(dst_ip), dst_port, src_port)
                    if key not in st.pending_flows:
                        st.pending_flows[key] = []
                    st.pending_flows[key].append(time.time())
                    log.debug("[TRW] %s: Outbound SYN->%s:%d, pending=%d, credit=%d, key=%s",
                              src_ip, dst_ip, dst_port, st.pending, st.credits, key)
                    # Schedule a check if no response arrives within PENDING_TIMEOUT
                    core.callDelayed(PENDING_TIMEOUT, self._check_no_response, src_ip, key)
                    # Forward the SYN (so that the server can reply)
                    self._flood_packet(event)
                else:
                    st.fail += 1
                    log.debug("[TRW] %s: No credit, dropping SYN => fail=%d, credit=%d",
                              src_ip, st.fail, st.credits)
                    self._drop_packet(event)
            else:
                log.debug("[TRW] Outbound non-SYN TCP from %s => flood", src_ip)
                self._flood_packet(event)

        # Inbound: from server to local client
        elif ip_pkt.dstip.inNetwork("10.0.0.0/24"):
            local_ip = str(ip_pkt.dstip)
            stLocal = self.ip_stats[local_ip]

            if ack_flag:
                # inbound SYN+ACK
                key = (str(ip_pkt.srcip), tcp_pkt.srcport, tcp_pkt.dstport)
                if key in stLocal.pending_flows and stLocal.pending_flows[key]:
                    stLocal.pending -= 1
                    stLocal.success += 1
                    stLocal.credits += SUCCESS_INC
                    stLocal.pending_flows[key].pop(0)
                    if not stLocal.pending_flows[key]:
                        del stLocal.pending_flows[key]
                    log.debug("[TRW] %s: Inbound SYN+ACK => success, pending=%d, credit=%d, success=%d, key=%s",
                              local_ip, stLocal.pending, stLocal.credits, stLocal.success, key)
                else:
                    log.debug("[TRW] Inbound SYN+ACK from %s but no matching pending key: %s",
                              local_ip, key)
                self._flood_packet(event)

            elif rst_flag:
                # inbound RST
                # check if it truly comes from server or from local client side
                if not ip_pkt.srcip.inNetwork("10.0.0.0/24"):
                    # RST from actual remote server
                    key = (str(ip_pkt.srcip), tcp_pkt.srcport, tcp_pkt.dstport)
                    if key in stLocal.pending_flows and stLocal.pending_flows[key]:
                        stLocal.pending -= 1
                        stLocal.fail += 1
                        stLocal.credits = max(0, stLocal.credits - FAIL_DEC)
                        stLocal.pending_flows[key].pop(0)
                        if not stLocal.pending_flows[key]:
                            del stLocal.pending_flows[key]
                        log.debug("[TRW] %s: Inbound RST from server => pending=%d, credit=%d, fail=%d, key=%s",
                                  local_ip, stLocal.pending, stLocal.credits, stLocal.fail, key)
                    else:
                        log.debug("[TRW] Inbound RST from server, no matching pending key: %s", key)
                else:
                    # RST đến từ local client => KHÔNG tính fail
                    log.debug("[TRW] %s: Inbound RST BUT src is local => skip fail", local_ip)
                self._flood_packet(event)

            else:
                log.debug("[TRW] Inbound non-SYN+ACK TCP from %s => flood", local_ip)
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
            log.debug("[TRW] NO-RESPONSE => fail for %s, pending=%d, credit=%d, fail=%d, key=%s",
                      src_ip, st.pending, st.credits, st.fail, key)

def launch(transparent=False):
    t = (str(transparent).lower() == 'true')
    from pox.core import core
    core.openflow.addListenerByName("ConnectionUp", lambda e: KYELearningSwitch(e.connection, t))
    log.info("[KYE] TRW-CB with real port 80 (no L2 flow for TCP) started.")
