from pox.core import core
import pox.openflow.libopenflow_01 as of
from collections import defaultdict
import time

from pox.lib.packet import ipv4, icmp, tcp, udp, ethernet
from pox.lib.packet.icmpv6 import icmpv6

log = core.getLogger()

# TRW-CB / credit-based approach constants
BASE_CREDITS = 10
SUCCESS_INC = 2      # how many credits to add on a successful connection
FAIL_DEC = 1         # how many credits to remove on a failed connection
FAIL_RATIO_THRESHOLD = 0.55  # alternative detection condition

IDLE_TIMEOUT = 60
HARD_TIMEOUT = 300

class KYEController(object):
    """
    A simplified POX controller using a credit-based approach to detect scanning
    (inspired by TRW-CB). If a host's IP is flagged as scanning, we push a DROP rule.
    """
    def __init__(self, connection):
        self.connection = connection
        # For L2 learning or storing MAC→port
        self.mac_to_port = {}

        # ip_state[src_ip] = {
        #   "credits": ...,
        #   "success": ...,
        #   "fail": ...,
        #   "last_time": ...
        # }
        self.ip_state = defaultdict(lambda: {
            "credits": BASE_CREDITS, 
            "success": 0,
            "fail": 0,
            "last_time": time.time()
        })

        # Time window for resetting scanning stats (secs)
        self.scan_window = 20

        # Bind listeners
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        if not packet:
            return

        # Basic L2 learning
        src_mac = packet.src
        dst_mac = packet.dst

        self.mac_to_port[src_mac] = in_port

        # If ARP, just flood or handle normally
        if packet.type == packet.ARP_TYPE:
            self._flood_packet(event, packet)
            return

        # We handle IPv4 specifically
        ip_pkt = packet.find('ipv4')
        if ip_pkt:
            src_ip = ip_pkt.srcip
            dst_ip = ip_pkt.dstip

            proto = ip_pkt.protocol
            # Could refine by reading 'tcp', 'udp' port
            transport = packet.find('tcp') or packet.find('udp') or packet.find('icmp') or packet.find('icmpv6')
            
            if transport:
                # Distinguish success vs. fail: 
                # "Fail" = If we suspect that DST is unresponsive? 
                # In practice, we'd do more logic. For demo, let's treat unknown host as "fail"
                # or we can keep it simpler: each new flow => check if reached some open port 
                # For a full approach, you'd parse RST or TTL. We'll do a simplified approach:

                # 1) We update time
                st = self.ip_state[str(src_ip)]
                now = time.time()
                # If time elapsed > scan_window, reset
                if (now - st["last_time"]) > self.scan_window:
                    st["credits"] = BASE_CREDITS
                    st["success"] = 0
                    st["fail"] = 0
                st["last_time"] = now

                # We'll do a simple "if port < 1024 => success, else => fail" for demonstration
                # or we can do "if the DST MAC is known => success, else => fail".
                # For a more realistic approach, you'd watch for actual handshake or replies.
                
                # We'll do a naive approach: if we do not know MAC of dst => fail
                if dst_mac not in self.mac_to_port.values():
                    # treat as fail
                    st["fail"] += 1
                    st["credits"] -= FAIL_DEC
                    log.debug(f"[{src_ip}] scanning fail => credits={st['credits']}, fail={st['fail']}")
                else:
                    # treat as success
                    st["success"] += 1
                    st["credits"] += SUCCESS_INC
                    log.debug(f"[{src_ip}] scanning success => credits={st['credits']}, success={st['success']}")

                # Check ratio or credit
                fail_ratio = 0.0
                total_conn = st["fail"] + st["success"]
                if total_conn > 0:
                    fail_ratio = float(st["fail"])/float(total_conn)

                # Condition #1: credit <= 0 => block
                # Condition #2: fail_ratio > 0.55 => block
                if st["credits"] <= 0 or fail_ratio >= FAIL_RATIO_THRESHOLD:
                    log.info(f"KYE Attack DETECT: {src_ip} BLOCKED (credits={st['credits']}, fail_ratio={fail_ratio:.2f})")
                    self.block_ip(src_ip, event, packet)
                    return

            # If not blocked, forward or flood
            self._install_flow(event, packet)
            return

        else:
            # If non-IPv4, just do normal L2 flooding or bridging
            self._flood_packet(event, packet)

    def _install_flow(self, event, packet):
        """
        Install a simple forward-flow (like L2 learn).
        """
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = HARD_TIMEOUT
        # For demonstration, just flood out
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)

        # Also do packet-out
        po = of.ofp_packet_out()
        po.data = event.ofp
        po.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(po)

    def _flood_packet(self, event, packet):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def block_ip(self, src_ip, event, packet):
        """
        Insert a DROP rule for src_ip
        """
        # match: ip src = src_ip
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x0800  # IPv4
        fm.match.nw_src = src_ip
        # no actions => drop
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 100  # higher than normal
        self.connection.send(fm)

        # Also do a packet_out to drop the current packet
        # i.e. no actions
        pass

def launch():
    def start_switch(event):
        log.info(f"KYEController Start on {event.connection.dpid}")
        KYEController(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)

