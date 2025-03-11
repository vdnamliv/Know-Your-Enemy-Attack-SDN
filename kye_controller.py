"""
A merged POX controller that does:
1) L2 Learning (so normal traffic is forwarded).
2) TRW-CB style scanning detection (KYE Attack logic).
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4, tcp, udp, icmp
from collections import defaultdict
import time

log = core.getLogger()

# L2 Learning optional hold-down time
FLOOD_DELAY = 0

# TRW-CB style scanning detection parameters
BASE_CREDITS = 10
SUCCESS_INC = 2
FAIL_DEC    = 1
FAIL_RATIO_THRESHOLD = 0.55
SCAN_WINDOW = 30  # seconds, after which we reset stats if no new traffic

IDLE_TIMEOUT = 30
HARD_TIMEOUT = 60

class MergeKYEL2Switch(object):
    def __init__(self, connection, transparent=False):
        self.connection = connection
        self.transparent = transparent

        # For L2 learning:
        # {mac_addr : port_no}
        self.mac_table = {}

        # For scanning detection:
        # ip_stats[src_ip] = { 'credits', 'fail', 'success', 'last_time'}
        self.ip_stats = defaultdict(lambda: {
            'credits': BASE_CREDITS,
            'fail': 0,
            'success': 0,
            'last_time': time.time(),
        })

        connection.addListeners(self)
        log.info(">>> Merge KYE-L2 Controller for %s", connection)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        inport = event.port

        if not packet:
            return

        if packet.type == ethernet.LLDP_TYPE:
            # Typically drop LLDP
            return

        # L2 learning: record that packet.src came in on inport
        self.mac_table[packet.src] = inport

        # Now let's do the typical "if we know where packet.dst is, forward, else flood."
        dst_port = self.mac_table.get(packet.dst)

        # Possibly we skip some special cases for broadcast, etc.
        # If it's broadcast or multicast, we flood.
        if packet.dst.is_multicast:
            self._flood_packet(event)
            return

        # If we do not know the port for that MAC yet, we might flood.
        if dst_port is None:
            self._flood_packet(event)
        else:
            if dst_port == inport:
                # It's coming from the same port, drop to avoid loops
                self._drop_packet(event, duration=2)
                return
            else:
                # We have a known port. We can install a flow from inport->dst_port
                self._install_l2_flow(event, packet, out_port=dst_port)

        # Next, do scanning detection if it's IPv4
        ip_pkt = packet.find('ipv4')
        if ip_pkt:
            src_ip = str(ip_pkt.srcip)
            now = time.time()

            # If too long since last traffic, reset
            if now - self.ip_stats[src_ip]['last_time'] > SCAN_WINDOW:
                self.ip_stats[src_ip]['credits'] = BASE_CREDITS
                self.ip_stats[src_ip]['fail'] = 0
                self.ip_stats[src_ip]['success'] = 0

            self.ip_stats[src_ip]['last_time'] = now

            # Let's check if the transport is e.g. TCP, UDP, or ICMP
            t = packet.find('tcp') or packet.find('udp') or packet.find('icmp')
            if t:
                # We'll define a naive success/fail:
                # If we have a known MAC for the dst => success
                # (meaning we "believe" the host is valid).
                # If we didn't know the MAC => fail
                # BUT we already installed it above if mac was unknown => flood
                # Actually let's do a minimal approach:
                if dst_port is None:
                    # We *just* flooded => let's skip marking that fail
                    pass
                else:
                    # We know the mac, let's call it success
                    self.ip_stats[src_ip]['success'] += 1
                    self.ip_stats[src_ip]['credits'] += SUCCESS_INC

                # Alternatively, if we want to handle a “port not found” or “port mismatch,” that might be fail
                # But for now let's keep it simpler

                # Check ratio
                s = self.ip_stats[src_ip]['success']
                f = self.ip_stats[src_ip]['fail']
                total = s + f
                fail_ratio = 0.0
                if total > 0:
                    fail_ratio = float(f)/float(total)

                # Also check if credits <= 0 or fail_ratio >= 0.55
                credits_now = self.ip_stats[src_ip]['credits']
                if credits_now <= 0 or fail_ratio >= FAIL_RATIO_THRESHOLD:
                    log.info("DETECT SCANNING - BLOCK src=%s (credits=%.1f fail_ratio=%.2f)", 
                             src_ip, credits_now, fail_ratio)
                    self._block_src_ip(src_ip)
                    return

    def _flood_packet(self, event):
        """ Flood the packet out all ports except the one it came in on. """
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def _drop_packet(self, event, duration=2):
        """ Drop this packet, optionally installing a short flow entry. """
        if duration:
            fm = of.ofp_flow_mod()
            fm.match = of.ofp_match.from_packet(event.parsed, event.port)
            fm.idle_timeout = duration
            fm.hard_timeout = duration
            fm.priority = 10
            self.connection.send(fm)
        else:
            # Just packet out with no actions
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            self.connection.send(msg)

    def _install_l2_flow(self, event, packet, out_port):
        """ Install a unidirectional L2 flow from (inport, src->dst) to out_port. """
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = HARD_TIMEOUT
        msg.priority = 10
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.data = event.ofp  # so we forward this packet too
        self.connection.send(msg)

    def _block_src_ip(self, src_ip):
        """ Insert a high-priority DROP rule for all traffic from src_ip. """
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x0800  # IPv4
        fm.match.nw_src = src_ip
        fm.priority = 100
        # no actions => drop
        fm.idle_timeout = 120
        fm.hard_timeout = 300
        self.connection.send(fm)
        log.info("  => Pushed DROP rule for %s", src_ip)


def launch(transparent=False, hold_down=None):
    """
    POX "launch" function
    usage: ./pox.py log.level --DEBUG kye_merge_controller [--transparent=False] [--hold_down=0]
    """
    global FLOOD_DELAY
    if hold_down is not None:
        FLOOD_DELAY = int(hold_down)

    transparent = str(transparent).lower() == 'true'

    def start_switch(event):
        log.info("** Merged KYE-L2Switch on %s", event.connection)
        MergeKYEL2Switch(event.connection, transparent=transparent)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
