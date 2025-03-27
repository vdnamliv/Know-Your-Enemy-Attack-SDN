from mininet.topo import Topo

class LargeSDNTopo(Topo):
    def build(self):
        # 3 Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Hosts 1..10 => subnet 10.0.0.x/24
        for i in range(1, 11):
            ip = f"10.0.0.{i}/24"
            h = self.addHost(f"h{i}", ip=ip)
            self.addLink(h, s1)

        # Hosts 11..20 => subnet 10.0.1.x/24
        # ip = 10.0.1.(i-10)/24 để .1..10
        for i in range(11, 21):
            ip = f"10.0.1.{i-10}/24"
            h = self.addHost(f"h{i}", ip=ip)
            self.addLink(h, s2)

        # Hosts 21..30 => subnet 10.0.2.x/24
        for i in range(21, 31):
            ip = f"10.0.2.{i-20}/24"
            h = self.addHost(f"h{i}", ip=ip)
            self.addLink(h, s3)

        # Links between switches
        self.addLink(s1, s2)
        self.addLink(s2, s3)

topos = {'largesdntopo': (lambda: LargeSDNTopo())}
