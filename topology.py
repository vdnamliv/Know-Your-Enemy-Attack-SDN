from mininet.topo import Topo

class LargeSDNTopo(Topo):
    def build(self):
        # 3 Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # 30 Hosts
        hosts = []
        for i in range(1, 31):
            ip = f"10.0.0.{i}/24"
            host = self.addHost(f'h{i}', ip=ip)
            hosts.append(host)

        # Links between switches
        self.addLink(s1, s2)
        self.addLink(s2, s3)

        # Assign hosts to switches (dividing equally)
        for i in range(10):
            self.addLink(hosts[i], s1)   # h1-h10 → s1
        for i in range(10, 20):
            self.addLink(hosts[i], s2)   # h11-h20 → s2
        for i in range(20, 30):
            self.addLink(hosts[i], s3)   # h21-h30 → s3

topos = {'largesdntopo': (lambda: LargeSDNTopo())}
