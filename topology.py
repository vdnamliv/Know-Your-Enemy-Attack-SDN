from mininet.topo import Topo

class SimpleSDNTopo(Topo):
    def build(self):
        # 3 Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # 6 Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
        h2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
        h3 = self.addHost('h3', ip='10.0.0.3/24', defaultRoute='via 10.0.0.254')
        h4 = self.addHost('h4', ip='10.0.0.4/24', defaultRoute='via 10.0.0.254')
        h5 = self.addHost('h5', ip='10.0.0.5/24', defaultRoute='via 10.0.0.254')
        h6 = self.addHost('h6', ip='10.0.0.6/24', defaultRoute='via 10.0.0.254')

        # Links
        self.addLink(s1, s2)
        self.addLink(s2, s3)

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)

topos = {'simplesdntopo': (lambda: SimpleSDNTopo())}
