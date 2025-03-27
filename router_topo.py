from mininet.topo import Topo
from mininet.node import Node

class LinuxRouter(Node):
    """Node chạy như router Linux, bật IP forwarding."""
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        # Bật IP forwarding
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

class ThreeSubnetRouterTopo(Topo):
    def build(self):
        # Tạo router r1, gán IP mặc định cho 1 interface
        router = self.addNode('r1', cls=LinuxRouter, ip='10.0.0.254/24')

        # Tạo 3 switch
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Link r1 - s1 (subnet 10.0.0.x)
        self.addLink(router, s1,
                     intfName1='r1-eth0',  # cổng router
                     params1={'ip':'10.0.0.254/24'})  # IP router cổng eth0

        # Link r1 - s2 (subnet 10.0.1.x)
        self.addLink(router, s2,
                     intfName1='r1-eth1',
                     params1={'ip':'10.0.1.254/24'})

        # Link r1 - s3 (subnet 10.0.2.x)
        self.addLink(router, s3,
                     intfName1='r1-eth2',
                     params1={'ip':'10.0.2.254/24'})

        # 10 hosts tại subnet 10.0.0.x
        for i in range(1, 11):
            h = self.addHost(f'h{i}',
                             ip=f'10.0.0.{i}/24',
                             defaultRoute='via 10.0.0.254')
            self.addLink(h, s1)

        # 10 hosts subnet 10.0.1.x
        for i in range(11, 21):
            h = self.addHost(f'h{i}',
                             ip=f'10.0.1.{i-10}/24',
                             defaultRoute='via 10.0.1.254')
            self.addLink(h, s2)

        # 10 hosts subnet 10.0.2.x
        for i in range(21, 31):
            h = self.addHost(f'h{i}',
                             ip=f'10.0.2.{i-20}/24',
                             defaultRoute='via 10.0.2.254')
            self.addLink(h, s3)

topos = { 'threesubnet': (lambda: ThreeSubnetRouterTopo()) }
