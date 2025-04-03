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

class SixSubnetRouterTopo(Topo):
    def build(self):
        # Tạo router r1, IP mặc định cho interface đầu tiên
        router = self.addNode('r1', cls=LinuxRouter, ip='10.0.0.254/24')

        # Tạo 6 switch
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')

        # Link r1 - s1 (subnet 10.0.0.x)
        self.addLink(router, s1,
                     intfName1='r1-eth0',
                     params1={'ip': '10.0.0.254/24'})  # cổng eth0 => 10.0.0.x

        # Link r1 - s2 (subnet 10.0.1.x)
        self.addLink(router, s2,
                     intfName1='r1-eth1',
                     params1={'ip': '10.0.1.254/24'})

        # Link r1 - s3 (subnet 10.0.2.x)
        self.addLink(router, s3,
                     intfName1='r1-eth2',
                     params1={'ip': '10.0.2.254/24'})

        # Link r1 - s4 (subnet 10.0.3.x)
        self.addLink(router, s4,
                     intfName1='r1-eth3',
                     params1={'ip': '10.0.3.254/24'})

        # Link r1 - s5 (subnet 10.0.4.x)
        self.addLink(router, s5,
                     intfName1='r1-eth4',
                     params1={'ip': '10.0.4.254/24'})

        # Link r1 - s6 (subnet 10.0.5.x)
        self.addLink(router, s6,
                     intfName1='r1-eth5',
                     params1={'ip': '10.0.5.254/24'})

        # Mỗi subnet 5 host => tổng 30 host
        # Subnet 10.0.0.x: h1..h5
        for i in range(1, 6):
            h = self.addHost(f'h{i}',
                             ip=f'10.0.0.{i}/24',
                             defaultRoute='via 10.0.0.254')
            self.addLink(h, s1)

        # Subnet 10.0.1.x: h6..h10
        for i in range(6, 11):
            h = self.addHost(f'h{i}',
                             ip=f'10.0.1.{i-5}/24',
                             defaultRoute='via 10.0.1.254')
            self.addLink(h, s2)

        # Subnet 10.0.2.x: h11..h15
        for i in range(11, 16):
            h = self.addHost(f'h{i}',
                             ip=f'10.0.2.{i-10}/24',
                             defaultRoute='via 10.0.2.254')
            self.addLink(h, s3)

        # Subnet 10.0.3.x: h16..h20
        for i in range(16, 21):
            h = self.addHost(f'h{i}',
                             ip=f'10.0.3.{i-15}/24',
                             defaultRoute='via 10.0.3.254')
            self.addLink(h, s4)

        # Subnet 10.0.4.x: h21..h25
        for i in range(21, 26):
            h = self.addHost(f'h{i}',
                             ip=f'10.0.4.{i-20}/24',
                             defaultRoute='via 10.0.4.254')
            self.addLink(h, s5)

        # Subnet 10.0.5.x: h26..h30
        for i in range(26, 31):
            h = self.addHost(f'h{i}',
                             ip=f'10.0.5.{i-25}/24',
                             defaultRoute='via 10.0.5.254')
            self.addLink(h, s6)

topos = { 'sixsubnet': (lambda: SixSubnetRouterTopo()) }
