# How to collect data and find the threshold of TRW-CB
## Requirement
1. Have 2 terminal: run topo in mininet and kye_controller.py, and both inside venv
2. In mininet:
```
sudo mn --custom router_topo.py --topo threesubnet --controller remote --switch ovsk  
mininet> xterm h1 h1 h20
```
3. In h1:
```
source venv/bin/activate  
First h1: sudo tcpdump -i h1-eth0 -n host 10.0.1.10 -w scan_capture.pcap  
Second h2: sudo hping3 -S -p 80 -c 35 -i u100000 10.0.1.10
```
4. In h20:
```
source venv/bin/activate
sudo sysctl -w net.core.somaxconn=1024
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=1024
nc -lk 80 
```
