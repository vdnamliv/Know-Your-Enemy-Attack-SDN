# Know Your Enemy Attack in Software Defined Network
Implement KYE attack (Side Channel Attack) in SDN environment, and using Flow Obfuscation to defense it.

## Set up environment and Install 
- Warning: Only use with Python 2.7, so using python-venv is a good work
- Install Python 2.7 and python-venv:
```
sudo apt update
sudo apt install python2.7 python2-pip
virtualenv -p python2.7 venv
source venv/bin/activate
```
- Install dependencies and run POX:
```
pip install --upgrade pip==20.3.4 setuptools==44.1.1 wheel==0.37.1
git clone https://github.com/noxrepo/pox.git
```
- Install mininet, hping3:
```
sudo apt install hping3 -y
sudo apt install mininet -y
```
- Put kye_controller.py to your venv/pox 

## Implement
- Run controller:
```
./pox.py log.level --DEBUG kye_controller 
```
- Run topology in mininet:
```
sudo mn --custom topology.py --topo largesdntopo --controller remote
```
- Dump flow:
```
sudo ovs-ofctl dump-flows s1
```
-Del flow:
```
sudo ovs-ofctl del-flows s1
```
