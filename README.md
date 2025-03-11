# Know Your Enemy Attack in Software Defined Network
Implement KYE attack (Side Channel Attack) in SDN environment, and using Flow Obfuscation to defense it.

## Set up
- Put kye_controller.py to your venv/pox 

## Implement
- Run controller:
```
./pox.py log.level --DEBUG samples.pretty_log forwarding.l2_learning kye_controller 
```
- Run topology in mininet:
```
sudo mn --custom topo_1.py --topo simplesdntopo --controller remote
```
