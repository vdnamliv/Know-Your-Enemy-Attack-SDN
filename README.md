# Know Your Enemy Attack in Software Defined Network
Implement KYE attack (Side Channel Attack) in SDN environment, and using Flow Obfuscation to defense it.

## Set up
- Put kye_controller.py to your venv/pox 

## Implement
- Run controller:
```
./pox.py log.level --DEBUG kye_controller 
```
- Run topology in mininet:
```
sudo mn --custom topology.py --topo simplesdntopo --controller remote
```
