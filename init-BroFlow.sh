##./set-controller.sh

ovs-vsctl set-controller OVS0 tcp:127.0.0.1:2266

echo controller set at local host 127.0.0.1 port 2266
#controller set on port 2266


#starting the controler +forwarding +BroFLow
/root/martin/pox/pox.py openflow.of_01 --port=2266 misc.broflow forwarding.l2_learning




