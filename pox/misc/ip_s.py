from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
from collections import namedtuple
import pox.lib.packet as pkt
import os
import string,sys,socket,json, subprocess
import thread 

log = core.getLogger()


#globlal variables
#global received #Revisar si funciona
ip_honeypot=IPAddr("192.168.0.14")
mac_honey= EthAddr("00:19:e2:4d:ac:02")

#ip_dest = str(sys.argv[1])

#############################here is the socket server ####
#def thread_socket(): #thread 1

#	global received
#	s = socket.socket()         # Create a socket object
#	host = '192.168.254.254'	#the host is receiving by interface 2
#	port = 12345                # Reserve a port for your service.
#	s.bind((host, port))        # Bind to the port
#	s.listen(5)                 # Now wait for client connection.

#	while True:
#		c, addr = s.accept()	# Establish connection with client.
#		print 'Message from', addr
#		received_data = c.recv(1024)

#		global received
#		received = received_data
		
		#        	if received == "quit":
		#               	print "Closing..."
		#	                break
 #		c.close()                # Close the socket connection   
#	thread.exit()
	#return received_data

######openflow code

####
#	global Interface, IP_dst, Port, MAC, IP_attack
class connect_test(EventMixin):	
  # Waits for OpenFlow switches to connect and makes them learning switches.
	#Global variables of connect_test subclass
	#global received
	def __init__(self):
		self.listenTo(core.openflow)
		log.debug("Enabling Firewall Module")
		
def thread_socket(): #thread 1
	global received
	s = socket.socket()         # Create a socket object
	host = '192.168.254.254'        #the host is receiving by interface 2
	port = 12345                # Reserve a port for your service.
	s.bind((host, port))        # Bind to the port
	s.listen(5)                 # Now wait for client connection.
	while True:
		c, addr = s.accept()    # Establish connection with client.
		print 'Message from', addr
		received_data = c.recv(1024)
		global received
		received = received_data
                #               if received == "quit":
                #                       print "Closing..."
                #                       break
		c.close()                # Close the socket connection   
	thread.exit()

	def _handle_ConnectionUp (self, event):
#		log.debug("Connection %s" % (event.connection,))
#		self.switches[str(event.dpid)] = LearningSwitch(event.connection, self.transparent)
		print event.dpid
		#thread.start_new_thread(thread_socket, tuple([]))
	#	global received
		thread.start_new_thread(thread_socket,tuple([]))

#################################################################json
		global received
		encoded_data = json.loads(received)
		Interface=encoded_data[0]["Interface"]
		IP_dst=encoded_data[0]["IP_dst"]
		Port=encoded_data[0]["Port"]
		MAC=encoded_data[0]["MAC"]
		IP_attack=encoded_data[0]["IP_attack"]
		ifaceid=Interface.split("eth")
		ifaceid=ifaceid[1]
		port_dst=Port.split("/")
		port_dst=port_dst[0]

		#        print Interface
		#        print IP_dst
		#        print Port
		#        print MAC
		#	print IP_attack

##########getting the domain name
		directory= "cd /root/VMs/cfgvms " #virtual machine configuration directory
		cmd= " grep -ri "
		name= subprocess.check_output(directory  +  "&&"  +  cmd  + MAC, shell=True)
		aux_name=name.split(".cfg")
		name=aux_name[0]

###here i get the vif 
		command="xm domid " #getting de domain id
		vmid=subprocess.check_output(command + name, shell=True)
		aux_v=vmid.split("\n")
		vmid=aux_v[0]
		#vmid=45
		#ifaceid=2

		#tag1=`ovs-vsctl list port vif$vmid.$ifaceid | grep tag | awk '{print$3}'

#####here i get the vlan tag

		proceso= 'ovs-vsctl list port '
		proceso2= '| grep tag |'
		proceso3=  " awk  '{print $3}'"
#		print "vif"+vmid+"."+Interface
		vlan_tag = subprocess.check_output(proceso +"vif"+vmid+"."+ifaceid + proceso2 +proceso3 ,shell=True)
		aux2=vlan_tag.split("\n")
		vlan_tag=aux2[0]
		print vlan_tag

		############################################################

		my_match = of.ofp_match(dl_type = 0x800,
dl_vlan=vlan_tag,
nw_src=IP_attack,
nw_dst=IP_dst,
tp_dst=port_dst ) ### i got the flux from the attacker to the Bro
		my_match.set_dst(IPAddr(ip_honeypot))
			
## i got this from antonio and ulysses

#	def _handle_PacketIn (event):
#		packet = event.parsed
##creating msg to match the correct vlan tag
#		msg = of.ofp_flow_mod()
#		msg.match.dl_type = 0x800
#		msg.match.nw_src = ip_packet.srcip
#		msg.match.nw_dst = ip_packet.dstip
#		msg.match.dl_vlan = vlan_tag #it is like that???
##	
	
##	action = ofp_action_nw_addr.set_dst(IPAddr(ip_honeypot)) #this flux is send to the honeypot
		


##c.close()                # Close the socket connection


def launch ():
	core.registerNew(connect_test)

#t = threading.Thread(target=thread_socket)
	#args=(Interface, IP_dst, Port, MAC,IP_attack))
#t2= threading.Thread(target=open_flow, args=(Interface, IP_dst, Port, MAC,IP_attack) )
#t.start()
#t2.start()

