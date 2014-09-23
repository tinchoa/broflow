from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.addresses import EthAddr, IPAddr
from collections import namedtuple
from pox.topology.topology import Switch, Entity
from pox.lib.revent import EventMixin
import pox.lib.packet as pkt
import os
import string, sys, socket, json, subprocess
import thread 
from threading import Thread
import time, datetime

#######################################variable declaration

#########################################################thread example
class testit(Thread):
	def __init__ (self,ip,pai=None):
		Thread.__init__(self)
		self.ip = ip
		self.status = -1
		self.pai = pai
	def run(self):
		while True:
			print "meu ip eh", self.ip
			time.sleep(2)
################################################################# definitions
print "Welcome to BroFlow Network Controller"
log = core.getLogger()
ip_honeypot=IPAddr("192.168.0.14")
mac_honey= EthAddr("00:19:e2:4d:ac:02")

duration_block = 15 #seconds to block flow


###############################output log
outputLog=open('output.csv', 'a')

#############################here is the socket server ####
class server_socket(Thread):
	
	def __init__(self, connections):
		Thread.__init__(self)
		global received
		self.sock = None
		self.status =-1			
		self.connections = connections							#dpdi of the switch

	def run(self):
		self.sock = socket.socket()         					# Create a socket object
		host = '192.168.254.254'								# The host is receiving by interface 2
		port = 12345               								# Reserve a port for your service.
		self.sock.bind((host, port))        					# Bind to the port
		self.sock.listen(5)                	 					# Now wait for client connection.
		while True:												# If this while was on it will never stop
			client, addr = self.sock.accept()					# Establish connection with client
			data = client.recv(1024)							# Get data from the client 
			print 'Message from', addr 							# Print a message confirming 
			data_treatment = data_trat(data,self.connections,addr)	# Call the thread to work with the data received
			data_treatment.setDaemon(True)						# Set the thread as a demond
			data_treatment.start()								# Start the thread
		
	#client.close()				                				# Close the socket connection  
																# This close is not working it should be in a function to close the thread

###########################thread to treat the data
class data_trat(Thread):
	def __init__(self,received,connections,addressSen):
		Thread.__init__(self)
		self.received = received
		self.myconnections = connections
		self.addressSensor = addressSen
	

	def run(self):
		encoded_data = json.loads(self.received) #received the json data 
		Action_of=encoded_data[0]["Action_of"]
		Interface=encoded_data[0]["Interface"]
		IP_dst=encoded_data[0]["IP_dst"]
		Port=encoded_data[0]["Port"]
#		MAC=encoded_data[0]["MAC"]
		IP_attack=encoded_data[0]["IP_attack"]
	#	ifaceid=Interface.split("eth")
	#	ifaceid=ifaceid[1]
		port_dst=Port.split("/")
		port_dst=port_dst[0]
#		print Interface
#		print IP_dst
#		print Port
#		print MAC
#		print Action_of

####MOMENTANEAMENTE FORA DO AR!!!!! VER COMO VOY A SOLUCIONAR EL PROBLEMA DE PEGAR LA VIF PARA MODIFICAR EL TAG DE VLAN


# ##########getting the domain name for xen
	# 		##directory= "cd /root/VMs/cfgvms/experimento-sbrc2014 " #virtual machine configuration directory
	# 		directory= "cd /root/VMs/cfgvms/ " #virtual machine configuration directory
	# 		cmd= " grep -ri "
	# 		name= subprocess.check_output(directory  +  "&&"  +  cmd  + MAC, shell=True)
	# 		aux_name=name.split(".cfg")
	# 		name=aux_name[0]
	# ##########here i get the vif 
	# 		command="xm domid " #getting de domain id
	# 		vmid=subprocess.check_output(command + name, shell=True) #este 
	# 		aux_v=vmid.split("\n")#este
	# 		vmid=aux_v[0]		#este deberian in si o si 
	# 		#tag1=`ovs-vsctl list port vif$vmid.$ifaceid | grep tag | awk '{print$3}'
	# ##########here i get the vlan tag
	# 		proceso= 'ovs-vsctl list port '
	# 		proceso2= '| grep tag |'
	# 		proceso3=  " awk  '{print $3}'"
	# 		vlan_tag = subprocess.check_output(proceso +"vif"+vmid+"."+ifaceid + proceso2 +proceso3 ,shell=True)
	# 		aux2=vlan_tag.split("\n")
	# 		vlan_tag=aux2[0]
	# 		vlan_tag=int(vlan_tag)
	# 		#		print vlan_tag
	######################################################



		my_match = of.ofp_match(dl_type = 0x800, # this is to catch the flux i want to move
#			dl_vlan=vlan_tag, #ACA TB TENGO Q SACAR
			#dl_vlan = 830,			
#			dl_dst= EthAddr(MAC),
			#nw_src=IPAddr(IP_attack),
			nw_src=IPAddr(IP_attack),
			nw_dst=IPAddr(IP_dst),
			#tp_dst=port_dst
			 ) ### i got the flux from the attacker to the Bro
		
		msg = of.ofp_flow_mod() 	# create a flow modification
		msg.match = my_match		# get the match of the flow before
	
#######################################Kill the old flux##################################
		def cleanSwitches():
			# create ofp_flow_mod message to delete all flows
			# (note that flow_mods match all flows by default)
			msg1 = of.ofp_flow_mod(command=of.OFPFC_DELETE)
 			# iterate over all connected switches and delete all their flows
			for connection in core.openflow.connections: # _connections.values() before betta
				connection.send(msg1)
				log.debug("Clearing all flows from %s." % (dpidToStr(connection.dpid),))
				print "cleaning flows"
	



######################################Drop################################################
		def dropping (duration=duration_block): #this is the time that flow will be blocked in seconds
			cleanSwitches()
			msg.priority=65535
			#msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = 831)) 		# modify the vlan id from the 830 to 831 
			if duration is not None:
				if not isinstance(duration, tuple):
					duration = (duration,duration)
		 		msg.idle_timeout = duration[0] #this made the flow go back after the specified time
		 		msg.hard_timeout = duration[1]
			print "dropping packets from ", IP_attack 	
			ts = time.time() #create time stamp
			st = datetime.datetime.fromtimestamp(ts).strftime('%d-%m-%Y %H:%M:%S')	#human format time stamp	
			outputLog.write("Flow Blocked "+ IP_attack +"-->" + IP_dst +' '+ str(st) +" detected by "+self.addressSensor[0]+'\n')# creating the log #see how to create a log style
			for connection in self.myconnections:
				connection.send(msg)  													#send the msg to the switch
				connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request())) #getting the flux stats
				print "MSG sent to switches!"


####################################Honeypot#####################################################
		def honeypot():
			print "Honeypot"	
			msg.actions.append(of.ofp_action_dl_addr.set_dst(mac_honey)) 	# honeypot MAC address
			msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = 831)) 		# modify the vlan id from the 830 to 831 
			msg.actions.append(of.ofp_action_nw_addr.set_dst(ip_honeypot))  # action to send the flux to the honey_pot
			msg.actions.append(of.ofp_action_output(port = 6)) 			# which port the honeypot is connected 
			ts = time.time()
			st = datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S %d-%m-%Y')		
			outputLog.write("Flow Deviated "+ IP_attack +"-->" + IP_dst +' '+ str(st) +'\n')
																		# see how i can get this port by python
			for connection in self.myconnections:
				connection.send(msg)  													#send the msg to the switch
				connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request())) #getting the flux stats
				print "MSG sent to switchs"
##############################OpenFlow Actions ###############################################
	
		if (Action_of =='drop'):
			dropping()
		elif (Action_of == 'honeypot'):
			honeypot()		

		#outputLog.close()		

# def listarFluxosIp(event):
# 	fluxosIp = []
# 	global ip_honeypot
# 	IP_dst=IPAddr("192.168.0.101")
# 	for fluxo in  event.stats:
# 		print 'Um dos Fluxos Atuais'
# 		print fluxo.match
# 		if fluxo.match.nw_src == IP_dst:
# 				fluxosIp.append(fluxo.match)
# 				msg = of.ofp_flow_mod()
# 				msg.match = fluxo.match
# 				msg.idle_timeout = 20
# 				msg.hard_timeout = 20
# 				msg.priority = 65535
# 				print 'Fluxo barrado'
# 				print fluxo.match
# 		#msg = of.ofp_flow_mod()
# 		#msg.match.dl_type = 0x800
# 		#msg.match.nw_src = IPAddr(IP_dst)
# 		#msg.idle_timeout = 20
# 		#msg.hard_timeout = 20
# 		#msg.priority = 65535
# #		print 'Ip barrado', IP_dst
# 	#print fluxosIp
	
#####################################################openflow code
#	global Interface, IP_dst, Port, MAC, IP_attack
class connect_test(EventMixin):	
  # Waits for OpenFlow switches to connect and makes them learning switches.
	#Global variables of connect_test subclass
	#global received
	def __init__(self):
		self.listenTo(core.openflow)
		log.debug("Enabling Firewall Module")
		#minhaThread = testit("192.168.254.254")
		#minhaThread.setDaemon(True)
		#minhaThread.start()
		self.myconnections=[]		# a list of the connections
		socket_server=server_socket(self.myconnections)	# send it to the socket with the connection 
		socket_server.setDaemon(True)		# establish the thread as a deamond, this will make to close the thread with the main program
		socket_server.start()				# starting the thread

	def _handle_ConnectionUp (self, event):
		print event.dpid #it prints the switch connection information, on the screen
		self.myconnections.append(event.connection)	# will pass as a reference to above

###############################################this is to "listen" the connection stats

for con in core.openflow.connections: # make this _connections.keys() for pre-betta
	con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))


#######################this is to launch the program
def launch ():
	#core.openflow.addListenerByName("FlowStatsReceived", listarFluxosIp)
	core.registerNew(connect_test)
