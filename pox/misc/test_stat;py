from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
from collections import namedtuple
import pox.lib.packet as pkt
import os
import string, sys, socket, json, subprocess
import thread 
from threading import Thread
import time
#######################################

def listarFluxosIp(event):
	print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	fluxosIp = []
	IP_dst=IPAddr("192.168.0.14")
	for fluxo in  event.stats:
		print 'Um dos Fluxos Atuais'
		print fluxo.match
		if fluxo.match.nw_src == IP_dst:
				fluxosIp.append(fluxo.match)
				msg = of.ofp_flow_mod()
				msg.match = fluxo.match
				msg.idle_timeout = 20
				msg.hard_timeout = 20
				msg.priority = 65535
				print 'Fluxo barrado'
				print fluxo.match
		msg = of.ofp_flow_mod()
		msg.match.dl_type = 0x800
		msg.match.nw_src = IPAddr(IP_dst)
		msg.idle_timeout = 20
		msg.hard_timeout = 20
		msg.priority = 65535
		print 'Ip barrado', IP_dst
	print fluxosIp
	