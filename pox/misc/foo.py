from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
from collections import namedtuple
import pox.lib.packet as pkt
import os
import string,sys

class MyComponent (object):
  def __init__ (self, an_arg):
    self.arg = an_arg
    print "MyComponent instance registered with arg:", self.arg
 
  def foo (self):
    print "MyComponent with arg:", self.arg
 
 
def launch ():
  component = MyComponent("spam")
  core.register("thing", component)
  core.thing.foo() # prints "MyComponent with arg: spam"
