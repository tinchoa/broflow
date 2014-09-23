# Simulate a long road trip 
from pox.lib.recoco import Timer
 
we_are_there = False
 
def are_we_there_yet ():
	if we_are_there: return False # Cancels timer (see selfStoppable)
	print "Are we there yet?"

Timer(5, are_we_there_yet, recurring = True)
