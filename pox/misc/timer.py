from pox.lib.recoco import Timer

def handle_timer_elapse (message):
 print "I was told to tell you:", message

Timer(10, handle_timer_elapse, args = ["Hello"])

# Prints out "I was told to tell you: Hello" in 10 seconds

# Alternate way for simple timers:
from pox.core import core # Many components already do this
core.callDelayed(10, handle_timer_elapse, "Hello") # You can just tack on args and kwargs

