#!/usr/bin/env python3

import angr
import angrcli.plugins.context_view
from angrcli.interaction.explore import ExploreInteractive
from angrcli.plugins.context_view import ContextView as cv
import claripy
import logging
import pickle
import IPython

logging.getLogger("angr.engines.vex.engine").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.ERROR)

testfile = "./MarsAnalytica"
p = angr.Project(testfile)
string = """
flag = claripy.BVS("flag", 8*19)
s = p.factory.entry_state(stdin=flag, add_options=angr.options.unicorn)
for b in flag.chop(8):
   s.solver.add(b > 0x20) 
   s.solver.add(b < 0x7f) 
sm = p.factory.simulation_manager(s)
print("Simulating until first branch")

sm.run(until=lambda lpg: len(lpg.active) > 1)
print("Reached first branch!")
f1 = open("mars_state1", "wb")
f2 = open("mars_state2", "wb")
f1.write(pickle.dumps(sm.active[0], -1))
f1.close()
f2.write(pickle.dumps(sm.active[1], -1))
f2.close()
print("States stored!")
"""
f1 = open("mars_state1", "rb")
f2 = open("mars_state2", "rb")
s1 = pickle.loads(f1.read())
s2 = pickle.loads(f2.read())
f1.close()
f2.close()
sm = p.factory.simgr([s1, s2])

print("starting exploring")
# Strategy: Explore from this point. Most constrained is good!
# active[0].history.jump_guard:     0x317 == mul(__reverse(...))
# active[1].history.jump_guard:     0x317 != mul(__reverse(...))
while len(sm.deadended) == 0:
    print(sm)
    # Drop every state from 'active', except the first one (which is the most constrained one)
    sm.drop(stash='active', filter_func=lambda s: s != sm.active[0])
    print(sm.one_active.posix.dumps(0))
    # Continue to next branch
    sm.run(until=lambda lpg: len(lpg.deadended) > 1 or len(lpg.active) > 1)

IPython.embed()
print("Done!")

s.context_view.pprint()
e = ExploreInteractive(p, s)
e.cmdloop()

import IPython; IPython.embed()
