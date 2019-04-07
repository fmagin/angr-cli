#!/usr/bin/env python3

import angr
import claripy
import logging
logging.getLogger("angr.sim_manager").setLevel(logging.INFO)

winStr = b'What are you waiting for, go submit that flag!'
testfile = "./morph"
p = angr.Project(testfile) 
argv = claripy.BVS('argv1', 8 * 0x17)
s = p.factory.entry_state(args=[p.filename, argv])

class NotVeryRand(angr.SimProcedure):
    def run(self, return_values=None):
        rand_idx = self.state.globals.get('rand_idx', 0) % len(return_values)
        out = return_values[rand_idx]
        self.state.globals['rand_idx'] = rand_idx + 1
        return out
p.hook_symbol('time', NotVeryRand(return_values=[0]))
p.hook_symbol('rand', NotVeryRand(return_values=[0]))

simgr = p.factory.simgr(s)#, save_unsat=True)
simgr.explore(find=lambda s: winStr in s.posix.dumps(1)) # winStr in stdout
print(simgr.one_found.solver.eval(argv, cast_to=bytes))

