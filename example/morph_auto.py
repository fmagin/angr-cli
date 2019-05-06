#!/usr/bin/env python3

import logging
import angr
import claripy

logging.getLogger("angr.sim_manager").setLevel(logging.INFO)

class NotVeryRand(angr.SimProcedure):
    def run(self, return_values=None):
        rand_idx = self.state.globals.get('rand_idx', 0) % len(return_values)
        out = return_values[rand_idx]
        self.state.globals['rand_idx'] = rand_idx + 1
        return out

winStr = b'What are you waiting for, go submit that flag!'
testfile = "./morph"
argv = claripy.BVS('argv1', 8 * 0x17)

p = angr.Project(testfile, 
                 support_selfmodifying_code=True,
                 load_options={"auto_load_libs":False})

p.hook_symbol('time', NotVeryRand(return_values=[0]))
p.hook_symbol('rand', NotVeryRand(return_values=[0]))

s = p.factory.entry_state(args=[p.filename, argv])

simgr = p.factory.simgr(s)#, save_unsat=True)


simgr.explore(find=lambda s: winStr in s.posix.dumps(1)) # winStr in stdout
print("Exploration done! Result:", str(simgr))
if len(simgr.stashes["found"]) > 0:
    print(simgr.one_found.solver.eval(argv, cast_to=bytes)

