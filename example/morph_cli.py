#!/usr/bin/env python3

import angr
from angrcli.interaction.explore import ExploreInteractive
import angrcli.plugins.ContextView
import claripy
import logging
logging.getLogger("angr.engines.vex.engine").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.ERROR)

testfile = "./morph"
p = angr.Project(testfile, support_selfmodifying_code=True,
        load_options={"auto_load_libs":False, 
        #load_options={"auto_load_libs":True, 
                    'main_opts': {
                        'base_addr': 0x555555554000 # To match gdb
                        }
                    }) 
argv = claripy.BVS('argv1', 8 * 0x17)
s = p.factory.entry_state(args=[p.filename, argv])


#s.register_plugin("context_view", cv())

class NotVeryRand(angr.SimProcedure):
    def run(self, return_values=None):
        rand_idx = self.state.globals.get('rand_idx', 0) % len(return_values)
        out = return_values[rand_idx]
        self.state.globals['rand_idx'] = rand_idx + 1
        return out
    
p.hook_symbol('time', NotVeryRand(return_values=[0]))
p.hook_symbol('rand', NotVeryRand(return_values=[0]))

s.watches.add_watch(lambda state: state.solver.eval(argv, cast_to=bytes), "argv[1]")

simgr = p.factory.simgr(s, save_unsat=True)

s.context_view.pprint()
e = ExploreInteractive(p, s)
e.cmdloop()

print("Done! e.simgr has the simgr from your session")

