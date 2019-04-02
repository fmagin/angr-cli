#!/usr/bin/env python3

import angr
import angrcli.plugins.context_view
from angrcli.interaction.explore import ExploreInteractive
from angrcli.plugins.context_view import ContextView as cv
import claripy
import logging
logging.getLogger("angr.engines.vex.engine").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.ERROR)

winStr = b'What are you waiting for, go submit that flag!'
testfile = "./morph"
p = angr.Project(testfile, support_selfmodifying_code=True,
        load_options={"auto_load_libs":False, 
                    'main_opts': {
                        'custom_base_addr': 0x555555554000 # To match gdb
                        }
                    }) 

argv = claripy.BVS('argv1', 8 * 0x17)

s = p.factory.entry_state(args=[p.filename, argv])
s.solver._solver.timeout = s.solver._solver.timeout * 10

s.register_plugin("context_view", cv())

class NotVeryRand(angr.SimProcedure):
    def run(self, return_values=None):
        rand_idx = self.state.globals.get('rand_idx', 0) % len(return_values)
        out = return_values[rand_idx]
        self.state.globals['rand_idx'] = rand_idx + 1
        return out
    
p.hook_symbol('time', NotVeryRand(return_values=[0]))
p.hook_symbol('rand', NotVeryRand(return_values=[0]))


simgr = p.factory.simgr(s, save_unsat=True)

s.context_view.pprint()
e = ExploreInteractive(p, s)
e.cmdloop()


