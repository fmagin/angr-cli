import angr
import angrcli.plugins.context_view
from angrcli.interaction.explore import ExploreInteractive
from angrcli.plugins.context_view import ContextView as cv
import claripy
import logging
logging.getLogger("angr.engines.vex.engine").setLevel(logging.ERROR)


proj = angr.Project("/Users/alexander/code/CTFs/2017/17-34C3CTF/m0rph/morph", support_selfmodifying_code=True, load_options={"auto_load_libs":False, 'main_opts': {'custom_base_addr': 0x555555554000}})
cfg = proj.analyses.CFGFast()
argc = claripy.BVS("argc", 64)
argv = claripy.BVS('argv1', 8 * 0x17)
#state = proj.factory.call_state(0x0000555555554A76, argc, [argv] )
state = proj.factory.entry_state(args=[argc, argv])
state.se._solver.timeout = state.se._solver.timeout * 10
state.register_plugin("context_view", cv())
#from angrcli.plugins.stackview import Stack
#state.register_plugin("stack", Stack())

class NotVeryRand(angr.SimProcedure):
    def run(self, return_values=None):
        rand_idx = self.state.globals.get('rand_idx', 0) % len(return_values)
        out = return_values[rand_idx]
        self.state.globals['rand_idx'] = rand_idx + 1
        return out
    
proj.hook_symbol('time', NotVeryRand(return_values=[0]))
proj.hook_symbol('rand', NotVeryRand(return_values=[0]))


simgr = proj.factory.simgr(state, save_unsat=True)

state.context_view.pprint()
e = ExploreInteractive(proj, state)
e.cmdloop()
