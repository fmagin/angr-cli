import nose
import os
import angr
import claripy
import angrcli.plugins.ContextView.context_view
from angrcli.interaction.explore import ExploreInteractive

morph_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "example", "morph")

proj = angr.Project(morph_location, load_options={'auto_load_libs': False})



class NotVeryRand(angr.SimProcedure):
    def run(self, return_values=None):
        rand_idx = self.state.globals.get('rand_idx', 0) % len(return_values)
        out = return_values[rand_idx]
        self.state.globals['rand_idx'] = rand_idx + 1
        return out


argv = claripy.BVS('argv1', 8 * 0x17)
state = proj.factory.entry_state(args=[proj.filename, argv])

state.watches.add_watch(lambda state: state.solver.eval(argv, cast_to=bytes), "argv[1]")

proj.hook_symbol('time', NotVeryRand(return_values=[0]))
proj.hook_symbol('rand', NotVeryRand(return_values=[0]))

e = ExploreInteractive(proj, state)

def test_morph():
    # Run until first branch
    e.do_run("")

    # Select correct Strlen result
    e.do_run("0")
    # Check that some code is being printed
    assert "No code at current ip" not in e.state.context_view._ContextView__pstr_current_codeblock(), "Code not being printed correctly"

    for _ in range(0,23):
        e.do_run("0")

    assert e.simgr.one_deadended.watches['argv[1]'] == b'34C3_M1GHTY_M0RPh1nG_g0', "Invalid watch result %s" % e.simgr.one_deadended.watches['argv[1]']

if __name__ == "__main__":
    test_morph()
