import nose
import os
import angr
import claripy
import angrcli.plugins.ContextView.context_view
from angrcli.interaction.explore import ExploreInteractive

from angrcli.plugins.ContextView.colors import Color

Color.disable_colors = True
location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "sym_exec.elf")

proj = angr.Project(location, load_options={'auto_load_libs': False})

#cfg = proj.analyses.CFGFast()




def test_proper_termination():
    state = proj.factory.entry_state()
    e = ExploreInteractive(proj, state)


    for _ in range(0,20):
        e.do_step("")

    # Final step
    e.do_step("")

    # One state should be deadended
    nose.tools.assert_equal(len(e.simgr.deadended), 1)

    # Stepping without active states should not throw an exception
    e.do_step("")

def test_branching():
    argv1 = claripy.BVS("argv1", 8 * 16)
    state = proj.factory.entry_state(args=[proj.filename, argv1])
    e = ExploreInteractive(proj, state)

    e.do_run("")
    state = e.state

    # Try stepping and check that the state has not been changed
    e.do_step("")
    nose.tools.assert_equal(state, e.state, "State is not equal anymore")


    # Check that branch info is as expected. Bit hacky because the generated name of the variable might change during testing e.g. to argv1_51_128 instead of argv1_0_128
    nose.tools.assert_equal(e.state.context_view.pstr_branch_info(),
                            "IP: 0x40119a <main+0x51 in sym_exec.elf (0x119a)>\tCond: <Bool %s[127:120] == 80>\n\tVars: frozenset({'%s'})\n" % (argv1.args[0], argv1.args[0]),
                            "Branch info not as expected")

    s1, s2 = e.simgr.active
    # Pick wrong branch
    e.do_run("1")

    # One state should be deadended
    nose.tools.assert_equal(len(e.simgr.deadended), 1, "Incorrect number of deadended states")

    # The other state of the last branch should now be the active one
    nose.tools.assert_equal(e.state, s1)

    for _ in range(0, 8):
        e.do_run("0")


    nose.tools.assert_true(b'PASSWORD' in e.simgr.deadended[1].solver.eval(argv1, cast_to=bytes))



if __name__ == "__main__":
    test_proper_termination()
    test_branching()
