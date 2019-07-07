import nose
import os
import angr
import claripy
import angrcli.plugins.ContextView.context_view
from angrcli.interaction.explore import ExploreInteractive

from angrcli.plugins.ContextView.colors import Color

Color.disable_colors = True
location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "simproc_demo.elf")

proj = angr.Project(location, load_options={'auto_load_libs': False})

cfg = proj.analyses.CFGFast()

state = proj.factory.entry_state()
e = ExploreInteractive(proj, state)

def test_sims():
    e.do_step("")

    lines = e.state.context_view._ContextView__pstr_current_codeblock().split('\n')
    nose.tools.assert_equal(lines[0], '__libc_start_main+0x0 in extern-address space (0x0)', "Incorrect location for __libc_start_main")
    nose.tools.assert_equal(lines[1], '<SimProcedure __libc_start_main>', "Incorrect code for __libc_start_main")

    for _ in range(0,14):
        e.do_step("")

    # Should be at call puts
    lines = e.state.context_view._ContextView__pstr_current_codeblock().split('\n')
    nose.tools.assert_equal(lines[0], 'puts+0x0 in extern-address space (0x10)', "Incorrect location for puts")
    nose.tools.assert_equal(lines[1], "char* string@<rdi>: 0x402004 <_IO_stdin_used+0x4 in simproc_demo.elf (0x2004)> ──> b'SimProc Demo'", "Incorrect arguments rendered for puts")
    nose.tools.assert_equal(lines[2], '<SimProcedure puts>', "Incorrect code for puts")

    for _ in range(0,3):
        e.do_step("")

    lines = e.state.context_view._ContextView__pstr_current_codeblock().split('\n')
    nose.tools.assert_equal(lines[0], 'malloc+0x0 in extern-address space (0x18)', "Incorrect location for malloc")
    nose.tools.assert_equal(lines[1], "unsigned long (64 bits) sim_size@<rdi>: 0x100", "Incorrect arguments rendered for malloc")
    nose.tools.assert_equal(lines[2], '<SimProcedure malloc>', "Incorrect code for malloc")

    for _ in range(0,3):
        e.do_step("")

    lines = e.state.context_view._ContextView__pstr_current_codeblock().split('\n')
    nose.tools.assert_equal(lines[0], 'strcpy+0x0 in extern-address space (0x8)', "Incorrect location for strcpy")
    nose.tools.assert_equal(lines[1], "char* dst@<rdi>: 0xc0000f20 ──> UNINITIALIZED", "Incorrect first argument rendered for strcpy")
    nose.tools.assert_equal(lines[2], "char* src@<rsi>: 0x7fffffffffeff98 ──> b'%s'" % proj.filename, "Incorrect sencond argument rendered for strcpy")
    nose.tools.assert_equal(lines[3], '<SimProcedure strcpy>', "Incorrect code for strcpy")


if __name__ == "__main__":
    test_sims()
