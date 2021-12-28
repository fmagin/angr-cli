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

    lines = e.state.context_view._pstr_current_codeblock().split('\n')
    r = ['__libc_start_main+0x0 in extern-address space (0x0)',
         'char* unknown@<rdi>: 0x401159 <main+0x0 in simproc_demo.elf (0x1159)>',
         # The following line is volatile and also wrong, because __libc_start_main has no proper prototype in angr defined yet
         # All the arguments default to char*, which is correct enough for all except argc, which is just an int
         'char* unknown@<rsi>: WARN: Symbolic Pointer <BV64 mem_7fffffffffeff5c_4_32{UNINITIALIZED} .. 0x1>',
         "char* unknown@<rdx>: 0x7fffffffffeff60 --> b'\\x98\\xff\\xfe\\xff\\xff\\xff\\xff\\x07'",
         'char* unknown@<rcx>: 0x4011b0 <__libc_csu_init+0x0 in simproc_demo.elf (0x11b0)>',
         'char* unknown@<r8>: 0x401220 <__libc_csu_fini+0x0 in simproc_demo.elf (0x1220)>',
         '<SimProcedure __libc_start_main>']
    assert lines[0] == r[0], "Incorrect location for __libc_start_main"
    assert lines[1] == r[1], "Incorrect main argument for __libc_start_main"
    assert lines[4] == r[4], "Incorrect init argument for __libc_start_main"
    assert lines[5] == r[5], "Incorrect fini argument for __libc_start_main"
    assert lines[6] == r[6], "Incorrect code for __libc_start_main"

    for _ in range(0, 14):
        e.do_step("")

    # Should be at call puts
    lines = e.state.context_view._pstr_current_codeblock().split('\n')
    assert lines[0] == 'puts+0x0 in extern-address space (0x10)', "Incorrect location for puts"
    assert lines[1] == "char* s@<rdi>: 0x402004 <_IO_stdin_used+0x4 in simproc_demo.elf (0x2004)> --> b'SimProc Demo'", "Incorrect arguments rendered for puts"
    assert lines[2] == '<SimProcedure puts>', "Incorrect code for puts"

    for _ in range(0, 3):
        e.do_step("")

    lines = e.state.context_view._pstr_current_codeblock().split('\n')
    assert lines[0] == 'malloc+0x0 in extern-address space (0x18)', "Incorrect location for malloc"
    assert lines[1] == "unsigned long (64 bits) size@<rdi>: 0x100", "Incorrect arguments rendered for malloc"
    assert lines[2] == '<SimProcedure malloc>', "Incorrect code for malloc"

    for _ in range(0, 3):
        e.do_step("")

    lines = e.state.context_view._pstr_current_codeblock().split('\n')
    assert lines[0] == 'strcpy+0x0 in extern-address space (0x8)', "Incorrect location for strcpy"
    assert lines[1] == "char* to@<rdi>: 0xc0000f40 --> UNINITIALIZED", "Incorrect first argument rendered for strcpy"
    assert lines[2] == "char* from@<rsi>: 0x%x --> b'%s'" % (e.state.regs.rsi.args[0], proj.filename), "Incorrect sencond argument rendered for strcpy"
    assert lines[3] == '<SimProcedure strcpy>', "Incorrect code for strcpy"


if __name__ == "__main__":
    test_sims()
