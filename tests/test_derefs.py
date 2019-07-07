import nose
import angr
import angrcli.plugins.ContextView.context_view
from angrcli.plugins.ContextView.colors import Color
proj = angr.Project("/bin/ls", load_options={'auto_load_libs': False})



Color.disable_colors = True






def test_max_depth():
    state = proj.factory.blank_state()
    state.regs.rax = 0x2000
    state.mem[0x2000].uintptr_t = 0x3000
    state.mem[0x3000].uintptr_t = 0x4000
    state.mem[0x4000].uintptr_t = 0x5000
    state.mem[0x5000].uintptr_t = 0x6000
    state.mem[0x6000].uintptr_t = 0x7000
    state.mem[0x7000].uintptr_t = 0x8000
    state.mem[0x8000].uintptr_t = 0xa000
    nose.tools.assert_equal(state.context_view._pstr_register("RAX", state.regs.rax),
                            'RAX:\t0x2000 ──> 0x3000 ──> 0x4000 ──> 0x5000 ──> 0x6000 ──> 0x7000 ──> <BV64 0x8000>')


def test_loop():
    state = proj.factory.blank_state()
    state.regs.rax = 0x1337
    state.mem[0x1337].uintptr_t = 0x4242
    state.mem[0x4242].uintptr_t = 0x1337
    nose.tools.assert_equal(
    state.context_view._pstr_register("RAX", state.regs.rax),
    'RAX:\t0x1337 ──> 0x4242 ──> 0x1337 ──> 0x4242 ──> 0x1337 ──> 0x4242 ──> <BV64 0x1337>'
    )

def test_cc():

    state = proj.factory.blank_state()
    state.regs.rax = 0x2000
    colored_ast = state.context_view._color_code_ast(state.regs.rax)[0]
    nose.tools.assert_equal(colored_ast, '0x2000')




if __name__ == "__main__":
    test_max_depth()
    test_loop()
    test_cc()
