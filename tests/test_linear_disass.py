import nose
import angr
import angrcli.plugins.ContextView.context_view


proj = angr.Project("/bin/ls", load_options={'auto_load_libs': False})

def test_linear_disass_valid_code():
    state = proj.factory.entry_state()
    state.context_view.use_only_linear_disasm = True
    state.context_view.pprint()

def test_linear_disass_symbolic_code():
    state = proj.factory.blank_state(addr=0x1337)
    state.context_view.pprint()

if __name__ == "__main__":
    test_linear_disass_symbolic_code()
    test_linear_disass_valid_code()
