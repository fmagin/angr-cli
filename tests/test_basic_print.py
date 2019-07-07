import nose
import angr
import angrcli.plugins.ContextView.context_view

proj = angr.Project("/bin/ls", load_options={'auto_load_libs': False})


def test_basic_print():
    state = proj.factory.entry_state()
    state.context_view.pprint()

if __name__ == "__main__":
    test_basic_print()
