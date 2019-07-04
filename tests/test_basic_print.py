import nose
import angr
import angrcli.plugins.ContextView.context_view

proj = angr.Project("/bin/ls", load_options={'auto_load_libs': False})


def test_basic_print():
    state = proj.factory.entry_state()
    state.context_view.pprint()

def test_all():
    test_basic_print()

if __name__ == "__main__":
    test_all()
