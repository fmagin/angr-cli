import angr
import angrcli.plugins.ContextView

from angrcli.plugins.ContextView.colors import Color

from angrcli.interaction.explore import ExploreInteractive

Color.disable_colors = True
import os

location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "sym_exec.elf")

proj = angr.Project(location, load_options={'auto_load_libs': False})


def test_linear_disass_valid_code():
    state = proj.factory.entry_state()
    assert "--> 0x401050:	endbr64	" in state.context_view._pstr_current_codeblock(
        linear_code=True), "'--> 0x401050:	endbr64	' not in code"


def test_linear_disass_symbolic_code():
    state = proj.factory.blank_state(addr=0x1337)
    assert state.context_view._pstr_current_codeblock(linear_code=True) == "Instructions are symbolic!"


def test_entry_print():
    state = proj.factory.entry_state()
    state.context_view: angrcli.plugins.ContextView.context_view.ContextView
    assert state.context_view._pstr_current_codeblock().split("\n")[1] == "0x401050:	endbr64\t", "First code line not as expected"
    assert state.context_view._pstr_current_codeblock() == state.context_view._pstr_code(), "Code pane must be equal to current codeblock on entry state"


def test_interactive():
    state = proj.factory.entry_state()
    e = ExploreInteractive(proj, state)


if __name__ == "__main__":
    test_linear_disass_symbolic_code()
    test_linear_disass_valid_code()
