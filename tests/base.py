import angr
import angrcli.plugins.ContextView
from angrcli.interaction.explore import ExploreInteractive
import os
location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "sym_exec.elf")

proj = angr.Project(location, load_options={'auto_load_libs': False})

state = proj.factory.entry_state()
e = ExploreInteractive(proj,state)
