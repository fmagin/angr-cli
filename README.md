# angr CLI






## State View Plugin


```python
import angr
import angrcli.plugins.context_view
proj = angr.Project("/bin/ls", load_options={"auto_load_libs":False})
state = proj.factory.entry_state()
state.context_view.pprint()
```

## Interactive explore example


```python
import angr
import angrcli.plugins.context_view
from angrcli.interaction.explore import ExploreInteractive
proj = angr.Project("/bin/ls", load_options={"auto_load_libs":False})
state = proj.factory.entry_state()
e = ExploreInteractive(proj, state)
e.cmdloop()
```