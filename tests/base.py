import angr
import angrcli.plugins.ContextView


proj = angr.Project("/bin/ls", load_options={'auto_load_libs': False})

state = proj.factory.entry_state()
