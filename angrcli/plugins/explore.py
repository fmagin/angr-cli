from typing import Optional, Any

from angr import SimStatePlugin, SimState
from angrcli.interaction.explore import ExploreInteractive


class ExplorePlugin(SimStatePlugin):

    def __init__(
        self,
        explorer: Optional[ExploreInteractive] = None,
    ):
        super(ExplorePlugin, self).__init__()
        self._explorer = explorer

    def set_state(self, state: SimState) -> None:
        super(ExplorePlugin, self).set_state(state)

    @SimStatePlugin.memo
    def copy(self, memo: Any) -> "ExplorePlugin":
        return ExplorePlugin(self._explorer)

    def __call__(self):
        self._explorer = ExploreInteractive(self.state.project, self.state)
        self._explorer.cmdloop()
        return self._explorer.simgr


ExplorePlugin.register_default("explore")