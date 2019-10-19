from typing import Callable, Any, Dict, List, Optional

from angr import SimStatePlugin, SimState
from claripy.ast.bv import BV

Watch = Callable[[SimState], Any]

class Watches(SimStatePlugin):
    def __init__(self, watches: Dict[str, Watch]={}):
        """
        :param watches: a list of lambdas that map a state to some AST to evaluate an arbitrary expression inside the state and keep track in the view
        """
        super(Watches, self).__init__()
        self._watches = watches

    def set_state(self, state: SimState) -> None:
        super(Watches, self).set_state(state)

    def add_watch(self, watch: Watch, name: str) -> None:
        self._watches[name] = watch

    def watch_bv(self, bv: BV, cast_to: Optional[Any] =None) -> Watch:
        w: Watch = lambda state: state.solver.eval(bv, cast_to=cast_to)
        self.add_watch(w, bv.args[0].split('_')[0])
        return w

    def __getitem__(self, key: str) -> Any:
        return self._watches[key](self.state)

    @SimStatePlugin.memo
    def copy(self, memo: object) -> 'Watches':
        return Watches(watches=self._watches)

    @property
    def eval(self) -> List[Any]:
        results = []
        for name, watch in self._watches.items():
            try:
                results.append((name, watch(self.state)))
            except Exception as e:
                results.append((name, e))
        return results





Watches.register_default("watches")