from angr import SimStatePlugin


class Watches(SimStatePlugin):
    def __init__(self, watches={}):
        """
        :param watches: a list of lambdas that map a state to some AST to evaluate an arbitrary expression inside the state and keep track in the view
        """
        super(Watches, self).__init__()
        self._watches = watches

    def set_state(self, state):
        super(Watches, self).set_state(state)

    def add_watch(self, watch, name):
        self._watches[name] = watch

    def watch_bv(self, bv, cast_to=None):
        w = lambda state: state.solver.eval(bv, cast_to=cast_to)
        self.add_watch(w, bv.args[0].split('_')[0])
        return w

    def __getitem__(self, key):
        return self._watches[key](self.state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return Watches(watches=self._watches)

    @property
    def eval(self):
        results = []
        for name, watch in self._watches.items():
            try:
                results.append((name, watch(self.state)))
            except Exception as e:
                results.append((name, e))
        return results





Watches.register_default("watches")