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

    @SimStatePlugin.memo
    def copy(self, memo):
        return Watches(watches=self._watches)

    @property
    def eval(self):
        return [(name, w(self.state)) for name, w in self._watches.items()]





Watches.register_default("watches")