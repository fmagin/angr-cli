import logging

from angr.state_plugins import SimStatePlugin

l = logging.getLogger('angr.state_plugins.stack_view')


class Stack(SimStatePlugin):

    def __init__(self):
        super(Stack, self).__init__()

    def set_state(self, state):
        super(Stack, self).set_state(state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return Stack()


    def element_count(self):
        return self.state.solver.eval( (self.state.arch.initial_sp - self.state.regs.sp) / self.state.arch.bytes)

    def __repr__(self):
        sp = self.state.solver.eval(self.state.regs.sp)
        return "<Stack Start: 0x%x Top: 0x%x Elements: %d>" % (self.state.arch.initial_sp, sp, self.element_count())

    def __getitem__(self, offset):
        """Returns a tuple of a stack element as (addr, content)"""
        addr = self.state.regs.sp + offset * self.state.arch.bytes
        if self.state.solver.eval(addr >= self.state.arch.initial_sp):
            raise IndexError("Stack only has %d elements" % self.element_count())
        return addr, self.state.memory.load(addr, size=self.state.arch.bytes, endness=self.state.arch.memory_endness)


Stack.register_default('stack')