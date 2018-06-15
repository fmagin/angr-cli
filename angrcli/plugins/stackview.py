import logging

from angr.state_plugins import SimStatePlugin

l = logging.getLogger('angr.state_plugins.stack_view')


class Stack(SimStatePlugin):
    def __init__(self, state):
        self.state = state

    def __getitem__(self, offset):
        """Returns a tuple of a stack element as (addr, content)"""
        addr = self.state.regs.sp + offset * self.state.arch.bytes
        if self.state.solver.eval(addr >= self.state.arch.initial_sp):
            raise IndexError
        return addr, self.state.memory.load(addr, size=self.state.arch.bytes, endness=self.state.arch.memory_endness)