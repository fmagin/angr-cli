import logging

from angr.state_plugins import SimStatePlugin

l = logging.getLogger('angr.state_plugins.context_view')

from pygments import highlight
from pygments.lexers import NasmLexer
from pygments.formatters import TerminalFormatter

MAX_AST_DEPTH = 5


class ContextView(SimStatePlugin):
    def __init__(self):
        super(ContextView, self).__init__()

    def set_state(self, state):
        super(ContextView, self).set_state(state)
        self.stack = Stack(self.state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return ContextView()

    def red(self, text):
        return "\x1b[0;31m" + text + "\x1b[0m"

    def blue(self, text):
        return "\x1b[0;34m" + text + "\x1b[0m"

    def green(self, text):
        return "\x1b[0;32m" + text + "\x1b[0m"

    def yellow(self, text):
        return "\x1b[0;33m" + text + "\x1b[0m"

    def magenta(self, text):
        return "\x1b[0;35m" + text + "\x1b[0m"

    def underline(self, text):
        return "\x1b[4m" + text + "\x1b[0m"

    def grey(self, text):
        return "\x1b[40;90;32m" + text + "\x1b[0m"

    def BVtoREG(self, bv):
        if type(bv) == str:
            return bv
        if "reg" in str(bv):
            args = list()
            for v in self.state.se.describe_variables(bv):
                if "reg" in v:
                    ridx = v[1]
                    regname = self.state.arch.register_names[ridx]
            replname = str(bv).replace("reg_" + hex(ridx)[2:], regname)
            return replname
        return str(bv)

    def print_legend(self):
        s = "LEGEND: "
        s += self.green("SYMBOLIC")
        s += " | " + self.grey("UNINITIALIZED")
        s += " | " + self.yellow("STACK")
        s += " | " + self.blue("HEAP")
        s += " | " + self.red("CODE")
        s += " | " + self.magenta("DATA")
        s += " | " + self.underline("RWX")
        s += " | RODATA"
        print(s)

    def cc(self, bv):
        """Takes a BV and returns a colored string"""
        if bv.symbolic:
            if bv.uninitialized:
                return self.grey(self.BVtoREG(bv))
            return self.green(self.BVtoREG(bv))
        # its concrete
        value = self.state.se.eval(bv)
        if self.state.project.loader.find_object_containing(value):
            descr = " <%s>" % self.state.project.loader.describe_addr(value)
            return self.red(hex(value) + descr)
        if value >= self.state.se.eval(self.state.regs.sp) and value < self.state.arch.initial_sp:
            return self.yellow(hex(value))
        return hex(value)

    def pprint(self):
        """Pretty context view similiar to the context view of gdb plugins (peda and pwndbg)"""
        self.print_legend()
        self.state.context_view.registers()
        self.state.context_view.code()
        self.state.context_view.fds()
        self.state.context_view.print_stack()
        self.state.context_view.backtrace()

    def backtrace(self):
        print(self.blue("[-------------------------------------backtrace--------------------------------]"))
        print("Backtrace:\n%s" % "\n".join(
            "Frame %d: %#x => %#x, sp = %#x" % (i, f.call_site_addr, f.func_addr, f.stack_ptr) for i, f in
            enumerate(self.state.callstack)))

    def __get_prev_block(self):
        """Find the previously block in terms of what a human would expect (e.g. if the last state was a SimProc
        I don't know a better way to do this...
        Iterates over the last executed basic blocks and tries to find the first one
        that isn't in the extern_object and is thus not a SimProc
        """
        for idx in range(-1, -20, -1):
            try:
                addr = self.state.history.bbl_addrs[idx]
                if self.state.project.loader.find_object_containing(addr) != self.state.project.loader.extern_object:
                    return addr
            except IndexError:
                break

    def code(self):
        print(self.blue("[-------------------------------------code-------------------------------------]"))
        try:
            self.__pprint_codeblock(self.__get_prev_block())
            print("\t|\t" + self.cc(self.state.solver.simplify(self.state.history.jump_guard)) + "\n\tv")
        except:
            pass
        self.__pprint_codeblock(self.state.solver.eval(self.state.regs.ip))

    def print_codeblock(self, ip):
        self.__pprint_codeblock(ip)

    def __pprint_codeblock(self, ip):
        # Check if we are currently in the extern object in which case printing disassembly is pointless
        o = self.state.project.loader.find_object_containing(ip)
        if o == self.state.project.loader.extern_object:
            print self.state.project._sim_procedures[ip]
            return
        try:
            f = self.state.project.kb.functions.floor_func(ip)
            print(f.name + "+" + hex(ip - f.addr))
        except:
            pass
        try:
            code = self.state.project.factory.block(ip).capstone.__str__()
            highlighed_code = highlight(code, NasmLexer(), TerminalFormatter())
            print "\n".join(highlighed_code.split('\n')[:20]) #HACK: limit printed lines to 20
        except:
            self.red("No code at current ip. Please specify self_modifying code ")

    def fds(self):
        if ["", "", ""] == [self.state.posix.dumps(x) for x in self.state.posix.fd]:
            return
        print(self.blue("[-------------------------------filedescriptors--------------------------------]"))
        for fd in self.state.posix.fd:
            print "fd " + str(fd), ":", repr(self.state.posix.dumps(fd))

    def print_stack(self):
        stackdepth = 8
        print(self.blue("[------------------------------------stack-------------------------------------]"))
        # Not sure if that can happen, but if it does things will break
        if not self.state.regs.sp.concrete:
            print "STACK POINTER IS SYMBOLIC: " + str(self.state.regs.sp)
            return
        for o in range(stackdepth):
            self.__pprint_stack_element(o)

    def __pprint_stack_element(self, offset):
        """Print stack element in the form IDX:OFFSET|      ADDRESS --> CONTENT"""
        l = "%s:" % ("{0:#02d}".format(offset))
        l += "%s| " % ("{0:#04x}".format(offset * self.state.arch.bytes))
        try:
            stackaddr, stackval = self.stack[offset]
        except IndexError:
            return

        if self.state.se.eval(stackaddr) == self.state.se.eval(self.state.regs.sp, cast_to=int):
            l += "sp"
        elif self.state.se.eval(stackaddr) == self.state.se.eval(self.state.regs.bp, cast_to=int):
            l += "bp"
        else:
            l += "  "
        l += " "

        l += "%s " % self.cc(stackaddr)
        l += " --> %s" % self.pstr_ast(stackval)
        print l

    def registers(self):
        """
        Visualise the register state
        """
        print(self.blue("[----------------------------------registers-----------------------------------]"))
        for reg in self.default_registers():
            register_number = self.state.arch.registers[reg][0]
            self.__pprint_register(reg, self.state.registers.load(register_number))

    def __pprint_register(self, reg, value):
        repr = reg.upper() + ":\t"
        repr += self.pstr_ast(value)
        print(repr)

    def describe_addr(self, addr):
        return self.__deref_addr(addr)

    def __deref_addr(self, addr, depth=0):
        o = self.state.project.loader.find_object_containing(addr)
        if o:
            return ""
        else:
            deref = self.state.mem[addr].uintptr_t.resolved
            if deref.concrete or not deref.uninitialized:
                value = self.state.solver.eval(deref)
                if not value == addr:
                    return " --> %s" % self.pstr_ast(deref)

    def pstr_ast(self, ast):
        """Return a pretty string for an AST including a description of the derefed value if it makes sense (i.e. if
        the ast is concrete and the derefed value is not uninitialized"""
        if ast.concrete:
            value = self.state.solver.eval(ast)
            if ast.op =='BVV' and self.__deref_addr(value):
                return self.cc(ast) + self.__deref_addr(value)
            else:
                return self.cc(ast)
        else:
            if ast.depth > MAX_AST_DEPTH:
                # AST is probably too large to render
                return self.green("<AST: Depth: %d Vars: %s Hash: %x>" % (ast.depth, ast.variables, ast.__hash__()))
            return self.cc(ast)

    def default_registers(self):
        custom = {
            'X86': ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip'],
            'AMD64': ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12',
                      'r13', 'r14', 'r15']

        }
        if self.state.arch.name in custom:
            return custom[self.state.arch.name]
        else:
            l.warn("No custom register list implemented, using fallback")
            return self.state.arch.default_symbolic_registers \
                   + [self.state.arch.register_names[self.state.arch.ip_offset]] \
                   + [self.state.arch.register_names[self.state.arch.sp_offset]] \
                   + [self.state.arch.register_names[self.state.arch.bp_offset]]

    def pstr_branch_info(self, idx=None):
        """Return the information about the state concerning the last branch as a pretty string"""
        str_ip = self.pstr_ast(self.state.regs.ip)
        simplified_jump_guard = self.state.solver.simplify(self.state.history.jump_guard)
        str_jump_guard = self.pstr_ast(simplified_jump_guard)
        vars = self.state.history.jump_guard.variables

        return "%sIP: %s\tCond: %s\n\tVars: %s\n" % \
               (str(idx) + ":\t" if type(idx) is int else "", str_ip, str_jump_guard, vars)


class Stack():
    def __init__(self, state):
        self.state = state

    def __getitem__(self, offset):
        """Returns a tuple of a stack element as (addr, content)"""
        addr = self.state.regs.sp + offset * self.state.arch.bytes
        if self.state.solver.eval(addr >= self.state.arch.initial_sp):
            raise IndexError
        return addr, self.state.memory.load(addr, size=self.state.arch.bytes, endness=self.state.arch.memory_endness)



ContextView.register_default("context_view")
