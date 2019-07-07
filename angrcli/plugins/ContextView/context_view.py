from angr import SimEngineError
from angr.sim_type import *




import angr # type annotations; pylint: disable=unused-import
from typing import Optional, Tuple

from angrcli.plugins.ContextView.disassemblers import AngrCapstoneDisassembler
from .colors import Color


from angr.storage.paged_memory import BasePage
from angr.state_plugins import SimStatePlugin

l = logging.getLogger('angr.state_plugins.context_view')

from pygments import highlight
from pygments.lexers import NasmLexer
from pygments.formatters import TerminalFormatter

MAX_AST_DEPTH = 5



class ContextView(SimStatePlugin):
    # Class variable to specify disassembler
    _disassembler = AngrCapstoneDisassembler()
    def __init__(self, use_only_linear_disasm=False, disable_linear_disasm_fallback=True):
        self.state = None  # type: angr.SimState
        super(ContextView, self).__init__()
        self.use_only_linear_disasm = use_only_linear_disasm
        self.disable_linear_disasm_fallback = disable_linear_disasm_fallback

    def set_state(self, state):
        super(ContextView, self).set_state(state)
        self.stack = Stack(self.state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return ContextView(self.use_only_linear_disasm, self.disable_linear_disasm_fallback)

    def BVtoREG(self, bv):
        """

        :param claripy.ast.BV bv:
        :return: str
        """
        if type(bv) == str:
            return bv
        if "reg" in str(bv):
            replname = str(bv)
            for v in self.state.solver.describe_variables(bv):
                if "reg" in v:
                    ridx = v[1]
                    regname = self.state.arch.register_names[ridx]
                    replname = replname.replace("reg_" + hex(ridx)[2:], regname)
            return replname
        return str(bv)

    def print_legend(self):
        s = "LEGEND: "
        s += Color.greenify("SYMBOLIC")
        s += " | " + Color.grayify("UNINITIALIZED")
        s += " | " + Color.yellowify("STACK")
        s += " | " + Color.blueify("HEAP")
        s += " | " + Color.redify("CODE R-X")
        s += " | " + Color.pinkify("DATA R*-")
        s += " | " + Color.underlinify("RWX")
        s += " | RODATA"
        print(s)


    def pprint(self):
        """Pretty context view similiar to the context view of gdb plugins (peda and pwndbg)"""
        headerWatch =       "[ ──────────────────────────────────────────────────────────────────── Watches ── ]"
        headerBacktrace =   "[ ────────────────────────────────────────────────────────────────── BackTrace ── ]"
        headerCode =        "[ ─────────────────────────────────────────────────────────────────────── Code ── ]"
        headerFDs =         "[ ──────────────────────────────────────────────────────────── FileDescriptors ── ]"
        headerStack =       "[ ────────────────────────────────────────────────────────────────────── Stack ── ]"
        headerRegs =        "[ ────────────────────────────────────────────────────────────────── Registers ── ]"

        # Disable the warnings about accessing uninitialized memory/registers so they don't break printing
        self.state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        self.state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        self.print_legend()

        print(Color.blueify(headerRegs))
        self.state.context_view.print_registers_pane()

        print(Color.blueify(headerCode))
        self.state.context_view.print_code_pane()


        if [b"", b"", b""] != [self.state.posix.dumps(x) for x in self.state.posix.fd]:
            print(Color.blueify(headerFDs))
            self.state.context_view.print_fds_pane()

        print(Color.blueify(headerStack))
        self.state.context_view.print_stack_pane()

        print(Color.blueify(headerBacktrace))
        self.state.context_view.print_backtrace_pane()


        try:
            self.state.watches
        except AttributeError:
            l.warning("No watches plugin loaded, unable to print watches")
        else:
            print(Color.blueify(headerWatch))
            self.state.context_view.print_watches_pane()


        # Reenable the warnings about accessing uninitialized memory/registers so they don't break printing
        self.state.options.remove(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        self.state.options.remove(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

        # This is a hack to allow this method to be monkey patched as the __repr__ method of a state
        return ""

    def print_registers_pane(self):
        """
        Visualise the register state
        """
        for reg in self.default_registers():
            register_number = self.state.arch.registers[reg][0]
            print(self.__pstr_register(reg, self.state.registers.load(register_number, inspect=False, disable_actions=True)))

    def print_code_pane(self):
        if not self.use_only_linear_disasm:
            try:
                self.__print_previous_codeblock()
                print("\t|\t" + self.cc(self.state.solver.simplify(self.state.history.jump_guard)) + "\n\tv")
            except:
                pass
        self.__print_current_codeblock()

    def print_fds_pane(self):
        for fd in self.state.posix.fd:
            print("fd " + str(fd), ":", repr(self.state.posix.dumps(fd)))

    def print_stack_pane(self):
        stackdepth = 8
        # Not sure if that can happen, but if it does things will break
        if not self.state.regs.sp.concrete:
            print("STACK POINTER IS SYMBOLIC: " + str(self.state.regs.sp))
            return
        for o in range(stackdepth):
            self.__pprint_stack_element(o)

    def print_backtrace_pane(self):
        print("\n".join(self.__pstr_backtrace()))

    def print_watches_pane(self):
        try:
            self.state.watches
        except AttributeError:
            l.warning("Tried accessing watches plugin, but the state doesn't have this registered")
            return
        for name, w in self.state.watches.eval:
                print("%s:\t%s" % (name, w))
        return None


    def __cc(self, bv):
        """

        :param claripy.ast.BV bv:
        :return Tuple[str, bool]:
        """
        if bv.symbolic:
            if bv.uninitialized:
                return Color.grayify(self.BVtoREG(bv)), False
            return Color.greenify(self.BVtoREG(bv)), False
        # its concrete
        value = self.state.solver.eval(bv, cast_to=int)
        
        if self.state.solver.eval(self.state.regs.sp) <= value < self.state.arch.initial_sp:
            return Color.yellowify(hex(value)), False
        if self.state.heap.heap_base <= value <= self.state.heap.heap_location:
            return Color.blueify(hex(value)), False
        
        try:
            perm = self.state.memory.permissions(value)
            if not perm.symbolic:
                perm = self.state.solver.eval(perm, cast_to=int)
                if perm:
                    if perm & BasePage.PROT_EXEC:
                        descr = " <%s>" % self.state.project.loader.describe_addr(value)
                        if descr == 'not part of a loaded object':
                            return Color.redify(hex(value)), True
                        return Color.redify(hex(value) + descr), True
                    else:
                        descr = " <%s>" % self.state.project.loader.describe_addr(value)
                        if descr == 'not part of a loaded object':
                            return Color.pinkify(hex(value)), False
                        return Color.pinkify(hex(value) + descr), False
        except:
            pass

        return hex(value), False

    def cc(self, bv):
        """

        :param claripy.ast.BV bv:
        :return str:
        """
        return self.__cc(bv)[0]

    def __pstr_backtrace(self) -> str:
        """
        Generates the backtrace of stackframes.
        Example:
            Frame 0: PLT.rand+0x401 in morph (0xb99) => 0xc0080176, sp = 0x7fffffffffefed8
            Frame 1: __libc_start_main.after_init+0x0 in extern-address space (0x98) => PLT.rand+0x2de in morph (0xa76), sp = 0x7fffffffffeff18
            Frame 2: PLT.rand+0x8 in morph (0x7a0) => __libc_start_main+0x0 in extern-address space (0x18), sp = 0x7fffffffffeff28
            Frame 3: 0x0 => 0x0, sp = 0xffffffffffffffff

        :return str:
        """
        result = []
        for i, f in enumerate(self.state.callstack):
            if self.state.project.loader.find_object_containing(f.call_site_addr):
                call_site_addr = self.state.project.loader.describe_addr(f.call_site_addr)
            else:
                call_site_addr = "%#x" % f.call_site_addr
            if self.state.project.loader.find_object_containing(f.func_addr):
                func_addr = self.state.project.loader.describe_addr(f.func_addr)
            else:
                func_addr = "%#x" % f.func_addr

            frame = "Frame %d: %s => %s, sp = %#x" % (i, call_site_addr, func_addr, f.stack_ptr)

            result.append(frame)
        return result


    def __print_previous_codeblock(self):
        prev_ip = self.state.history.bbl_addrs[-1]

        # Print the location (like main+0x10) if possible
        descr = self.state.project.loader.describe_addr(prev_ip)
        if descr != 'not part of a loaded object':
            print(descr)

        if not self.state.project.is_hooked(prev_ip):
            code = self.__pstr_codeblock(prev_ip)
            if code == None:
                if self.disable_linear_disasm_fallback:
                    code = Color.redify("No code at current ip. Please specify self_modifying code ")
                else:
                    raise Exception() # skip print of previous
            code = code.split("\n")
            
            # if it is longer than MAX_DISASS_LENGTH, only print the first lines
            if len(code) >= self._disassembler.MAX_DISASS_LENGHT:
                print("TRUNCATED BASIC BLOCK")
                print("\n".join(code[-self._disassembler.MAX_DISASS_LENGHT:]))
            else:
                print("\n".join(code))
            return
        else:
            hook = self.state.project.hooked_by(prev_ip)
            print(hook)



    def __print_current_codeblock(self) -> None:
        print(self.__pstr_current_codeblock())

    def __pstr_current_codeblock(self) -> str:

        result = []
        current_ip = self.state.solver.eval(self.state.regs.ip)


        # Print the location (like main+0x10) if possible
        descr = self.state.project.loader.describe_addr(current_ip)
        if descr != 'not part of a loaded object':
            result.append(descr)


        # Check if we are at the start of a known function to maybe pretty print the arguments
        try:
            function = self.state.project.kb.functions[current_ip]
        except KeyError:
            pass
        else:
            if function.calling_convention:
                result.extend(self.pstr_call_info(self.state, function))


        # Get the current code block about to be executed as pretty disassembly
        if not self.state.project.is_hooked(current_ip):
            if self.use_only_linear_disasm:
                code = self.__pstr_codelinear(current_ip)
            else:
                code = self.__pstr_codeblock(current_ip)
                if code == None:
                    if self.disable_linear_disasm_fallback:
                        code = Color.redify("No code at current ip. Please specify self_modifying code ")
                    else:
                        code = self.__pstr_codelinear(current_ip) # do fallback to Capstone
            code = code.split("\n")
            
            # if it is longer than MAX_DISASS_LENGTH, only print the first lines
            if len(code) >= self._disassembler.MAX_DISASS_LENGHT:
                result.extend(code[:self._disassembler.MAX_DISASS_LENGHT])
                result.append("TRUNCATED BASIC BLOCK")
            else:
                result.extend(code)
        else:
            hook = self.state.project.hooked_by(current_ip)
            result.append(str(hook))

        return "\n".join(result)

    def __pstr_codeblock(self, ip) -> Optional[str]:
        """Get the pretty version of a basic block with Pygemnts
        :param int ip:
        :return:

        """
        try:
            block = self.state.project.factory.block(ip, backup_state=self.state)
            code = self._disassembler.block_disass(block, self)
            if not Color.disable_colors:
                return highlight(code, NasmLexer(), TerminalFormatter())
            else:
                return code
        except SimEngineError as e:
            l.info("Got exception %s, returning None" % e)
            return None

    def __pstr_codelinear(self, ip) -> str:
        """Get the pretty version of linear disasm with Pygemnts"""
        code = self._disassembler.linear_disass(ip, self)
        if not Color.disable_colors:
            return highlight(code, NasmLexer(), TerminalFormatter())
        else:
            return code



    def __pprint_stack_element(self, offset):
        """print(stack element in the form IDX:OFFSET|      ADDRESS ──> CONTENT"""
        l = "%s:" % ("{0:#02d}".format(offset))
        l += "%s| " % ("{0:#04x}".format(offset * self.state.arch.bytes))
        try:
            stackaddr, stackval = self.stack[offset]
        except IndexError:
            return

        if self.state.solver.eval(stackaddr) == self.state.solver.eval(self.state.regs.sp, cast_to=int):
            l += "sp"
        elif self.state.solver.eval(stackaddr) == self.state.solver.eval(self.state.regs.bp, cast_to=int):
            l += "bp"
        else:
            l += "  "
        l += " "

        l += "%s " % self.cc(stackaddr)
        l += " ──> %s" % self.pstr_ast(stackval)
        print(l)


    def __pstr_register(self, reg, value):

        repr = reg.upper() + ":\t"
        repr += self.pstr_ast(value)
        return repr

    def describe_addr(self, addr):
        return self.__deref_addr(addr)

    def __deref_addr(self, addr, depth=0):
        if addr in self.state.memory:
            deref = self.state.memory.load(addr, 1, inspect=False, disable_actions=True)
            if deref.op == 'Extract':
                deref = deref.args[2]
            else:
                deref = self.state.mem[addr].uintptr_t.resolved
            if deref.concrete or not deref.uninitialized:
                value = self.state.solver.eval(deref)
                if not value == addr and not value == 0 and depth < MAX_AST_DEPTH:
                    return " ──> %s" % self.pstr_ast(deref, depth=depth+1)
        return ""

    def pstr_ast(self, ast, ty=None, depth=0):
        """Return a pretty string for an AST including a description of the derefed value if it makes sense (i.e. if
        the ast is concrete and the derefed value is not uninitialized
        More complex rendering is possible if type information is supplied
        """
        if isinstance(ty, SimTypePointer):
            if ast.concrete:
                cc_ast, ast_is_code_ptr = self.__cc(ast)
                if ast_is_code_ptr:
                    return cc_ast
                try:
                    tmp = "%s ──> %s" % (cc_ast, repr(self.state.mem[ast].string.concrete))
                except ValueError:
                    deref = self.state.memory.load(ast, 1, inspect=False, disable_actions=True)
                    if deref.op == 'Extract':
                        return "%s ──> %s" % (cc_ast, self.cc(deref.args[2]))
                    elif deref.uninitialized:
                        return "%s ──> UNINITIALIZED" % (cc_ast)
                    else:
                        return "%s ──> COMPLEX SYMBOLIC STRING" % (cc_ast)
                else:
                    return tmp
            else:
                return "%s %s" % (Color.redify("WARN: Symbolic Pointer"), self.cc(ast))

        if ast.concrete:
            value = self.state.solver.eval(ast)
            cc_ast, ast_is_code_ptr = self.__cc(ast)
            if not ast_is_code_ptr and ast.op =='BVV' and self.__deref_addr(value, depth+1):
                return cc_ast + self.__deref_addr(value, depth+1)
            else:
                return cc_ast
        else:
            if ast.depth > MAX_AST_DEPTH:
                # AST is probably too large to render
                return Color.greenify("<AST: Depth: %d Vars: %s Hash: %x>" % (ast.depth, ast.variables, ast.__hash__()))
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


    def pstr_call_info(self, state, function):
        """

        :param angr.SimState state:
        :param angr.knowledge_plugins.functions.Function function:
        :return:
        """
        return [ self.pstr_call_argument(*arg) for arg in function.calling_convention.get_arg_info(state)]

    def pstr_call_argument(self, ty, name, location, value):
        """
        The input should ideally be the unpacked tuple from one of the list entries of calling_convention.get_arg_info(state)
        :param angr.sim_type.SimType ty:
        :param str name:
        :param angr.calling_conventions.SimFunctionArgument location:
        :param claripy.ast.BV value:
        :return:
        """
        return "%s %s@%s: %s" %( ty, name, location, self.pstr_ast(value, ty=ty))


class Stack():
    def __init__(self, state):
        self.state = state # type: angr.SimState

    def __getitem__(self, offset):
        """Returns a tuple of a stack element as (addr, content)"""
        addr = self.state.regs.sp + offset * self.state.arch.bytes
        if self.state.solver.eval(addr >= self.state.arch.initial_sp):
            raise IndexError
        return addr, self.state.memory.load(addr, size=self.state.arch.bytes, endness=self.state.arch.memory_endness, inspect=False, disable_actions=True)




ContextView.register_default("context_view")
