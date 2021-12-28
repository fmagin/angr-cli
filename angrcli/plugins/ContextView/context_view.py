from angr import SimEngineError, SimProcedure, SimState
from angr.knowledge_plugins import Function
from angr.sim_type import *

import angr  # type annotations; pylint: disable=unused-import
import claripy
from claripy.ast.bv import BV
from angr.calling_conventions import SimCC, SimFunctionArgument
from typing import Optional, Tuple, Any, cast, List, Union, Dict

from angrcli.plugins.ContextView.disassemblers import (
    AngrCapstoneDisassembler,
    DisassemblerInterface,
)
from archinfo import RegisterName
from .colors import Color, ColoredString

from angr.state_plugins import SimStatePlugin, SimSolver

l = logging.getLogger("angr.state_plugins.context_view")

from pygments import highlight  # type: ignore
from pygments.lexers.asm import NasmLexer  # type: ignore
from pygments.formatters.terminal import TerminalFormatter  # type: ignore

MAX_AST_DEPTH = 5

PrettyString = Union[str, ColoredString]

class ContextView(SimStatePlugin):
    # Class variable to specify disassembler
    _disassembler = AngrCapstoneDisassembler()  # type: DisassemblerInterface

    def __init__(
        self,
        use_only_linear_disasm: bool = False,
        disable_linear_disasm_fallback: bool = True,
    ):
        super(ContextView, self).__init__()
        self.use_only_linear_disasm = use_only_linear_disasm
        self.disable_linear_disasm_fallback = disable_linear_disasm_fallback

    def set_state(self, state: SimState) -> None:
        super(ContextView, self).set_state(state)
        self.stack = Stack(self.state)

    @SimStatePlugin.memo
    def copy(self, memo: Any) -> "ContextView":
        return ContextView(
            self.use_only_linear_disasm, self.disable_linear_disasm_fallback
        )

    def print_legend(self) -> None:
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

    def pprint(self, linear_code: bool = False) -> str:
        """
        Pretty print an entire state
        :param bool linear_code:
        :return str: Should always be the empty string to allow monkey patching as __repr__ method
        """
        """Pretty context view similiar to the context view of gdb plugins (peda and pwndbg)"""
        headerWatch = "[ ──────────────────────────────────────────────────────────────────── Watches ── ]"
        headerBacktrace = "[ ────────────────────────────────────────────────────────────────── BackTrace ── ]"
        headerCode = "[ ─────────────────────────────────────────────────────────────────────── Code ── ]"
        headerFDs = "[ ──────────────────────────────────────────────────────────── FileDescriptors ── ]"
        headerStack = "[ ────────────────────────────────────────────────────────────────────── Stack ── ]"
        headerRegs = "[ ────────────────────────────────────────────────────────────────── Registers ── ]"

        # Disable the warnings about accessing uninitialized memory/registers so they don't break printing
        self.state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        self.state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        self.print_legend()

        print(Color.blueify(headerRegs))
        self.print_registers_pane()

        print(Color.blueify(headerCode))
        self.print_code_pane(linear_code)

        if [b"", b"", b""] != [self.state.posix.dumps(x) for x in self.state.posix.fd]:
            print(Color.blueify(headerFDs))
            self.print_fds_pane()

        print(Color.blueify(headerStack))
        self.print_stack_pane()

        print(Color.blueify(headerBacktrace))
        self.print_backtrace_pane()

        try:
            self.state.watches
        except AttributeError:
            l.warning("No watches plugin loaded, unable to print watches")
        else:
            print(Color.blueify(headerWatch))
            self.print_watches_pane()

        # Reenable the warnings about accessing uninitialized memory/registers so they don't break printing
        self.state.options.remove(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        self.state.options.remove(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

        # This is a hack to allow this method to be monkey patched as the __repr__ method of a state
        return ""

    def print_registers_pane(self) -> None:
        for reg in self.default_registers():
            register_number, size = self.state.arch.registers[reg]
            print(
                self._pstr_register(
                    reg,
                    self.state.registers.load(
                        register_number, inspect=False, disable_actions=True, size=size
                    ),
                )
            )

    def print_code_pane(self, linear_code: bool = False) -> None:
        print(self._pstr_code(linear_code))

    def print_fds_pane(self) -> None:
        for fd in self.state.posix.fd:
            print("fd " + str(fd), ":", repr(self.state.posix.dumps(fd)))

    def print_stack_pane(self) -> None:
        stackdepth = 8
        # Not sure if that can happen, but if it does things will break
        if not self.state.regs.sp.concrete:
            print("STACK POINTER IS SYMBOLIC: " + str(self.state.regs.sp))
            return
        for o in range(stackdepth):
            print(self._pstr_stack_element(o))

    def print_backtrace_pane(self) -> None:
        print(self._pstr_backtrace())

    def print_watches_pane(self) -> None:
        try:
            self.state.watches
        except AttributeError:
            l.warning(
                "Tried accessing watches plugin, but the state doesn't have this registered"
            )
            return
        for name, w in self.state.watches.eval:
            print("%s:\t%s" % (name, w))
        return None

    def __BVtoREG(self, bv: BV) -> str:
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

    def _color_code_ast(self, bv: claripy.ast.bv.BV) -> Tuple[ColoredString, bool]:
        """
        Converts a bitvector into a string representation that is colored depending on it's type/value and returns

        Colors:
        Uninitialized: Gray
        Symbolic: Green
        Stack: Yellow
        Heap: Blue
        Code: Red
        :param claripy.ast.BV bv:
        :return Tuple[str, bool]:
        """
        if bv.symbolic:
            if bv.uninitialized:
                return Color.grayify(self.__BVtoREG(bv)), False
            return Color.greenify(self.__BVtoREG(bv)), False
        # its concrete
        value: int = self.state.solver.eval(bv, cast_to=int)

        if (
            self.state.solver.eval(self.state.regs.sp)
            <= value
            <= self.state.arch.initial_sp
        ):
            return Color.yellowify(hex(value)), False
        if self.state.heap.heap_base <= value <= self.state.heap.heap_base + self.state.heap.heap_size:
            return Color.blueify(hex(value)), False

        try:
            perm = self.state.memory.permissions(value)
            if not perm.symbolic:
                perm = self.state.solver.eval(perm, cast_to=int)
                if perm:
                    PROT_EXEC = 4
                    if perm & 4:
                        descr = " <%s>" % self.state.project.loader.describe_addr(value)
                        if descr == " <not part of a loaded object>":
                            return Color.redify(hex(value)), True
                        return Color.redify(hex(value) + descr), True
                    else:
                        descr = " <%s>" % self.state.project.loader.describe_addr(value)
                        if descr == " <not part of a loaded object>":
                            return Color.pinkify(hex(value)), False
                        return Color.pinkify(hex(value) + descr), False
        except:
            pass

        return cast(ColoredString, hex(value)), False

    def __color_code_ast(self, bv: claripy.ast.bv.BV) -> ColoredString:
        """

        :param claripy.ast.BV bv:
        :return str:
        """

        return self._color_code_ast(bv)[0]

    def _pstr_backtrace(self) -> PrettyString:
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
                call_site_addr = self.state.project.loader.describe_addr(
                    f.call_site_addr
                )
            else:
                call_site_addr = "%#x" % f.call_site_addr
            if self.state.project.loader.find_object_containing(f.func_addr):
                func_addr = self.state.project.loader.describe_addr(f.func_addr)
            else:
                func_addr = "%#x" % f.func_addr

            frame = "Frame %d: %s => %s, sp = %#x" % (
                i,
                call_site_addr,
                func_addr,
                f.stack_ptr,
            )

            result.append(frame)
        return "\n".join(result)

    def _pstr_code(self, linear_code: bool =False) -> PrettyString:
        """

        :param bool linear_code: Whether the code will be printed as linear or block based disassembly
        :return str: the string of the code pane with colored assembly
        """
        result = []
        if not self.use_only_linear_disasm and not linear_code:
            previos_block: str = self._pstr_previous_codeblock()
            if previos_block:
                result.append(previos_block)
                result.append(
                    "\t|\t"
                    + self.__color_code_ast(
                        self.state.solver.simplify(self.state.history.jump_guard)
                    )
                    + "\n\tv"
                )
        result.append(self._pstr_current_codeblock(linear_code))
        return "\n".join(result)

    def _pstr_previous_codeblock(self) -> PrettyString:
        """
        Example:
            main+0x0 in sym_exec.elf (0x1149)
            0x401149:	push	rbp
            0x40114a:	mov	rbp, rsp
            0x40114d:	sub	rsp, 0x20
            0x401151:	mov	dword ptr [rbp - 0x14], edi
            0x401154:	mov	qword ptr [rbp - 0x20], rsi
            0x401158:	cmp	dword ptr [rbp - 0x14], 1
            0x40115c:	jg	0x401183

        :return str: The string form of the previous code block including annotations like location
        """
        result = [] # type: List[PrettyString]
        try:
            prev_ip = self.state.history.bbl_addrs[-1]
        except IndexError:
            return cast(ColoredString, "")

        # Print the location (like main+0x10) if possible
        descr = self.state.project.loader.describe_addr(prev_ip)
        if descr != "not part of a loaded object":
            result.append(descr)

        if not self.state.project.is_hooked(prev_ip):
            code = self._pstr_codeblock(prev_ip)
            if code == None:
                if self.disable_linear_disasm_fallback:
                    code = Color.redify(
                        "No code at current ip. Please specify self_modifying code "
                    )
                else:
                    raise Exception()  # skip print of previous
            code_lines = code.split("\n") # type: List[PrettyString]

            # if it is longer than MAX_DISASS_LENGTH, only print the first lines
            if len(code_lines) >= self._disassembler.MAX_DISASS_LENGHT:
                result.append("TRUNCATED BASIC BLOCK")
                result.extend(code_lines[-self._disassembler.MAX_DISASS_LENGHT :])
            else:
                result.extend(code_lines)

        else:
            hook = self.state.project.hooked_by(prev_ip)
            result.append(str(hook))

        return "\n".join(result)

    def _pstr_current_codeblock(self, linear_code: bool = False) -> PrettyString:
        """
        Example:
        main+0x15 in sym_exec.elf (0x115e)
        0x40115e:	mov	rax, qword ptr [rbp - 0x20]
        0x401162:	mov	rax, qword ptr [rax]
        0x401165:	mov	rsi, rax
        0x401168:	lea	rdi, [rip + 0xe95]
        0x40116f:	mov	eax, 0
        0x401174:	call	0x401040

        :param bool linear_code: Whether the code will be printed as linear or block based disassembly
        :return str: The colored string form of the current code block including annotations like location, either in block or linear form
        """

        result = []
        current_ip = self.state.solver.eval(self.state.regs.ip)

        # Print the location (like main+0x10) if possible
        descr = self.state.project.loader.describe_addr(current_ip)
        if descr != "not part of a loaded object":
            result.append(descr)

        # Check if we are hooked or at the start of a known function to maybe pretty print the arguments
        cc = None  # type: Optional[SimCC]
        target: Union[SimProcedure, Function, None] = None
        if current_ip in self.state.project.kb.functions:
            target: Function = self.state.project.kb.functions[current_ip]
            cc = target.calling_convention

        if self.state.project.is_hooked(current_ip):
            hook = self.state.project.hooked_by(
                current_ip
            )  # type: Optional[SimProcedure]
            # Technically we can be sure that hook isn't None, because we checked with is_hooked,
            # but mypy doesn't know this
            # But by not guarding this with an is_hooked, we get annoying warnings, so we do both
            if hook is not None:
                target = hook
                cc = target.cc

        if target and target.prototype:
            result.extend(self._pstr_call_info(self.state, cc, target.prototype))

        # Get the current code block about to be executed as pretty disassembly
        if not self.state.project.is_hooked(current_ip):
            if self.use_only_linear_disasm or linear_code:
                code = self._pstr_codelinear(current_ip)
            else:
                code = self._pstr_codeblock(current_ip)
                if code == None:
                    if self.disable_linear_disasm_fallback:
                        code = Color.redify(
                            "No code at current ip. Please specify self_modifying code "
                        )
                    else:
                        code = self._pstr_codelinear(
                            current_ip
                        )  # do fallback to Capstone
            code = code.split("\n")

            # if it is longer than MAX_DISASS_LENGTH, only print the first lines
            if len(code) >= self._disassembler.MAX_DISASS_LENGHT:
                result.extend(code[: self._disassembler.MAX_DISASS_LENGHT])
                result.append("TRUNCATED BASIC BLOCK")
            else:
                result.extend(code)
        else:
            hook = self.state.project.hooked_by(current_ip)
            result.append(str(hook))

        return "\n".join(result)

    def _pstr_codeblock(self, ip: int) -> Optional[List[PrettyString]]:
        """
        Example:
        0x40115e:	mov	rax, qword ptr [rbp - 0x20]
        0x401162:	mov	rax, qword ptr [rax]
        0x401165:	mov	rsi, rax
        0x401168:	lea	rdi, [rip + 0xe95]
        0x40116f:	mov	eax, 0
        0x401174:	call	0x401040

        :param int ip: Address of the start of the block (typically the instruction pointer, thus ip)
        :return Optional[str]: If a code block could be generated returns the colored assembly, else None

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

    def _pstr_codelinear(self, ip: int) -> PrettyString:
        """
        Example:
        0x401154:	mov	qword ptr [rbp - 0x20], rsi
        0x401158:	cmp	dword ptr [rbp - 0x14], 1
        0x40115c:	jg	0x401183
        0x40115e:	mov	rax, qword ptr [rbp - 0x20]
    --> 0x401162:	mov	rax, qword ptr [rax]
        0x401165:	mov	rsi, rax
        0x401168:	lea	rdi, [rip + 0xe95]
        0x40116f:	mov	eax, 0
        0x401174:	call	0x401040
        0x401179:	mov	eax, 0xffffffff
        0x40117e:	jmp	0x401222

        :param int ip: Address around the instructon that should be disassembled
        :return str: The colored string of the instructions around the ip, with the ip instruction prefixed with "-->"
        """
        code = self._disassembler.linear_disass(ip, self)
        if not Color.disable_colors:
            return highlight(code, NasmLexer(), TerminalFormatter())
        else:
            return code

    def _pstr_stack_element(self, offset: int) -> PrettyString:
        """
        Format:
        "IDX:OFFSET|      ADDRESS --> CONTENT":
        Example
        00:0x00| sp 0x7fffffffffeff10  --> 0x7fffffffffeff60 --> 0x7fffffffffeff98 --> 0x6d662f656d6f682f
        :param int offset:
        :return str: One line for the stack element being prettified
        """
        """print(stack element in the form """
        l = "%s:" % ("{0:#02d}".format(offset))
        l += "%s| " % ("{0:#04x}".format(offset * self.state.arch.bytes))
        try:
            stackaddr, stackval = self.stack[offset]
        except IndexError:
            return ""

        if self.state.solver.eval(stackaddr) == self.state.solver.eval(
            self.state.regs.sp, cast_to=int
        ):
            l += "sp"
        elif self.state.solver.eval(stackaddr) == self.state.solver.eval(
            self.state.regs.bp, cast_to=int
        ):
            l += "bp"
        else:
            l += "  "
        l += " "

        l += "%s " % self.__color_code_ast(stackaddr)
        l += " --> %s" % self._pstr_ast(stackval)
        return l

    def _pstr_register(self, reg: RegisterName, value: claripy.ast.bv.BV) -> str:
        """

        :param str reg: Name of the register
        :param claripy.ast.BV value: Value of the register
        :return str:
        """
        repr = reg.upper() + ":\t"
        repr += self._pstr_ast(value)
        return repr

    def __deref_addr(self, addr: int) -> Optional[claripy.ast.bv.BV]:
        """

        :param int addr:
        :param int depth:
        :return Optional[claripy.ast.BV]:
        """
        if addr in self.state.memory:
            deref = self.state.memory.load(addr, 1, inspect=False, disable_actions=True)
            if deref.op == "Extract":
                deref = deref.args[2]
            else:
                deref = self.state.mem[addr].uintptr_t.resolved
            return deref
        return None

    def _pstr_ast(
        self, ast: claripy.ast.bv.BV, ty: Optional[SimType] = None, depth: int=0
    ) -> str:
        """Return a pretty string for an AST including a description of the derefed value if it makes sense (i.e. if
        the ast is concrete and the derefed value is not uninitialized
        More complex rendering is possible if type information is supplied
        :param claripy.ast.BV ast: The AST to be pretty printed
        :param angr.sim_type.SimType ty: Optional Type information
        :return str: Pretty colored string
        """
        if depth > MAX_AST_DEPTH:
            return str(ast)

        # Type handling
        if isinstance(ty, SimTypePointer):
            if ast.concrete:
                cc_ast, ast_is_code_ptr = self._color_code_ast(ast)
                if ast_is_code_ptr:
                    return cc_ast
                if isinstance(ty.pts_to, SimTypePointer):
                    return
                try:
                    tmp = "%s --> %s" % (
                        cc_ast,
                        repr(self.state.mem[ast].string.concrete),
                    )
                except ValueError:
                    deref = self.state.memory.load(
                        ast, 1, inspect=False, disable_actions=True
                    )
                    if deref.op == "Extract":
                        return "%s --> %s" % (
                            cc_ast,
                            self.__color_code_ast(deref.args[2]),
                        )
                    elif deref.uninitialized:
                        return "%s --> UNINITIALIZED" % (cc_ast)
                    else:
                        return "%s --> COMPLEX SYMBOLIC STRING" % (cc_ast)
                else:
                    return tmp
            else:
                return "%s %s" % (
                    Color.redify("WARN: Symbolic Pointer"),
                    self.__color_code_ast(ast),
                )
        if isinstance(ty, SimTypeChar) and ast.concrete:
            return "'%s'" % chr(self.state.solver.eval(ast))
        elif isinstance(ty, SimTypeInt):
            if ast.concrete:
                return "%#x" % self.state.solver.eval(ast, cast_to=int)
            else:
                return str(ast)

        if ast.concrete:
            value: int = self.state.solver.eval(ast)
            cc_ast, ast_is_code_ptr = self._color_code_ast(ast)
            deref = self.__deref_addr(value)
            if (deref != None) and not ast_is_code_ptr and ast.op == "BVV":
                pretty_deref = self._pstr_ast(deref, depth=depth + 1)
                return "%s --> %s" % (cc_ast, pretty_deref)
            else:
                return cc_ast
        else:
            if ast.depth > MAX_AST_DEPTH:
                # AST is probably too large to render
                return Color.greenify(
                    "<AST: Depth: %d Vars: %s Hash: %x>"
                    % (ast.depth, ast.variables, ast.__hash__())
                )
            return self.__color_code_ast(ast)

    def default_registers(self) -> List[RegisterName]:
        """
        The list of the registers that are printed by default in the register pane
        Either some custom set for common architectures or a default set generated from the arch specification
        :return List[str]:
        """
        custom = {
            "X86": cast(List[RegisterName], ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]),
            "AMD64": cast(List[RegisterName], [
                "rax",
                "rbx",
                "rcx",
                "rdx",
                "rsi",
                "rdi",
                "rbp",
                "rsp",
                "rip",
                "r8",
                "r9",
                "r10",
                "r11",
                "r12",
                "r13",
                "r14",
                "r15",
            ]),
        } # type: Dict[str, List[RegisterName]]
        if self.state.arch.name in custom:
            return custom[self.state.arch.name]
        else:
            l.warning("No custom register list implemented, using fallback")
            return (
                self.state.arch.default_symbolic_registers
                + [self.state.arch.register_names[self.state.arch.ip_offset]]
                + [self.state.arch.register_names[self.state.arch.sp_offset]]
                + [self.state.arch.register_names[self.state.arch.bp_offset]]
            )

    def _pstr_branch_info(self, idx: Optional[int] = None) -> PrettyString:
        """
        Return the information about the state concerning the last branch as a pretty string
        :param Optional[int] idx:
        :return str:
        """
        str_ip = self._pstr_ast(self.state.regs.ip)
        simplified_jump_guard = self.state.solver.simplify(
            self.state.history.jump_guard
        )
        str_jump_guard = self._pstr_ast(simplified_jump_guard)
        vars = cast(BV, self.state.history.jump_guard).variables

        return "%sIP: %s\tCond: %s\n\tVars: %s\n" % (
            str(idx) + ":\t" if type(idx) is int else "",
            str_ip,
            str_jump_guard,
            vars,
        )

    def _pstr_call_info(self, state: SimState, cc: SimCC, prototype: SimTypeFunction) -> List[PrettyString]:
        """

        :param angr.SimState state:
        :param SimCC cc:
        :return List[str]:
        """
        return [self._pstr_call_argument(*arg) for arg in cc.get_arg_info(state, prototype)]

    def _pstr_call_argument(self, ty: SimType, name: str, location: SimFunctionArgument, value: claripy.ast.bv.BV) -> PrettyString:
        """
        The input should ideally be the unpacked tuple from one of the list entries of calling_convention.get_arg_info(state)
        :param angr.sim_type.SimType ty:
        :param str name:
        :param angr.calling_conventions.SimFunctionArgument location:
        :param claripy.ast.BV value:
        :return str:
        """
        return "%s %s@%s: %s" % (ty, name, location, self._pstr_ast(value, ty=ty))


class Stack:
    def __init__(self, state: SimState):
        self.state = state  # type: angr.SimState

    def __getitem__(self, offset: int) -> Tuple[int, claripy.ast.bv.BV]:
        """Returns a tuple of a stack element as (addr, content)"""
        addr = self.state.regs.sp + offset * self.state.arch.bytes
        if self.state.solver.eval(addr >= self.state.arch.initial_sp):
            raise IndexError
        return (
            addr,
            self.state.memory.load(
                addr,
                size=self.state.arch.bytes,
                endness=self.state.arch.memory_endness,
                inspect=False,
                disable_actions=True,
            ),
        )


ContextView.register_default("context_view")
