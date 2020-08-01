from typing import List, TYPE_CHECKING

import angr


class DisassemblerInterface:
    """
    Interface that contains the options for the Disassembler abstraction used and the methods that need to be implemented
    """

    MAX_DISASS_LENGHT = 30
    MAX_CAP_DIS_LENGHT = 10
    NB_INSTR_PREV = 4

    def block_disass(self, block: angr.block.Block, ctx_view: 'ContextView') -> List[str]:
        raise NotImplemented

    def linear_disass(self, ip: int, ctx_view: 'ContextView') -> List[str]:
        raise NotImplemented


import capstone  # type: ignore
import claripy


class AngrCapstoneDisassembler(DisassemblerInterface):
    def block_disass(self, block: angr.block.Block, ctx_view: 'ContextView') -> List[str]:
        """

        :param angr.block.Block block:
        :param angrcli.plugins.context_view.ContextView ctx_view:
        :return:
        """
        return str(block.capstone)

    def linear_disass(self, ip: int, ctx_view: 'ContextView') -> List[str]:
        """

        When doing a fallback to Capstone we cannot disassemble by blocks so we
        procede in a GEF style:
        print NB_INSTR_PREV instruction before the current,
        print the current with an arrow,
        print (MAX_CAP_DIS_LENGHT - NB_INSTR_PREV -1) isntructions after current
        :param int ip:
        :param angrcli.plugins.context_view.ContextView ctx_view:
        :return:
        """
        md = capstone.Cs(
            ctx_view.state.project.arch.cs_arch, ctx_view.state.project.arch.cs_mode
        )

        disasm_start = ip
        for i in range(15 * self.NB_INSTR_PREV, 0, -1):

            mem = ctx_view.state.memory.load(
                ip - i, i + 15, inspect=False, disable_actions=True
            )
            if mem.symbolic:
                break

            mem = ctx_view.state.solver.eval(mem, cast_to=bytes)

            cnt = 0
            last_instr = None
            for instr in md.disasm(mem, ip - i):
                if cnt == self.NB_INSTR_PREV:
                    last_instr = instr
                    break
                cnt += 1

            if last_instr is not None and last_instr.address == ip:
                disasm_start = ip - i
                break

        code = ""
        mem = ctx_view.state.memory.load(disasm_start, self.MAX_CAP_DIS_LENGHT * 15)
        if mem.symbolic:
            if isinstance(mem.args[0], claripy.ast.bv.BV) and not mem.args[0].symbolic:
                mem = mem.args[0]
            else:
                return "Instructions are symbolic!"

        mem = ctx_view.state.solver.eval(mem, cast_to=bytes)

        cnt = 0
        md = capstone.Cs(
            ctx_view.state.project.arch.cs_arch, ctx_view.state.project.arch.cs_mode
        )
        for instr in md.disasm(mem, disasm_start):
            if instr.address == ip:
                code += " --> "
            else:
                code += "     "
            code += "0x%x:\t%s\t%s\n" % (instr.address, instr.mnemonic, instr.op_str)
            if cnt == self.MAX_CAP_DIS_LENGHT:
                break
            cnt += 1
        return code


class GhidraDisassembler(DisassemblerInterface): # noqa
    """
    This classes uses ghidra_bridge to query the disassembly from Ghidra which automatically resolves structure and variable references
    ghidra_bridge is a giant hack, don't be confused that this uses variables that shouldn't exist and probably messes with the namespace in weird ways
    """

    def __init__(self) -> None:
        import ghidra_bridge

        namespace = {}
        self._bridge = ghidra_bridge.GhidraBridge(namespace)
        self._cuf = ghidra.program.model.listing.CodeUnitFormat.DEFAULT # noqa: F821
        self._diss = ghidra.app.util.PseudoDisassembler(currentProgram) # noqa: F821

    def disass_line(self, addr):
        codeUnit = self._diss.disassemble(currentAddress.getNewAddress(addr)) # noqa: F821
        return "0x%x: %s\n" % (addr, self._cuf.getRepresentationString(codeUnit))

    def block_disass(self, block: angr.block.Block, ctx_view: 'ContextView') -> List[str]:
        """

        :param angr.block.Block block:
        :return:
        """
        result = ""
        for a in block.instruction_addrs:
            codeUnit = self._diss.disassemble(currentAddress.getNewAddress(a)) # noqa: F821
            result += "0x%x: %s\n" % (a, self._cuf.getRepresentationString(codeUnit))
        return result

    def linear_disass(self, ip: int, ctx_view: 'ContextView') -> List[str]:
        """

        :param int ip:
        :param angrcli.plugins.context_view.ContextView ctx_view:
        :return:
        """
        raise NotImplemented  # TODO

if TYPE_CHECKING:
    from angrcli.plugins.ContextView.context_view import ContextView
