
from cmd import Cmd


class GUICallbackBaseClass():
    def update_ip(self, ip):
        pass


class BinjaCallback(GUICallbackBaseClass):
    def __init__(self, bv):
        self.bv = bv

    def update_ip(self, ip):
        self.bv.file.navigate(self.bv.file.view, ip)


def red(text):
    return "\x1b[0;31m" + text + "\x1b[0m"

class ExploreInteractive(Cmd, object):

    intro = red("[!] Dropping into angr shell\n") 
    intro += red("Available Commands: print, (p)ick, (r)un, (s)tep, stepi, (q)uit")
    prompt = red(">>> ")

    def __init__(self, proj, state, gui_callback_object=GUICallbackBaseClass()):
        super(ExploreInteractive, self).__init__()
        self.proj = proj
        self.simgr = proj.factory.simulation_manager(state)
        if "deferred" not in self.simgr.stashes:
            self.simgr.stashes["deferred"] = []
        self.gui_cb = gui_callback_object

    @property
    def state(self):
        """
        Alias to `self.simgr.one_active`
        :return:
        """
        return self.simgr.one_active

    def _clearScreen(self):
        print("\033[H\033[J")

    def do_quit(self, args):
        """Quits the cli."""
        print(red("Exiting cmd-loop"))
        return True
    
    def do_q(self, args):
        self.do_quit(args)
        return True

    def do_print(self, arg):
        if not arg:
            arg = "0"

        pick = int(arg)
        active = len(self.simgr.active)
        if pick >= active:
            print(red("Only {} active state(s), indexed from 0".format(active)))
        else:
            self.simgr.active[pick].context_view.pprint()
            self.gui_cb.update_ip(self.simgr.active[pick].addr)

    def do_stepi(self, args):
        if len(self.simgr.active) == 1:
            self.simgr.step(num_inst=1)
            self._clearScreen()
            self.simgr.one_active.context_view.pprint()
            self.gui_cb.update_ip(self.simgr.one_active.addr)
        elif len(self.simgr.active) > 1:
            for idx, state in enumerate(self.simgr.active):
                print(state.context_view.pstr_branch_info(idx))

    def do_step(self, args):
        if len(self.simgr.active) == 1:
            self.simgr.step()
            self._clearScreen()
            self.simgr.one_active.context_view.pprint()
            self.gui_cb.update_ip(self.simgr.one_active.addr)
        elif len(self.simgr.active) > 1:
            for idx, state in enumerate(self.simgr.active):
                print(state.context_view.pstr_branch_info(idx))
    
    def do_s(self, args):
        self.do_step(args)

    def do_s(self, args):
        self.do_step(args)

    def do_run(self, args):
        if len(self.simgr.active) > 1 and args:
            self.do_pick(args)
        if len(self.simgr.active) == 1:
            self.simgr.run(until=lambda s: len(s.active) != 1)
            if self.simgr.active:
                self.gui_cb.update_ip(self.simgr.one_active.addr)

        if len(self.simgr.active) > 0:
            for i, state in enumerate(self.simgr.active):
                print(state.context_view.pstr_branch_info(i))
        else:
            if len(self.simgr.stashes["deferred"]) == 0:
                print(red("No active states left"))
            else: # DFS-style like 
                self.simgr.stashes["active"].append(self.simgr.stashes["deferred"].pop())

    def do_r(self, args):
        self.do_run(args)


    def do_pick(self, arg):
        try:
            pick = int(arg)
            ip = self.simgr.active[pick].regs.ip
        except:
            print("Invalid Choice: "+red("{}".format(arg))+", for {}".format(self.simgr))
            return False
        print(red("Picking state with ip: " + (str(ip))))
        self.simgr.move(from_stash='active',
                   to_stash="deferred",
                   filter_func=lambda x: x.solver.eval(ip != x.regs.ip))
        self.simgr.step()
        self._clearScreen()
        self.simgr.one_active.context_view.pprint()
    
    def do_p(self, args):
        self.do_pick(args)

    def do_EOF(self, args):
        self.do_quit(args)
        return True

