
from cmd import Cmd


class GUICallbackBaseClass():
    def update_ip(self, ip):
        pass


class BinjaCallback(GUICallbackBaseClass):
    def __init__(self, bv):
        self.bv = bv

    def update_ip(self, ip):
        self.bv.file.navigate(self.bv.file.view, ip)


class ExploreInteractive(Cmd, object):

    intro = "Dropping into angr shell"
    prompt = "explore>"

    def __init__(self, proj, state, gui_callback_object=None):
        super(ExploreInteractive, self).__init__()
        self.proj = proj
        self.simgr = proj.factory.simulation_manager(state)
        self.gui_cb = gui_callback_object

    def do_quit(self, args):
        """Quits the program."""
        print "Quitting."
        raise SystemExit

    def do_print(self, arg):
        if not arg:
            arg = "0"

        pick = int(arg)
        self.simgr.active[pick].context_view.pprint()
        self.gui_cb.update_ip(self.simgr.active[pick].addr)

    def do_stepi(self, args):
        if len(self.simgr.active) == 1:
            self.simgr.step(num_inst=1)
            print("\033[H\033[J")
            self.simgr.one_active.context_view.pprint()
            self.gui_cb.update_ip(self.simgr.one_active.addr)

        elif len(self.simgr.active) > 1:
            idx = 0
            for state in self.simgr.active:
                print state.context_view.pstr_branch_info(idx)
                idx += 1

    def do_step(self, args):
        if len(self.simgr.active) == 1:
            self.simgr.step()
            print("\033[H\033[J")
            self.simgr.one_active.context_view.pprint()
            self.gui_cb.update_ip(self.simgr.one_active.addr)
        elif len(self.simgr.active) > 1:
            idx = 0
            for state in self.simgr.active:
                print state.context_view.pstr_branch_info(idx)
                idx += 1

    def do_s(self, args):
        self.do_step(args)

    def do_run(self, args):
        self.simgr.run(until=lambda s: len(s.active) != 1)
        self.gui_cb.update_ip(self.simgr.one_active.addr)
        idx = 0
        for state in self.simgr.active:
            print state.context_view.pstr_branch_info(idx)
            idx += 1


    def do_pick(self, arg):
        pick = int(arg)
        ip = self.simgr.active[pick].regs.ip
        print("Picking state with ip: " + (str(ip)))
        self.simgr.move(from_stash='active',
                   to_stash="stashed",
                   filter_func=lambda x: x.solver.eval(ip != x.regs.ip))
        self.simgr.step()
        print("\033[H\033[J")
        self.simgr.one_active.context_view.pprint()
