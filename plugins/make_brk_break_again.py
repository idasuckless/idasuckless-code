import idaapi
from ida_ua import cmd
from idautils import XrefsFrom
from ida_allins import ARM_brk

class CPUHooks(idaapi.IDP_Hooks):
    def custom_emu(self):
        if cmd.itype != ARM_brk:
            return False
        # print 'brk @ 0x%X'%(cmd.ea)
        return True


class MakeBRKBreakAgainPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Make BRK break again."
    help = "Make BRK break again."
    wanted_name = "Make BRK break again (c) IDASuckLess"
    wanted_hotkey = ''
    hooks = None

    def init(self):
        if idaapi.ph_get_id() != idaapi.PLFM_ARM or idaapi.BADADDR <= 0xFFFFFFFF:
            print "%s won't load!"%self.wanted_name
            return idaapi.PLUGIN_SKIP
        self.hooks = CPUHooks()
        self.hooks.hook()
        print "%s is loaded!"%self.wanted_name
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None


def PLUGIN_ENTRY():
    return MakeBRKBreakAgainPlugin()
