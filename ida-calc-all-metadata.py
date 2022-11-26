import ida_kernwin, ida_pro, ida_funcs, ida_auto, ida_segment, ida_idp, ida_registry, idc

#this script writes each function address into a file, and triggers lumina sequentially (intended to use with frida to obtain hash)
#note: idat is *pretty* fragile so things might break if you reorder code (might even be nondeterministic if its related to lumina initialization)
#also idat will utilize 100% of a core if the script throws an exception


#open disasm window well in advance to prepare for lumina
idaview = ida_kernwin.open_disasm_window('IDA View-A')
ida_kernwin.display_widget(idaview, 0)

#we need to disable lumina pull all on autoanalysis finish or else we get junk that we dont want
orig = ida_registry.reg_read_int('AutoUseLumina', 1)
ida_registry.reg_write_int('AutoUseLumina', 0)

#wait until autoanalysis is finished to get full function list; this also gives time for frida to attach
ida_auto.auto_wait()

#restore option
ida_registry.reg_write_int('AutoUseLumina', orig)

#use local server to speed up processing - we dont need actual responses anyway
#self note: if local server is not running idat's gonna make a ton of windows noise
ida_idp.process_config_directive('LUMINA_HOST="127.0.0.1"')
ida_idp.process_config_directive('LUMINA_PORT=4443')
ida_idp.process_config_directive('LUMINA_TLS=NO')


class Run(ida_kernwin.UI_Hooks):
    def __init__(self) -> None:
        ida_kernwin.UI_Hooks.__init__(self)

    #wait until ready
    def ready_to_run(self):
        #spinning seems to be necessary when we are connecting to remote but makes things worse when we are connecting to local server
        # #spin until lumina finishes initializing - have to use idc.qsleep not time.sleep since we cannot occupy the thread
        # #somehow sometimes it deadlocks though i have no idea how to fix
        # while not ida_kernwin.is_action_enabled(ida_kernwin.get_action_state('LuminaIDAViewPullMd')[1]):
        #     with open('test.log', 'a') as ww:
        #         ww.write('spinning\n')
        #     idc.qsleep(100)

        ea = 0
        while (f:=ida_funcs.get_next_func(ea)):
            ea = f.start_ea   #move onto the next func regardless
            if not ida_segment.is_spec_ea(ea):  #ignore extern symbols and the likes
                ida_kernwin.jumpto(ea)
                ida_kernwin.process_ui_action('LuminaIDAViewPullMd')

        ida_idp.process_config_directive('ABANDON_DATABASE=YES')
        ida_pro.qexit(0)


uihook = Run()
uihook.hook()
