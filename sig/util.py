from binaryninja import BinaryView, BinaryReader, Function, BackgroundTaskThread

def hexdump(block):
    print("\n".join([" ".join([row.hex()[i:i + 2] for i in range(0, len(row.hex()), 2)]) for row in [block[i:i + 16] for i in range(0, len(block), 16)]]))


#base class for all architectures' signature generation functions
class Sig(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, func: Function):
        BackgroundTaskThread.__init__(self, "Lumina: calculating function metadata...", True)
        self.bv = bv
        self.br = BinaryReader(bv)
        self.func = func

    #run sync
    def calc_func_metadata(self) -> tuple[str, bytes, bytes]:
        raise NotImplementedError()

    #run async
    def run(self):
        self.retval = self.calc_func_metadata()

    def join(self, timeout=None):
        self.thread.join(timeout)
        return self.retval
    


    