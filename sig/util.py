from binaryninja import BinaryView, BinaryReader, Function

def hexdump(block):
    print("\n".join([" ".join([row.hex()[i:i + 2] for i in range(0, len(row.hex()), 2)]) for row in [block[i:i + 16] for i in range(0, len(block), 16)]]))


#base class for all architectures' signature generation functions
class Sig:
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.br = BinaryReader(bv)

    def calc_func_metadata(self, func: Function) -> tuple[str, bytes, bytes]:
        raise NotImplementedError()