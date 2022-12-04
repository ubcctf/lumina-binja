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


#metaclass like how binja implements its subscriptable Architecture class
#have to do this to lazy load; otherwise we end up with circular import
class _mapping(type):
    def __init__(self, name, bases, dict) -> None:
        super().__init__(name, bases, dict)
        from .x86 import X86
        self.map = {'x86_64': X86, 'x86': X86}

    def __iter__(self):
        return self.map.__iter__()

    def __getitem__(self, name: str) -> Sig:
        return self.map[name]

class ARCH_MAPPING(metaclass=_mapping): ...