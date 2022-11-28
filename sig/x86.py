
from binaryninja import Function

from capstone import Cs, CsInsn, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_FS, X86_REG_GS, X86_REG_RIP, X86_OP_MEM, X86_OP_IMM

import io

from .util import Sig


class X86(Sig):

    def valid_loc(self, offset: int, f: Function):
        #include all data variables that has a code ref (aka if it is a valid reference binja would tell us)
        #also include if is pointing to start of instruction, but never mask same function jumps
        #sometimes there might be multiple functions at the same address even on the same architecture it seems like - we check all of them to see if any is the same function then reject
        #binja considers <0x1000 (header space) to be referenced by way too many non related things, so count it as an exception (somehow it considers any values used in instructions as references regardless of actually using it or not)
        return offset > 0x1000 and (((others:=self.bv.get_functions_containing(offset)) and all(o.start != f.start and (inst:=o.get_instruction_containing_address(offset)) and inst == offset for o in others)) or (self.bv.get_data_var_at(offset) is not None and next(self.bv.get_code_refs(offset), None) is not None))
        #DataVariable is falsey, but List and Optional works


    def calcrel(self, d: CsInsn, f: Function):
        mask = bytes(d.size)

        #<opcode, disp_offset, imm_offset> - offsets are optional and can not exist
        #afaik x86 imm is always at the end

        if d.disp_offset: #consider references - any fs address, any relative memory accesses that's valid in program scope (see valid_loc def)
            m = b'\xFF' if any(op.type == X86_OP_MEM and (op.reg in [X86_REG_FS, X86_REG_GS] or (op.value.mem.base == X86_REG_RIP and self.valid_loc(op.value.mem.disp + d.address + d.size, f))) for op in d.operands) else b'\0'
            size = (d.imm_offset - d.disp_offset if d.imm_offset else d.size - d.disp_offset)
            mask = mask[:d.disp_offset] + m*size + mask[d.disp_offset+size:]

        #imm always later than disp
        if d.imm_offset: #references in imm just points directly to addresses
            m = b'\xFF' if any(op.type == X86_OP_IMM and self.valid_loc(op.imm, f) for op in d.operands) else b'\0'
            size = d.size - d.imm_offset
            mask = mask[:d.imm_offset] + m*size + mask[d.imm_offset+size:]

        return mask

    def calc_func_metadata(self, func: Function) -> tuple[str, bytes, bytes]:
        ranges = func.address_ranges

        #dont check the portions of the function above func.start (aka no min([r.start for r in ranges])); seems like IDA doesnt care either and this speeds things up by a ton in binaries with exception handlers
        func_start = func.start 
        func_end = max([r.end for r in ranges])

        cap = Cs(CS_ARCH_X86, CS_MODE_64)  #seems like 64bit mode can still disassemble 32 bit completely fine
        cap.detail = True

        #take the entire block of data including alignment into account (use size if disassembly is not available)
        self.br.seek(func_start)
        block = self.br.read(func_end - func_start)

        #linearly disassemble the entire block of bytes that the function encompasses (IDA does that instead of checking whether the bytes are accessible to the function or not)
        dis = cap.disasm(block, func_start) 

        maskblock = io.BytesIO(bytes(len(block)))
        block = io.BytesIO(block)
        #if its in the valid proc address space then it counts as volatile
        for d in dis:
            maskblock.seek(d.address - func_start)
            block.seek(d.address - func_start)

            mask = (self.calcrel(d, func))
            data = bytes([b if m != 0xFF else 0 for m, b in zip(mask, block.read(len(mask)))])

            maskblock.write(mask)
            
            block.seek(d.address - func_start)
            block.write(data)
        block = block.getvalue()
        maskblock = maskblock.getvalue()

        #compute MD5
        import hashlib

        hash = hashlib.md5(block + maskblock).digest()
        return hash, block, maskblock