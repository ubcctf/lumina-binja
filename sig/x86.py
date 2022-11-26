
from binaryninja import Function

from capstone import *
from capstone.x86 import *

import io

from .util import Sig


class X86(Sig):

    def valid_loc(self, offset: int, f: Function):
        #include all data variables that has a code ref (aka if it is a valid reference binja would tell us)
        #also include if is pointing to start of instruction, but never mask same function jumps
        #sometimes there might be multiple functions at the same address even on the same architecture it seems like - we check all of them to see if any is the same function then reject
        #binja considers <0x1000 (header space) to be referenced by way too many non related things, so count it as an exception (somehow it considers any values used in instructions as references regardless of actually using it or not)
        return offset > 0x1000 and ((self.bv.get_data_var_at(offset) is not None and next(self.bv.get_code_refs(offset), None) is not None) or ((others:=self.bv.get_functions_containing(offset)) and all(o.start != f.start and (inst:=o.get_instruction_containing_address(offset)) and inst == offset for o in others)))
        #DataVariable is falsey, but List and Optional works


    def getmask(self, d: CsInsn, f: Function):
        mask = bytes(d.size)

        #<opcode, disp_offset, imm_offset> - offsets are optional and can not exist
        #afaik x86 imm is always at the end

        if d.disp_offset: #consider references - any fs address, any relative memory accesses that's valid in program scope (see valid_loc def)
            m = b'\xFF' if any(op.type == X86_OP_MEM and (op.reg == X86_REG_FS or (op.value.mem.base == X86_REG_RIP and self.valid_loc(op.value.mem.disp + d.address + d.size, f))) for op in d.operands) else b'\0'
            size = (d.imm_offset - d.disp_offset if d.imm_offset else d.size - d.disp_offset)
            mask = mask[:d.disp_offset] + m*size + mask[d.disp_offset+size:]

        #imm always later than disp
        if d.imm_offset: #references in imm just points directly to addresses
            m = b'\xFF' if any(op.type == X86_OP_IMM and self.valid_loc(op.imm, f) for op in d.operands) else b'\0'
            size = d.size - d.imm_offset
            mask = mask[:d.imm_offset] + m*size + mask[d.imm_offset+size:]

        return mask

    def calcrel(self, func: Function) -> tuple[str, bytes, bytes]:
        inst = [i for i in func.instructions]

        func_end = func.address_ranges[-1].end

        ptr = func.start
        while (f:=self.bv.get_function_at(self.bv.get_next_function_start_after(ptr))) and all(addr in range(func.start, func_end+1) for addr in [f.address_ranges[-1].end, f.start]):
            ptr = f.start
            inst += f.instructions

        inst_bytes = [self.br.seek(i[1]) or self.br.read(self.bv.get_instruction_length(i[1])) for i in inst]

        cap = Cs(CS_ARCH_X86, CS_MODE_64)  #seems like 64bit mode can still disassemble 32 bit completely fine
        cap.detail = True
        #make offset to start of func so its easily referencable with the MD5 dump we get
        #TODO check why disasm can't disassemble certain binja instructions
        dis = [next(cap.disasm(b, i[1]), len(i)) for i, b in zip(inst, inst_bytes)]  #should always only have one result
        #fallback to give size instead if failed

        #if its in the valid proc address space then it counts as volatile
        #take the entire block of data including alignment into account (use size if disassembly is not available)
        mask = [self.getmask(d, func) if isinstance(d, CsInsn) else bytes(d) for d in dis]

        masked = [bytes([0 if m == 0xFF else b for m, b in zip(mb, bb)]) for mb, bb in zip(mask, inst_bytes)]


        assert len(mask) == len(masked) == len(inst) == len(inst_bytes)


        #write the masks back into the block of data that the function encompasses (not sure why IDA does that)
        try:
            self.br.seek(func.start)
            maskblock = io.BytesIO(b'\0'*(func_end - func.start))
            block = io.BytesIO(self.br.read(func_end - func.start))
            for i in range(len(mask)):
                block.seek(inst[i][1] - func.start)
                maskblock.seek(inst[i][1] - func.start)
                block.write(masked[i])
                maskblock.write(mask[i])
            block = block.getvalue()
            maskblock = maskblock.getvalue()
        except:
            print("Function", func.name, "has references above func start (exception handlers?), aborting...")
            return None

        #compute MD5
        import hashlib

        hash = hashlib.md5(block + maskblock).digest().hex()
        return hash, block, maskblock