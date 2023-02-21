from lumina_structs.tinfo import *
from construct import Container
from binaryninja import BinaryView, Type, FunctionParameter, enums
from typing import List, Optional
import math

#
# handles mapping from generic lumina tinfo definitions to binja-specific data
#

def construct_ptr(tinfo: Container, bv: BinaryView, *_):
    #binja has no concept of near/far pointers unlike IDA, nor __closure(? unless one of the ReferenceTypes are the same as IDA closures)
    #TODO figure out TAPTR_* and whether they exist in binja
    if tinfo.data.ptrsize:
        return Type.pointer_of_width((tinfo.data.ptrsize, construct_type(bv, tinfo.data.type, *_)), const=tinfo.typedef.flags == Modifiers.BTM_CONST, volatile=tinfo.typedef.flags == Modifiers.BTM_VOLATILE)
    else:
        return Type.pointer(bv.arch, construct_type(bv, tinfo.data.type, *_), const=tinfo.typedef.flags == Modifiers.BTM_CONST, volatile=tinfo.typedef.flags == Modifiers.BTM_VOLATILE)

def construct_arr(tinfo: Container, bv: BinaryView, *_):
    #binja have no "base of array" concepts, assume zero always
    return Type.array(construct_type(bv, tinfo.data.type, *_), tinfo.data.num_elems)


cc_mapping = {
    CallingConvention.CM_CC_CDECL: lambda platform: platform.cdecl_calling_convention,
    CallingConvention.CM_CC_ELLIPSIS: lambda platform: platform.cdecl_calling_convention,
    CallingConvention.CM_CC_STDCALL: lambda platform: platform.stdcall_calling_convention,
    CallingConvention.CM_CC_PASCAL: lambda platform: platform.stdcall_calling_convention,    #TODO but reversed order of args
    CallingConvention.CM_CC_FASTCALL: lambda platform: platform.fastcall_calling_convention,
    CallingConvention.CM_CC_THISCALL: lambda platform: platform.fastcall_calling_convention, #TODO except only first arg is in reg
}

def construct_func(tinfo: Container, bv: BinaryView, names: Optional[List[str]], *_):
    #again no near/far concepts (no calling model difference/calling ptr size); probably no iret either; spoiled regs and all that seems to be largely nonexistent too
    #TODO create special calling conventions and register in case of CM_CC_SPECIAL*?
    stkoff = 0
    if tinfo.data.argloc:
        if tinfo.data.argloc.type == ArglocType.ALOC_STACK:  #only one thats supported by binja in types, other are directly handled on functions
            stkoff = tinfo.data.argloc.stkoff

    cc = cc_mapping[tinfo.data.cc.convention](bv.platform) if tinfo.data.cc.convention in cc_mapping else None  #only certain ccs exist in binja
    return Type.function(construct_type(bv, tinfo.data.rettype, names, *_), [FunctionParameter(construct_type(bv, param.type, names, *_), names.pop(0) if names else "") for param in tinfo.data.params], cc, stack_adjust=stkoff)

def construct_cmplx(tinfo: Container, bv: BinaryView, names: Optional[List[str]], nbytes: int):
    #lumina only pushes typedef, so not much we can do if it doesnt already exist in type libraries
    if tinfo.typedef.flags == ComplexFlags.BTMT_TYPEDEF:   #just to be sure we are dealing with typedefs before we search the name up
        for lib in bv.platform.type_libraries:
            if tinfo.data.name in lib.named_types:
                return lib.named_types[tinfo.data.name]
        return Type.named_type_reference(enums.NamedTypeReferenceClass.TypedefNamedTypeClass, tinfo.data.name, const=tinfo.typedef.flags == Modifiers.BTM_CONST, volatile=tinfo.typedef.flags == Modifiers.BTM_VOLATILE, width=nbytes)
    
    #TODO properly parse the complex types once ive figured out ways to force lumina to push full struct info (or extend it to do that)
    #this should basically never be reached before then
    return Type.named_type_reference(enums.NamedTypeReferenceClass.TypedefNamedTypeClass, "unk_complex_type")


def construct_bitfield(tinfo: Container, bv: BinaryView, *_):  #ive never seen this in use - see lumina_structs.tinfo for more info
    #binja doesnt have this as a type, treat as a byte array
    return Type.array(Type.int(1, sign=not tinfo.data.unsigned, alternate_name="byte"), math.ceil(tinfo.data.bitsize / 8))



float_width_mapping = {
    FloatFlags.BTMT_FLOAT: 4,
    FloatFlags.BTMT_DOUBLE: 8,
    FloatFlags.BTMT_LNGDBL: 10, #compiler specific, assume 10 since binja does not provide information on this unlike IDA (TODO maybe extract from type libraries? there are long double types in those sometimes)
    FloatFlags.BTMT_SPECFLT: 2, #depends on use_tbyte() in IDA otherwise 2 - likely not used for lumina
}

basetype_mapping = {
    BaseTypes.BT_VOID: lambda *_: Type.void(),
    BaseTypes.BT_INT8: lambda tinfo, *_: Type.int(1, sign = not tinfo.typedef.flags == IntFlags.BTMT_USIGNED),  #default to signed unless unsigned is specified
    BaseTypes.BT_INT16: lambda tinfo, *_: Type.int(2, sign = not tinfo.typedef.flags == IntFlags.BTMT_USIGNED),
    BaseTypes.BT_INT32: lambda tinfo, *_: Type.int(4, sign = not tinfo.typedef.flags == IntFlags.BTMT_USIGNED),
    BaseTypes.BT_INT64: lambda tinfo, *_: Type.int(8, sign = not tinfo.typedef.flags == IntFlags.BTMT_USIGNED),
    BaseTypes.BT_INT128: lambda tinfo, *_: Type.int(16, sign = not tinfo.typedef.flags == IntFlags.BTMT_USIGNED),
    BaseTypes.BT_INT: lambda tinfo, bv, *_: Type.int(bv.arch.default_int_size, sign = not tinfo.typedef.flags == IntFlags.BTMT_USIGNED),
    BaseTypes.BT_BOOL: lambda *_: Type.bool(),
    BaseTypes.BT_FLOAT: lambda tinfo, *_: Type.float(float_width_mapping[tinfo.typedef.flags]),
    #complex types
    BaseTypes.BT_PTR: construct_ptr,
    BaseTypes.BT_ARRAY: construct_arr,
    BaseTypes.BT_FUNC: construct_func,
    BaseTypes.BT_COMPLEX: construct_cmplx,
    BaseTypes.BT_BITFIELD: construct_bitfield,
}


def construct_type(bv: BinaryView, tinfo: Container, names: Optional[List[str]] = None, nbytes: int = 0) -> Type:
    #trust nbytes more than type info coz sometimes its missing width (especially typedefs)
    return basetype_mapping[tinfo.typedef.basetype](tinfo, bv, names, nbytes)
