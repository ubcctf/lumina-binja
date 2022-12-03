from binaryninja import BinaryView, Function, BackgroundTask
from binaryninja.transform import Transform
from binaryninja.log import log_debug

import socket, itertools

from construct import *
from lumina_structs import *
from lumina_structs.metadata import *

from .sig.util import Sig, ARCH_MAPPING

#
# Push Functions
#

def extract_md(bv: BinaryView, func: Function, gen: Sig) -> dict:
    chunks = []

    #apply comments; theres no anterior/posterior/repeatable comments in binja - use MD_INSN_CMT is enough
    if func.comment:
        chunks.append({
            'type': MetadataType.MD_FUNC_CMT,
            'data': {'text': func.comment}})
            #TODO see if need unparsed
    
    if func.comments:
        chunks.append({
            'type': MetadataType.MD_INSN_CMT,
            'data': [{
                'offset': addr - func.start,
                'text': cmt} 
                for addr, cmt in func.comments.items()]})

    #TODO frame info and tinfo
    #OPREPRS as a concept doesnt really exist in binja afaik (coz all of the potential references are offsets regardless),
    #but might be helpful in defining data vars so parsing might be good

    if chunks: #only compute signature and returns something if has data
        sig, block, mask = gen.calc_func_metadata(func)

        return {
            "metadata": {
                "func_name": func.name,  #func name is automatically whatever it should be
                "func_size": len(block),
                "serialized_data": {
                    #TODO use construct instead of this workaround to get the byte length
                    "size": len(b''.join([MetadataType.build(c['type']) + Metadata.build(c['data'], code=c['type']) for c in chunks])),  
                    "chunks": chunks}},
            "signature": {
                "version": 1, 
                "signature": sig}}
    else:
        return None



def craft_push_md(bv: BinaryView, funcs: list[Function], task: BackgroundTask = None) -> dict:
    if task:
        task.progress = '[Lumina] Calculating binary checksum'

    with open(bv.file.original_filename, 'rb') as f:  #file mightve been patched in between pushes, so reread
        buf = f.read()

    progress = "[Lumina] Extracting function metadata ({count}/" + str(len(funcs)) + " functions)"
    push, eas = [], []
    for i, f in enumerate(funcs):
        md = extract_md(bv, f, ARCH_MAPPING[f.arch.name](bv))
        if md: #only apply if extracted useful data
            push.append(md)
            eas.append(f.start)
        if task:
            task.progress = progress.format(count=i)

    return {
        "field_0x10": 0, 
        "idb_filepath": bv.file.filename, 
        "input_filepath": bv.file.original_filename, 
        "input_md5": Transform['MD5'].encode(buf),
        "hostname": socket.gethostname(),
        "funcInfos": push,
        "funcEas": eas}  #seems like ida is offset by one???


#
# Pull Functions
#


#can return multiple queries coz binja supports multiple archs in one binary view unlike IDA
def craft_pull_md(bv: BinaryView, funcs: list[Function], task: BackgroundTask = None) -> list[dict]:
    #groupby needs the list to be sorted first
    k = lambda f: f.arch.name #sort and group according to arch
    groups = [[f for f in g[1]] for g in itertools.groupby(sorted(funcs, key=k), key=k)]

    mds = []

    for fs in groups:
        sigs = []
        i = 0
        progress = "[Lumina] Calculating function signatures ({count}/" + str(len(funcs)) + " functions)"
        for func in fs:
            #arch can change between funcs
            if task:
                task.progress = progress.format(count=i)
            sigs.append({'signature':ARCH_MAPPING[func.arch.name](bv).calc_func_metadata(func)[0]})
            i+=1

        #already grouped, the first one will have the same arch as the rest
        mds.append({'flags': 1 if fs[0].arch.address_size == 8 else 0, 
            'ukn_list':[0]*len(fs),
            'funcInfos':sigs})

    return mds



def apply_md(bv: BinaryView, func: Function, info: Container):
    #we don't really care about popularity atm, but it might be useful server side for sorting
    func.name = info.metadata.func_name
    #func size should be the same to be able to get the same signature, so no need to set
    for md in info.metadata.serialized_data.chunks:
        if md.type in [MetadataType.MD_INSN_CMT, MetadataType.MD_INSN_REPCMT]:
            for c in md.data:
                addr = func.start + c.offset
                func.set_comment_at(addr, c.text)
        elif md.type in [MetadataType.MD_FUNC_CMT, MetadataType.MD_FUNC_REPCMT]:
            func.comment = md.data.text
        elif md.type == MetadataType.MD_EXTRA_CMT:
            #TODO figure out how to use wrap_comment and see if it enables actual anterior/posterior comments
            for c in md.data:
                addr = func.start + c.offset
                #only | if is not empty string
                func.set_comment_at(addr, ' | '.join(filter(bool, [c.anterior, (cmt if (cmt:=func.get_comment_at(addr)) else ''), c.posterior])))
        else:
            #logger is likely already instantiated by client.py, we can just invoke it with the name now
            log_debug('Unimplemented metadata type ' + str(md.type) + ', skipping for now...', logger='Lumina')
