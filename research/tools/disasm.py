from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parent))
from pe_analyze import *
import capstone
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_INS_ADRP, ARM64_INS_ADD

def engine(pe):
    if pe.FILE_HEADER.Machine==0xaa64:
        md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
    elif pe.FILE_HEADER.Machine==0x8664:
        md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    else: raise ValueError(f'Machine {pe.FILE_HEADER.Machine:X} not handled')
    md.detail=True
    md.skipdata=True
    return md

name=sys.argv[1]; pe=load(name); base=pe.OPTIONAL_HEADER.ImageBase
print('Architecture',hex(pe.FILE_HEADER.Machine),'base',hex(base),flush=True)
symbol_file=root/'symbols'/f'{name}.json'
symbol_list=sorted(json.loads(symbol_file.read_text()),key=lambda x:x['rva']) if symbol_file.exists() else []

def nearest(rva):
    syms=[s for s in symbol_list if s['rva']<=rva and s['flags']&2]
    return syms[-1]['name'] if syms else '?'

md=engine(pe)
sym_names={s['rva']:s['name'] for s in symbol_list}
if sys.argv[2]=='range':
    rva=int(sys.argv[3],16); size=int(sys.argv[4],0) if len(sys.argv)>4 else 512
    for i in md.disasm(pe.get_data(rva,size),base+rva):
        note=''
        if i.id and i.mnemonic in ('bl','b') and i.operands[0].type==ARM64_OP_IMM:
            target=i.operands[0].imm-base
            note=' ; '+sym_names.get(target,'')
        print(f'{i.address-base:08X} {i.mnemonic:8} {i.op_str}{note}')
else:
    data=pe.__data__; targets={}
    for phrase in sys.argv[2:]:
        for encoding in ('utf-16-le','ascii'):
            encoded=phrase.encode(encoding)
            for match in re.finditer(re.escape(encoded),data):
                targets[base+pe.get_rva_from_offset(match.start())]=phrase
    print('String targets', {hex(k-base):v for k,v in targets.items()},flush=True)
    for section in pe.sections:
        if not section.Characteristics & 0x20000000: continue
        regs={}; recent=[]
        for i in md.disasm(section.get_data(),base+section.VirtualAddress):
            if i.id==0: continue
            ops=i.operands
            if pe.FILE_HEADER.Machine==0xaa64:
                if i.id==ARM64_INS_ADRP and len(ops)>1:
                    regs[ops[0].reg]=ops[1].imm
                elif i.id==ARM64_INS_ADD and len(ops)>2 and ops[2].type==ARM64_OP_IMM and ops[1].reg in regs:
                    addr=regs[ops[1].reg]+ops[2].imm
                    regs[ops[0].reg]=addr
                    if addr in targets:
                        print(f'XREF {targets[addr]} at {i.address-base:08X} in {nearest(i.address-base)}')
                        print('\n'.join(recent[-6:]))
                        print(f'{i.address-base:08X} {i.mnemonic} {i.op_str}')
            recent.append(f'{i.address-base:08X} {i.mnemonic} {i.op_str}')
            if len(recent)>7: recent.pop(0)
