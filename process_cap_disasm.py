from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from collections import defaultdict, namedtuple
import os
import idc
import idautils
import idaapi
import pickle
import networkx as nx
from capstone import *
import base64
# import numpy as np
import json

# DATAROOT = "/home/liu/project/ida_script/dataset/"
DATAROOT = "./dataset/"
# SAVEROOT = "/home/liu/project/ida_script/extract/"
SAVEROOT = "./extract/"


BasicBlock = namedtuple('BasicBlock', ['va', 'size', 'succs', 'preds'])


def convert_procname_to_str(procname, bitness):
    """Convert the arch and bitness to a std. format."""
    if procname == 'mipsb' or procname == 'mipsl':
        return "mips-{}".format(bitness)
    if procname == "arm":
        return "arm-{}".format(bitness)
    if "pc" in procname:
        return "x86-{}".format(bitness)
    raise RuntimeError(
        "[!] Arch not supported ({}, {})".format(
            procname, bitness))

def get_bitness():
    """Return 32/64 according to the binary bitness."""
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        return 64
    elif info.is_32bit():
        return 32


def initialize_capstone(procname, bitness):
    """
    Initialize the Capstone disassembler.

    Original code from Willi Ballenthin (Apache License 2.0):
    https://github.com/williballenthin/python-idb/blob/
    2de7df8356ee2d2a96a795343e59848c1b4cb45b/idb/idapython.py#L874
    """
    md = None
    prefix = "UNK_"

    # WARNING: mipsl mode not supported here
    if procname == 'mipsb':
        prefix = "M_"
        if bitness == 32:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
        if bitness == 64:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)

    if procname == 'mipsl':
        prefix = "M_"
        if bitness == 32:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
        if bitness == 64:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)

    if procname == "arm":
        prefix = "A_"
        if bitness == 32:
            # WARNING: THUMB mode not supported here
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        if bitness == 64:
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    if "pc" in procname:
        prefix = "X_"
        if bitness == 32:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        if bitness == 64:
            md = Cs(CS_ARCH_X86, CS_MODE_64)

    if md is None:
        raise RuntimeError(
            "Capstone initialization failure ({}, {})".format(
                procname, bitness))

    # Set detail to True to get the operand detailed info
    md.detail = True
    return md, prefix


def get_basic_blocks(fva):
    """Return the list of BasicBlock for a given function."""
    bb_list = list()
    func = idaapi.get_func(fva)
    if func is None:
        return bb_list
    for bb in idaapi.FlowChart(func):
        # WARNING: this function DOES NOT include the BBs with size 0
        # This is different from what IDA_features does.
        # if bb.end_ea - bb.start_ea > 0:
        if bb.end_ea - bb.start_ea > 0:
            bb_list.append(
                BasicBlock(
                    va = bb.start_ea,
                    size = bb.end_ea - bb.start_ea,
                    succs = bb.succs(),
                    preds = bb.preds()
                )
            )
    return bb_list


def capstone_disassembly(md, ea, size, prefix):
    """Return the BB (normalized) disassembly, with mnemonics and BB heads."""
    try:
        bb_heads, bb_mnems, bb_disasm, bb_norm = list(), list(), list(), list()

        # Iterate over each instruction in the BB
        for i_inst in md.disasm(idc.get_bytes(ea, size), ea):
            # Get the address
            bb_heads.append(i_inst.address)
            # Get the mnemonic
            bb_mnems.append(i_inst.mnemonic)
            # Get the disasm
            bb_disasm.append("{} {}".format(i_inst.mnemonic, i_inst.op_str))

            # Compute the normalized code. Ignore the prefix.
            # cinst = prefix + i_inst.mnemonic
            cinst = i_inst.mnemonic

            # Iterate over the operands
            for op in i_inst.operands:

                # Type register
                if (op.type == 1):
                    cinst = cinst + " " + i_inst.reg_name(op.reg)

                # Type immediate
                elif (op.type == 2):
                    imm = int(op.imm)
                    if (-int(5000) <= imm <= int(5000)):
                        cinst += " " + str(hex(op.imm))
                    else:
                        cinst += " " + str('HIMM')

                # Type memory
                elif (op.type == 3):
                    # If the base register is zero, convert to "MEM"
                    if (op.mem.base == 0):
                        cinst += " " + str("[MEM]")
                    else:
                        # Scale not available, e.g. for ARM
                        if not hasattr(op.mem, 'scale'):
                            cinst += " " + "[{}+{}]".format(
                                str(i_inst.reg_name(op.mem.base)),
                                str(op.mem.disp))
                        else:
                            cinst += " " + "[{}*{}+{}]".format(
                                str(i_inst.reg_name(op.mem.base)),
                                str(op.mem.scale),
                                str(op.mem.disp))

                if (len(i_inst.operands) > 1):
                    cinst += ","

            # Make output looks better
            cinst = cinst.replace("*1+", "+")
            cinst = cinst.replace("+-", "-")

            if "," in cinst:
                cinst = cinst[:-1]
            cinst = cinst.replace(" ", "_").lower()
            bb_norm.append(str(cinst))

        return bb_heads, bb_mnems, bb_disasm, bb_norm

    except Exception as e:
        print("[!] Capstone exception", e)
        return list(), list(), list(), list()


def get_bb_disasm(bb, md, prefix):
    """Return the (nomalized) disassembly for a BasicBlock."""
    b64_bytes = base64.b64encode(idc.get_bytes(bb.va, bb.size))
    b64_bytes = str(b64_bytes, encoding='utf-8')
    bb_heads, bb_mnems, bb_disasm, bb_norm = capstone_disassembly(md, bb.va, bb.size, prefix)
    return b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm


class Binarybase(object):
    def __init__(self, file_path):
        self.file_path = file_path
        assert os.path.exists(file_path), f'{file_path} not exists'
        self.addr2name, self.dyn_funcs = self.extract_addr2name(self.file_path)

    def get_func_name(self, name, functions):
        if name not in functions:
            return name
        i = 0
        while True:
            new_name = name+'_'+str(i)
            if new_name not in functions:
                return new_name
            i += 1

    def scan_section(self, functions, section):
        """
        Function to extract function names from a shared library file.
        """
        if not section or not isinstance(section, SymbolTableSection) or section['sh_entsize'] == 0:
            return 0

        count = 0
        for nsym, symbol in enumerate(section.iter_symbols()):
            if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] != 'SHN_UNDEF':
                func = symbol.name
                name = self.get_func_name(func, functions)
                if not name in functions:
                    functions[name] = {}
                functions[name]['begin'] = symbol.entry['st_value']

    def extract_addr2name(self, path):
        functions = {}
        dyn_funcs = []
        with open(path, 'rb') as stream:
            elffile = ELFFile(stream)
            self.scan_section(functions, elffile.get_section_by_name('.symtab'))
            self.scan_section(functions, elffile.get_section_by_name('.dynsym'))
            dyn_funcs = self.get_dynsym_func_list(elffile.get_section_by_name('.dynsym'))
            addr2name = {func['begin']: name for (name, func) in functions.items()}
        return defaultdict(lambda: -1, addr2name), dyn_funcs
    
    def get_dynsym_func_list(self, dyn_sym):
        functions = []
        if dyn_sym is None:
            return []
        for sym in dyn_sym.iter_symbols():
            if sym.entry.st_info['type'] == 'STT_FUNC' and sym.entry['st_shndx'] == 'SHN_UNDEF':
                func_name = sym.name
                if func_name not in functions:
                    functions.append(func_name)
        return functions


class BinaryData(Binarybase):
    def __init__(self, unstrip_path):
        super(BinaryData, self).__init__(unstrip_path)
        self.fix_up()
    
    def fix_up(self):
        for addr in self.addr2name:
            # incase some functions' instructions are not recognized by IDA
            idc.create_insn(addr)  
            idc.add_func(addr) 
    
    def run_disasm(self, file_name, save_path):
        procname = idaapi.get_inf_structure().procName.lower()
        bitness = get_bitness()
        md, prefix = initialize_capstone(procname, bitness)

        output_dict = dict()
        output_dict[file_name] = dict()
        output_dict[file_name]['arch'] = convert_procname_to_str(procname, bitness)
        for fva in idautils.Functions():
            try:
                func_name = self.addr2name[fva]
                func_addr_set = set([addr for addr in idautils.FuncItems(fva)])
                if func_name == -1:
                    func_name = idaapi.get_func_name(fva)
                    print(f'[!]unk func name:{func_name}')
                else:
                    print(f'[+]func name:{func_name}')
                nx_graph = nx.DiGraph()
                nodes_set, edges_set = set(), set()
                bbs_dict = dict()
                for bb in get_basic_blocks(fva):
                    if bb.size:
                        b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm = get_bb_disasm(bb, md, prefix)
                        bbs_dict[bb.va] = {
                            'b64_bytes': b64_bytes,
                            'bb_disasm': bb_disasm,
                        }
                    else:
                        bbs_dict[bb.va] = {
                            'b64_bytes': "",
                            'bb_disasm': list(),
                        }
                        continue
                    
                    nx_graph.add_node(bb.va)
                    nodes_set.add(bb.va)
                    
                    for pred in bb.preds:
                        if pred.start_ea not in func_addr_set:
                            continue
                        nx_graph.add_edge(pred.start_ea, bb.va)
                        edges_set.add((pred.start_ea, bb.va))
                    
                    for succ in bb.succs:
                        if succ.start_ea not in func_addr_set:
                            continue
                        nx_graph.add_edge(bb.va, succ.start_ea)
                        edges_set.add((bb.va, succ.start_ea))

                    # for dest_ea in bb.succs:
                    #     nx_graph.add_edge(bb.va, dest_ea)
                    #     edges_set.add((bb.va, dest_ea))
                    #     if bb.size:
                    #         b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm = get_bb_disasm(bb, md, prefix)
                    #         bbs_dict[bb.va] = {
                    #             'b64_bytes': b64_bytes,
                    #             'bb_disasm': bb_disasm,
                    #         }
                    #     else:
                    #         bbs_dict[bb.va] = {
                    #             'b64_bytes': "",
                    #             'bb_disasm': list(),
                    #         }
                # adj_matrix = np.array(nx.to_numpy_matrix(nx_graph))
                func_dict = {
                    'name': func_name,
                    'nodes': list(nodes_set),
                    'edges': list(edges_set),
                    'basic_blocks': bbs_dict,
                    # 'adj_matrix': json.dumps(adj_matrix.tolist())
                    'netx': nx_graph
                }
                output_dict[file_name][hex(fva)] = func_dict
                    
            except Exception as e:
                print("[!] Exception: skipping function fva: %d" % fva)
                print(e)

        output_dict[file_name]['dyn_func_list'] = self.dyn_funcs
        
        # with open(save_path+'.json', "w") as f_out:
        #     json.dump(output_dict, f_out)

        with open(save_path, 'wb') as f:            
            pickle.dump(output_dict, f)


if __name__ == '__main__':
    assert os.path.exists(DATAROOT)
    assert os.path.exists(SAVEROOT)

    binary_abs_path = idc.get_input_file_path()
    file_name = binary_abs_path.split('\\')[-1]
    file_path = os.path.join(DATAROOT, file_name)
    idc.auto_wait()

    print(f'[DATAROOT]{DATAROOT}')
    print(f'[file_name]{file_name}')
    print(f'[file_path]{file_path}')

    binay_data = BinaryData(file_path)

    save_path = os.path.join(SAVEROOT, file_name + '_extract2.pkl')

    print(f'[save_path]{save_path}')

    binay_data.run_disasm(file_name, save_path)

    idc.qexit(0)
