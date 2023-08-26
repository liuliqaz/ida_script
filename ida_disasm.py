import base64
import idaapi
import idc
import idautils
import json
import ntpath
import os
import time

from capstone import *
from collections import namedtuple
import networkx as nx
# import numpy as np

BasicBlock = namedtuple('BasicBlock', ['va', 'size', 'succs'])


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
            bb_disasm.append("{} {}".format(
                i_inst.mnemonic,
                i_inst.op_str))

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
                    va=bb.start_ea,
                    size=bb.end_ea - bb.start_ea,
                    succs=[x.start_ea for x in bb.succs()]))
    return bb_list


def get_bb_disasm(bb, md, prefix):
    """Return the (nomalized) disassembly for a BasicBlock."""
    b64_bytes = base64.b64encode(idc.get_bytes(bb.va, bb.size))
    b64_bytes = str(b64_bytes, encoding='utf-8')
    bb_heads, bb_mnems, bb_disasm, bb_norm = \
        capstone_disassembly(md, bb.va, bb.size, prefix)
    return b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm


def run_disasm(idb_path, output_dir):
    """Disassemble each function. Extract the CFG. Save output to JSON."""
    print("[D] Processing: %s" % idb_path)

    # Create output directory if it does not exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    output_dict = dict()
    output_dict[idb_path] = dict()

    procname = idaapi.get_inf_structure().procName.lower()
    bitness = get_bitness()
    output_dict[idb_path]['arch'] = convert_procname_to_str(procname, bitness)
    md, prefix = initialize_capstone(procname, bitness)
    for fva in idautils.Functions():
        try:
            start_time = time.time()
            func_name = idaapi.get_func_name(fva)
            nx_graph = nx.DiGraph()
            nodes_set, edges_set = set(), set()
            bbs_dict = dict()
            for bb in get_basic_blocks(fva):
                # CFG
                nx_graph.add_node(bb.va)
                nodes_set.add(bb.va)
                for dest_ea in bb.succs:
                    nx_graph.add_edge(bb.va, dest_ea)
                    edges_set.add((bb.va, dest_ea))
                # BB-level features
                if bb.size:
                    b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm = \
                        get_bb_disasm(bb, md, prefix)
                    bbs_dict[bb.va] = {
                        # 'bb_len': bb.size,
                        'b64_bytes': b64_bytes,
                        # 'bb_heads': bb_heads,
                        # 'bb_mnems': bb_mnems,
                        'bb_disasm': bb_disasm,
                        # 'bb_norm': bb_norm
                    }
                else:
                    bbs_dict[bb.va] = {
                        # 'bb_len': bb.size,
                        'b64_bytes': "",
                        # 'bb_heads': list(),
                        # 'bb_mnems': list(),
                        'bb_disasm': list(),
                        # 'bb_norm': list()
                    }
            elapsed_time = time.time() - start_time
            # adj_matrix = np.array(nx.to_numpy_matrix(nx_graph))
            func_dict = {
                'name': func_name,
                'nodes': list(nodes_set),
                'edges': list(edges_set),
                'elapsed_time': elapsed_time,
                'basic_blocks': bbs_dict,
                # 'adj_matrix': json.dumps(adj_matrix.tolist())
            }
            output_dict[idb_path][hex(fva)] = func_dict

        except Exception as e:
            print("[!] Exception: skipping function fva: %d" % fva)
            print(e)

    out_name = ntpath.basename(idb_path.replace(".i64", "_acfg_disasm.json"))
    with open(os.path.join(output_dir, out_name), "w") as f_out:
        json.dump(output_dict, f_out)


if __name__ == '__main__':
    if not idaapi.get_plugin_options("disasm"):
        print("[!] -Odisasm option is missing")
        idc.qexit(1)
        # idc.Exit(1)

    plugin_options = idaapi.get_plugin_options("disasm").split(":")
    if len(plugin_options) != 2:
        print("[!] -Odisasm:IDB_PATH:OUTPUT_DIR is required")
        idc.qexit(1)
        # idc.Exit(1)

    idb_path = plugin_options[0]
    output_dir = plugin_options[1]

    print(f'[test_log]idb_path={idb_path}, output_dir={output_dir}')

    run_disasm(idb_path, output_dir)
    idc.qexit(0)
