from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from collections import defaultdict
import os
import idc
import idautils
import idaapi
import pickle
import networkx as nx

# DATAROOT = "/home/liu/project/ida_script/dataset/"
DATAROOT = "./dataset/"
# SAVEROOT = "/home/liu/project/ida_script/extract/"
SAVEROOT = "./extract/"


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

    def get_asm(self, func):
        instGenerator = idautils.FuncItems(func)
        asm_list = []
        for inst in instGenerator:
            asm_list.append(idc.GetDisasm(inst))
        return asm_list

    def get_rawbytes(self, func):
        instGenerator = idautils.FuncItems(func)
        rawbytes_list = b""
        for inst in instGenerator:
            rawbytes_list += idc.get_bytes(inst, idc.get_item_size(inst))
        return rawbytes_list

    def get_cfg(self, func):

        def get_attr(block, func_addr_set):
            asm,raw=[],b""
            curr_addr = block.start_ea
            if curr_addr not in func_addr_set:
                return -1
            # print(f"[*] cur: {hex(curr_addr)}, block_end: {hex(block.end_ea)}")
            while curr_addr <= block.end_ea:
                asm.append(idc.GetDisasm(curr_addr))
                raw+=idc.get_bytes(curr_addr, idc.get_item_size(curr_addr))
                curr_addr = idc.next_head(curr_addr, block.end_ea)
            return asm, raw

        nx_graph = nx.DiGraph()
        flowchart = idaapi.FlowChart(idaapi.get_func(func), flags=idaapi.FC_PREDS)
        func_addr_set = set([addr for addr in idautils.FuncItems(func)])
        for block in flowchart:
            # Make sure all nodes are added (including edge-less nodes)
            attr = get_attr(block, func_addr_set)
            if attr == -1:
                continue
            nx_graph.add_node(block.start_ea, asm=attr[0], raw=attr[1])
            # print(f"[*] bb: {hex(block.start_ea)}, asm: {attr[0]}")
            for pred in block.preds():
                if pred.start_ea not in func_addr_set:
                    continue
                nx_graph.add_edge(pred.start_ea, block.start_ea)
            for succ in block.succs():
                if succ.start_ea not in func_addr_set:
                    continue
                nx_graph.add_edge(block.start_ea, succ.start_ea)
        return nx_graph  

    def extract_all(self):
        for func in idautils.Functions():
            if idc.get_segm_name(func) in ['.plt','extern','.init','.fini']:
                continue
            print("[+] %s" % idc.get_func_name(func))
            asm_list = self.get_asm(func)
            rawbytes_list = self.get_rawbytes(func)
            cfg = self.get_cfg(func)
            yield (self.addr2name[func], func, asm_list, rawbytes_list, cfg)


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

    save_dict = defaultdict(lambda: list)
    save_path = os.path.join(SAVEROOT, file_name + '_extract.pkl')

    print(f'[save_path]{save_path}')

    with open(save_path, 'wb') as f:
        for func_name, func, asm_list, rawbytes_list, cfg in binay_data.extract_all():
            save_dict[func_name] = [func_name, func, asm_list, rawbytes_list, cfg]
        save_dict['dyn_func_list'] = binay_data.dyn_funcs
        pickle.dump(dict(save_dict), f)
    
    idc.qexit(0)
