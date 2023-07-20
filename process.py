from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from collections import defaultdict
import os


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
        dyn_funcs = {}
        with open(path, 'rb') as stream:
            elffile = ELFFile(stream)
            # self.scan_section(functions, elffile.get_section_by_name('.symtab'))
            # self.scan_section(functions, elffile.get_section_by_name('.dynsym'))
            self.scan_section(dyn_funcs, elffile.get_section_by_name('.symtab'))
            addr2name = {func['begin']: name for (name, func) in functions.items()}
        return defaultdict(lambda: -1, addr2name), dyn_funcs



if __name__ == '__main__':
    bin = Binarybase('./data/a2ps/a2ps-4.14_clang-7.0_arm_32_O0_a2ps')

    print('helo')
