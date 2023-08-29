import argparse
import pickle
import os
import re


arm_branch_opcode = ['beq', 'bne', 'bcs', 'bcc', 'bmi', 'bpl', 
                     'bvs', 'bvc', 'bhi', 'bls', 'bge', 'blt', 
                     'bgt', 'ble', 'bal']
mips_branch_opcode = ['j', 'jr', 'b', 
                      'beq', 'bne', 'beqz', 'bnez', 
                      'bge', 'bgeu', 'bgez', 
                      'bgt', 'bgtu', 'bgtz',
                      'ble', 'bleu', 'blez'
                      'blt', 'bltu', 'bltz',
                      'bltzal', 'bgezal']


def load_pickle(file):
    with open(file, 'rb') as f:
        return pickle.load(f)


def get_all_pkl_file(data_dir):
    proj_list = []
    for file_name in os.listdir(data_dir):
        if not file_name.endswith(''):
            continue
        pickle_path = os.path.join(data_dir, file_name)
        if os.path.isdir(pickle_path):
            proj_list.append(file_name)
    return proj_list


def process_asm_x86(basic_blocks, func_dict, dyn_func_list):
    res_dict = dict()
    for block_addr, block_data in basic_blocks.items():
        block_asm_list = block_data['bb_disasm']
        res_block_asm_list = []
        for ins_str in block_asm_list:
            ins_list = ins_str.split()
            opcode = ins_list[0]
            # step1 parse jmp ins and parse target addr into DEC 
            if opcode[0] == 'j':
                jmp_addr = ins_list[1]
                jmp_addr_dec = int(jmp_addr, base=16)
                res_block_asm_list.append(f'{opcode} {jmp_addr_dec}')
                continue
            # step2 parse function call (stc_link, dyn_link, func)
            if 'call' in opcode:
                call_addr = ins_list[1]
                if call_addr not in func_dict:
                    callee_func_token = 'subxx'
                elif func_dict[call_addr]['name'] in dyn_func_list:
                    callee_func_token = 'outter_func_call'
                else:
                    callee_func_token = 'inner_func_call'
                res_block_asm_list.append(f'{opcode} {callee_func_token}')
                continue
            # step3 parse const into specific token
            tmp_ins_str = ins_str
            re_const_hex = r'(0x[0-9a-fA-F]+)'
            match_const_hex = re.findall(re_const_hex, tmp_ins_str, re.I)
            if match_const_hex:
                hex_regex = re.compile(re_const_hex)
                tmp_ins_str = hex_regex.sub('const_hex', tmp_ins_str)
            re_const_dec = r'\b(?!r[0-9])\d+\b'
            match_const_dec = re.findall(re_const_dec, tmp_ins_str, re.I)
            if match_const_dec:
                dec_regex = re.compile(re_const_dec)
                tmp_ins_str = dec_regex.sub('const_dec', tmp_ins_str)
            res_block_asm_list.append(tmp_ins_str)
        res_dict[int(block_addr)] = res_block_asm_list
    return res_dict


def process_asm_arm(basic_blocks, func_dict, dyn_func_list):
    res_dict = dict()
    for block_addr, block_data in basic_blocks.items():
        block_asm_list = block_data['bb_disasm']
        res_block_asm_list = []
        for ins_str in block_asm_list:
            ins_list = ins_str.split()
            opcode = ins_list[0]
            # step1 parse brach instruction, in case  jump addr tokenized
            if opcode[0] == 'b' and opcode != 'bl':
                jmp_addr = ins_list[1]
                jmp_addr_dec = int(jmp_addr, base=16)
                res_block_asm_list.append(f'{opcode} {jmp_addr_dec}')
                continue
            # step1 parse function call (stc_link, dyn_link, func)
            if opcode == 'bl':
                call_addr = ins_list[1][1:]
                if call_addr not in func_dict:
                    callee_func_token = 'subxxx'
                elif func_dict[call_addr]['name'] in dyn_func_list:
                    callee_func_token = 'outter_func_call'
                else:
                    callee_func_token = 'inner_func_call'
                res_block_asm_list.append(f'{opcode} {callee_func_token}')
                continue
            # step2 parse const into specific token
            tmp_ins_str = ins_str
            re_const_hex = r'(#0x[0-9a-fA-F]+)'
            match_const_hex = re.findall(re_const_hex, tmp_ins_str, re.I)
            if match_const_hex:
                hex_regex = re.compile(re_const_hex)
                tmp_ins_str = hex_regex.sub('const_hex', tmp_ins_str)
            re_const_dec = r'(#[0-9]+)'
            match_const_dec = re.findall(re_const_dec, tmp_ins_str, re.I)
            if match_const_dec:
                dec_regex = re.compile(re_const_dec)
                tmp_ins_str = dec_regex.sub('const_dec', tmp_ins_str)
            res_block_asm_list.append(tmp_ins_str)
        res_dict[int(block_addr)] = res_block_asm_list
    return res_dict


def process_asm_mips(basic_blocks, func_dict, dyn_func_list):
    res_dict = dict()
    for block_addr, block_data in basic_blocks.items():
        block_asm_list = block_data['bb_disasm']
        res_block_asm_list = []
        for ins_str in block_asm_list:
            ins_list = ins_str.split()
            opcode = ins_list[0]
            # step1 parse brach instruction, for mips, some brach instructions have more than one oprand
            if (opcode[0] == 'b' and opcode != 'bal') or (opcode == 'j'):
                jmp_addr = ins_list[-1]
                jmp_addr_dec = int(jmp_addr, base=16)
                new_ins_list = [i for i in ins_list]
                new_ins_list[-1] = str(jmp_addr_dec)
                res_block_asm_list.append(' '.join(new_ins_list))
                continue
            # step2 parse function call (stc_link, dyn_link, func)
            if opcode == 'jal' or opcode == 'bal':
                call_addr = ins_list[1]
                # [notion]sometimes bal is used for branch
                if call_addr not in func_dict:
                    if int(call_addr, base=16) in basic_blocks:
                        res_block_asm_list.append(ins_str)
                        continue
                    callee_func_token = 'subxxx'
                elif func_dict[call_addr]['name'] in dyn_func_list:
                    callee_func_token = 'outter_func_call'
                else:
                    callee_func_token = 'inner_func_call'
                res_block_asm_list.append(f'{opcode} {callee_func_token}')
                continue
            # step3 parse const into specific token
            tmp_ins_str = ins_str
            re_const_hex = r'(0x[0-9a-fA-F]+)'
            match_const_hex = re.findall(re_const_hex, tmp_ins_str, re.I)
            if match_const_hex:
                hex_regex = re.compile(re_const_hex)
                tmp_ins_str = hex_regex.sub('const_hex', tmp_ins_str)
            re_const_dec = r'\b(?!v[01]|a[0-3]|t[0-9]|s[0-8]|k[01])\d+\b'
            match_const_dec = re.findall(re_const_dec, tmp_ins_str, re.I)
            if match_const_dec:
                dec_regex = re.compile(re_const_dec)
                tmp_ins_str = dec_regex.sub('const_dec', tmp_ins_str)
            res_block_asm_list.append(tmp_ins_str)
        res_dict[int(block_addr)] = res_block_asm_list
    return res_dict


def gen_block_pair_for_pretrain(arch, func_dict, dyn_func_list):
    for func_addr, func_data in func_dict.items():
        func_name = func_data['name']
        edge_list = func_data['edges']
        node_list = func_data['nodes']
        basic_blocks = func_data['basic_blocks']

        if func_name in dyn_func_list:
            continue
        
        # step1 parse asm ins to token type
        if 'x86' in arch:
            asm_dict = process_asm_x86(basic_blocks, func_dict, dyn_func_list)
        elif 'arm' in arch:
            asm_dict = process_asm_arm(basic_blocks, func_dict, dyn_func_list)
        elif 'mips' in arch:
           asm_dict = process_asm_mips(basic_blocks, func_dict, dyn_func_list)
        else:
            print(f'[error] unknown arch: {arch}')
            return
        
        # step2 transfer asm blocks into pairs
        
    pass


def process_all_pkl(data_dir):
    pkl_file_list = get_all_pkl_file(data_dir)

    pkl_file_len = len(pkl_file_list)

    for file in pkl_file_list:
        binary_name = '_'.join(file.split('_')[:-1])
        pickle_data = load_pickle(file)
        func_dict = pickle_data[binary_name]['func_dict']
        arch = pickle_data[binary_name]['arch']
        dyn_func_list = pickle_data[binary_name]['dyn_func_list']

        gen_block_pair_for_pretrain(arch, func_dict, dyn_func_list)


def test_code():
    # test code
    file_arm_2 = './extract/a2ps-4.14_clang-7.0_arm_32_O1_a2ps_extract2.pkl' # arm
    file_x86_2 = './extract/a2ps-4.14_clang-7.0_x86_32_O0_a2ps_extract2.pkl' # x86
    file_mips_2 = './extract/nettle-3.8.1_gcc-8.2.0_mips_64_O1_nettle-hash_extract2.pkl' # mips

    file = file_mips_2
    file_name = file.split('/')[-1]
    binary_name = '_'.join(file_name.split('_')[:-1])
    pickle_data = load_pickle(file)
    func_dict = pickle_data[binary_name]['func_dict']
    arch = pickle_data[binary_name]['arch']
    dyn_func_list = pickle_data[binary_name]['dyn_func_list']

    gen_block_pair_for_pretrain(arch, func_dict, dyn_func_list)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="print pretrain dataset.")
    parser.add_argument("--input_path", type=str, default='mix')
    parser.add_argument("--output_path", type=str, default='/home/liu/bcsd/datasets/edge_gnn_datas/pretrain.txt')
    args = parser.parse_args()

    input_path = args.input_path
    output_path = args.output_path

    test_code()