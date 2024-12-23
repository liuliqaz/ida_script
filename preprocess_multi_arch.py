import argparse
import pickle
import os
import re
from tqdm import tqdm
import json
import pandas as pd
import random

SAVE_PATH = '/home/liu/bcsd/datasets/edge_gnn_datas/'
FILTER_CLANG = True
FILTER_64 = True

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
missed_ams_count = 0
rand_pair_block = 0.2

def pick_rand_idx(max_len):
    return random.randrange(max_len)

def is_hexadecimal(s):
    try:
        if s[0] == '#':
            s = s[1:]
        int(s, 16)
        return True
    except ValueError:
        return False

def load_pickle(file):
    with open(file, 'rb') as f:
        return pickle.load(f)


def dict_save_as_json(json_dict, output_path):
    json_str = json.dumps(json_dict)
    with open(output_path, 'w') as f:  
        f.write(json_str)


def dict_save_as_csv(csv_dict, output_path):
    df = pd.DataFrame(csv_dict)
    df.to_csv(output_path, index=False)


def get_all_pkl_file(data_dir):
    proj_list = []
    for file_name in os.listdir(data_dir):
        if not file_name.endswith('pkl'):
            continue
        pickle_path = os.path.join(data_dir, file_name)
        proj_list.append(pickle_path)
    return proj_list


def tokenize_bracket_comma(ins_str):
    ins_str = ins_str.replace('[', ' [ ')
    ins_str = ins_str.replace(']', ' ] ')
    ins_str = ins_str.replace('(', ' ( ')
    ins_str = ins_str.replace(')', ' ) ')
    ins_str = ins_str.replace('{', ' { ')
    ins_str = ins_str.replace('}', ' } ')
    ins_str = ins_str.replace('-', ' - ')
    ins_str = ins_str.replace(':', ' : ')
    ins_str = ins_str.replace('!', ' ! ')
    ins_str = ins_str.replace('*', ' * ')
    ins_str = ins_str.replace('+', ' + ')
    ins_str = ins_str.replace(',', '')
    ins_str = ' '.join(ins_str.strip().split())
    return ins_str


def process_asm_x86(basic_blocks, func_dict, dyn_func_list, func_name):
    res_dict = dict()
    for block_addr, block_data in basic_blocks.items():
        block_asm_list = block_data['bb_disasm']
        res_block_asm_list = []
        for ins_str in block_asm_list:
            ins_str = tokenize_bracket_comma(ins_str)
            ins_list = ins_str.split()
            opcode = ins_list[0]
            # step1 parse jmp ins and parse target addr into DEC 
            if opcode[0] == 'j' and is_hexadecimal(ins_list[-1]):
                jmp_addr = ins_list[-1]
                jmp_addr_dec = int(jmp_addr, base=16)
                res_block_asm_list.append(f'{opcode} jp_{jmp_addr_dec}')
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


def process_asm_arm(basic_blocks, func_dict, dyn_func_list, func_name):
    res_dict = dict()
    for block_addr, block_data in basic_blocks.items():
        block_asm_list = block_data['bb_disasm']
        res_block_asm_list = []
        for ins_str in block_asm_list:
            ins_str = tokenize_bracket_comma(ins_str)
            ins_str = ins_str.replace('#', '')
            ins_list = ins_str.split()
            opcode = ins_list[0]
            # step1 parse brach instruction, in case  jump addr tokenized
            if opcode[0] == 'b' and opcode != 'bl'and is_hexadecimal(ins_list[-1]):
                jmp_addr = ins_list[-1]
                jmp_addr_dec = int(jmp_addr, base=16)
                res_block_asm_list.append(f'{opcode} jp_{jmp_addr_dec}')
                continue
            # step1 parse function call (stc_link, dyn_link, func)
            if opcode == 'bl':
                call_addr = ins_list[1]
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


def process_asm_mips(basic_blocks, func_dict, dyn_func_list, func_name):
    res_dict = dict()
    for block_addr, block_data in basic_blocks.items():
        block_asm_list = block_data['bb_disasm']
        res_block_asm_list = []
        for ins_str in block_asm_list:
            ins_str = tokenize_bracket_comma(ins_str)
            ins_list = ins_str.split()
            opcode = ins_list[0]
            # step1 parse brach instruction, for mips, some brach instructions have more than one oprand
            if ((opcode[0] == 'b' and opcode != 'bal') or (opcode == 'j')) and is_hexadecimal(ins_list[-1]):
                jmp_addr = ins_list[-1]
                jmp_addr_dec = int(jmp_addr, base=16)
                new_ins_list = [i for i in ins_list]
                new_ins_list[-1] = 'jp_' + str(jmp_addr_dec)
                res_block_asm_list.append(' '.join(new_ins_list))
                continue
            # step2 parse function call (stc_link, dyn_link, func)
            if opcode == 'jal' or opcode == 'bal':
                call_addr = ins_list[1]
                # [notion]sometimes bal is used for branch
                if call_addr not in func_dict:
                    callee_func_token = 'subxxx'
                    if int(call_addr, base=16) in basic_blocks:
                        callee_func_token = 'jump_addr'
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


def gen_block_pair_for_pretrain(arch, func_dict, dyn_func_list, binary_name):
    func_map = dict()
    edge_pair_list = []
    for func_addr, func_data in func_dict.items():
        func_name = func_data['name']
        edge_list = func_data['edges']
        node_list = func_data['nodes']
        basic_blocks = func_data['basic_blocks']

        if func_name in dyn_func_list:
            continue
        
        # step1 parse asm ins to token type
        if 'x86' in arch:
            asm_dict = process_asm_x86(basic_blocks, func_dict, dyn_func_list, func_name)
        elif 'arm' in arch:
            asm_dict = process_asm_arm(basic_blocks, func_dict, dyn_func_list, func_name)
        elif 'mips' in arch:
           asm_dict = process_asm_mips(basic_blocks, func_dict, dyn_func_list, func_name)
        else:
            print(f'[error] unknown arch: {arch}')
            return
        
        # step2 transfer asm blocks into pairs
        for edge in edge_list:
            pred = asm_dict[edge[0]]
            succ = asm_dict[edge[1]]

            if len(pred) == 0 or len(succ) == 0:
                global missed_ams_count 
                missed_ams_count  += 1
                continue
            
            if 'mips' in arch and len(pred) > 1:
                jmp_ins = pred[-2]
            else:
                jmp_ins = pred[-1]
            jmp_ins_list = jmp_ins.split()
            jmp_op = jmp_ins_list[0]

            jp_pattern = r'jp_([0-9]*)'
            match_jump_id = re.search(jp_pattern, jmp_ins, re.I)
            if match_jump_id:
                jump_addr = int(match_jump_id.group(1))
                if jump_addr == edge[1]:
                    rela_token = f'[t_{jmp_op}]'
                else:
                    rela_token = f'[f_{jmp_op}]'
            else:
                rela_token = '[seq]'
            edge_pair_str = ' '.join(pred) + '\t' + rela_token + '\t' + ' '.join(succ) + '\n'
            edge_pair_str = re.sub(r'jp_[0-9]*', 'jump_addr', edge_pair_str)
            # edge_pair_str = edge_pair_str.replace(',', '')
            edge_pair_list.append(edge_pair_str)

        
        if func_name in func_map:
            func_map[func_name].append(func_addr)
        else:
            func_map[func_name] = [func_addr]
        func_dict[func_addr]['asm_dict'] = asm_dict
    
    # save processed asm code and pairs
    # with open()
        
    return func_map, edge_pair_list


def process_all_pkl(data_dir, target_write_file):
    pkl_file_list = get_all_pkl_file(data_dir)

    pkl_file_len = len(pkl_file_list)

    target_dict = dict()
    target_dict['train'] = []

    target_dict_without_rand = dict()
    target_dict_without_rand['train'] = []

    trace_idx = 0

    for file in tqdm(pkl_file_list):
        binary_name = '_'.join(file.split('/')[-1].split('_')[:-1])

        if FILTER_CLANG and 'clang' in binary_name.split('_')[1]:
            continue
        if FILTER_64 and binary_name.split('_')[-3] == '64':
            continue

        pickle_data = load_pickle(file)
        func_dict = pickle_data[binary_name]['func_dict']
        arch = pickle_data[binary_name]['arch']
        dyn_func_list = pickle_data[binary_name]['dyn_func_list']
        
        func_map, edge_pair_list = gen_block_pair_for_pretrain(arch, func_dict, dyn_func_list, binary_name)

        pickle_data[binary_name]['func_map'] = func_map

        for edge_pair in edge_pair_list:
            nodes = edge_pair.strip().split('\t')
            data_row = {
                'arch': arch,
                'rela': nodes[1],
                '0': nodes[0],
                '2': nodes[2],
            }
            global rand_pair_block
            if rand_pair_block > 0 and random.random() < rand_pair_block:
                rand_edge_idx = random.randrange(len(edge_pair_list))
                pair_idx = random.choice([0, 2])
                if rand_edge_idx == trace_idx:
                    rand_edge_idx = (rand_edge_idx + 1) % len(edge_pair_list)
                
                rand_node = edge_pair_list[rand_edge_idx].strip().split('\t')[pair_idx]
                data_row['rela'] = '[no_rela]'
                data_row[str(pair_idx)] = rand_node
            data_row['sep'] = len(data_row['0'].split())
            # data_row['sentence'] = data_row['0'] + ' [SEP] ' + data_row['2']
            # data_row.pop('0')
            # data_row.pop('2')
            target_dict['train'].append(data_row)

            target_dict_without_rand['train'].append(
                {
                    'arch': arch,
                    'sep': len(nodes[0].split()),
                    'sentence': ' '.join(nodes),
                }
            )

        trace_idx += 1

    # target_pairs_file_csv = os.path.join(SAVE_PATH, 'pretrain_with_rand_pair.csv')
    # dict_save_as_csv(target_dict, target_pairs_file_csv)

    target_pairs_file_json = os.path.join(SAVE_PATH, target_write_file)
    dict_save_as_json(target_dict, target_pairs_file_json)

    # target_whole_file_csv = os.path.join(SAVE_PATH, 'pretrain_without_rand_whole.csv')
    # dict_save_as_csv(target_dict_without_rand, target_whole_file_csv)

    # target_whole_file_json = os.path.join(SAVE_PATH, 'pretrain_without_rand_whole.txt')
    # dict_save_as_json(target_dict_without_rand, target_whole_file_json)



def test_code():
    # test code
    file_arm_2 = './extract/a2ps-4.14_clang-7.0_arm_32_O1_a2ps_extract2.pkl' # arm
    file_x86_2 = './extract/a2ps-4.14_clang-7.0_x86_32_O0_a2ps_extract2.pkl' # x86
    file_mips_2 = './extract/nettle-3.8.1_gcc-8.2.0_mips_64_O1_nettle-hash_extract2.pkl' # mips

    file = './extract/gmp-6.2.1_gcc-8.2.0_mips_64_Ofast_libgmp.so.10.4.1_extract2.pkl'
    file_name = file.split('/')[-1]
    binary_name = '_'.join(file_name.split('_')[:-1])
    pickle_data = load_pickle(file)
    func_dict = pickle_data[binary_name]['func_dict']
    arch = pickle_data[binary_name]['arch']
    dyn_func_list = pickle_data[binary_name]['dyn_func_list']

    func_map, edge_pair_list = gen_block_pair_for_pretrain(arch, func_dict, dyn_func_list, binary_name)

    print("done")



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="preprocess dataset & generate block pairs.")
    parser.add_argument("--input_path", type=str, default='/home/liu/bcsd/train_set_extract')
    parser.add_argument("--output_path", type=str, default='/home/liu/bcsd/datasets/edge_gnn_datas/pretrain.txt')
    args = parser.parse_args()

    input_path = args.input_path
    output_path = args.output_path

    # test_code()
    # input_path = './extract'
    output_path = 'pretrain_sep_without_clang64.txt'
    process_all_pkl(input_path, output_path)

    print('[missed asm]', missed_ams_count)
