import argparse
import pickle
import os


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
            # step1 parse const into specific token 

            # step2 parse function name (local, dyn_link, func)
            ins_list = ins_str.split()
            opcode = ins_list[0]
            if opcode.contain('call'):
                call_addr = ins_list[1]
                callee_func = func_dict[call_addr]
                if callee_func in dyn_func_list:
                    callee_func_token = 'outter_func_call'
                else:
                    callee_func_token = 'inner_func_call'
                res_block_asm_list.append(f'{opcode} {callee_func_token}')
                continue
            res_block_asm_list.append(ins_str)
    return res_dict


def process_asm_arm(basic_blocks, dyn_func_list):
    pass

def process_asm_mips(basic_blocks, dyn_func_list):
    pass


def gen_block_pair_for_pretrain(arch, func_dict, dyn_func_list):
    for func_addr, func_data in func_dict.items():
        func_name = func_data['name']
        edge_list = func_data['edges']
        basic_blocks = func_data['basic_blocks']

        if func_name in dyn_func_list:
            continue

        if arch.contains('x86'):
            asm_dict = process_asm_x86(basic_blocks, func_dict, dyn_func_list)
        elif arch.contains('arm'):
            asm_dict = process_asm_arm(basic_blocks, func_dict, dyn_func_list)
        elif arch.contains('mips'):
           asm_dict = process_asm_mips(basic_blocks, func_dict, dyn_func_list)
        else:
            print(f'[error] unknown arch: {arch}')
            return
        

    pass


def process_all_pkl(data_dir):
    pkl_file_list = get_all_pkl_file(data_dir)

    pkl_file_len = len(pkl_file_list)

    for file in pkl_file_list:
        binary_name = '-'.join(file.split('-')[:-1])
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





