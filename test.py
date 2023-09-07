import pickle
import re
import base64
import capstone
import json
from tqdm import tqdm
import wandb


def load_pickle(file):
    with open(file, 'rb') as f:
        return pickle.load(f)

def test_code():
    file = './extract/gmp-6.2.1_gcc-8.2.0_mips_64_Ofast_libgmp.so.10.4.1_extract2.pkl'
    file_name = file.split('/')[-1]
    binary_name = '_'.join(file_name.split('_')[:-1])
    pickle_data = load_pickle(file)
    func_dict = pickle_data[binary_name]['func_dict']
    arch = pickle_data[binary_name]['arch']
    dyn_func_list = pickle_data[binary_name]['dyn_func_list']


    func_name = '__gmpf_set_d_0'
    target_addr = '0x11710'
    target = func_dict[target_addr]['basic_blocks'][71504] #71504
    target_b64_str = target['b64_bytes']
    print(target_b64_str)
    # target_b64_str = 'PGwgRsiBmd8QAITcAgAFJP7/AiQBELAARWsgRgn4IAMEAAKuCAAC/g=='
    decoded_bytes = base64.b64decode(target_b64_str) 

    md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | capstone.CS_MODE_LITTLE_ENDIAN)
    # md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)  
    
    insns = md.disasm(decoded_bytes, 0x1000)

    for i in insns:  
        print(i.mnemonic, i.op_str)

    print("done")


def rm_comman(read_file, write_file):
    with open(read_file, 'r') as f:
        lines = f.readlines()
    
    new_lines = []
    for l in lines:
        new_l = l.replace(',', '')
        new_lines.append(new_l)
    
    with open(write_file, 'w') as f:
        f.writelines(new_lines)


if __name__ == '__main__':
    file_arm = './extract/a2ps-4.14_clang-7.0_arm_32_O1_a2ps_extract.pkl' # arm
    file_x86 = './extract/a2ps-4.14_clang-7.0_x86_32_O0_a2ps_extract.pkl' # x86
    file_mips = './extract/nettle-3.8.1_gcc-8.2.0_mips_64_O1_nettle-hash_extract.pkl' # mips

    file_arm_2 = './extract/a2ps-4.14_clang-7.0_arm_32_O1_a2ps_extract2.pkl' # arm
    file_x86_2 = './extract/a2ps-4.14_clang-7.0_x86_32_O0_a2ps_extract2.pkl' # x86
    file_mips_2 = './extract/nettle-3.8.1_gcc-8.2.0_mips_64_O1_nettle-hash_extract2.pkl' # mips

    # with open(file_arm, 'rb') as f:
    #     pkl_arm = pickle.load(f)

    # with open(file_arm_2, 'rb') as f:
    #     pkl_arm_2 = pickle.load(f)
    
    # with open(file_mips, 'rb') as f:
    #     pkl_mips = pickle.load(f)
    
    # with open(file_mips_2, 'rb') as f:
    #     pkl_mips_2 = pickle.load(f)
    
    # with open(file_x86, 'rb') as f:
    #     pkl_x86 = pickle.load(f)

    # with open(file_x86_2, 'rb') as f:
    #     pkl_x86_2 = pickle.load(f)

    # test_code()

    # rm_comman('/home/liu/bcsd/datasets/edge_gnn_datas/pretrain.txt', '/home/liu/bcsd/datasets/edge_gnn_datas/pretrain_00.txt')

    # read_file = '/home/liu/bcsd/datasets/edge_gnn_datas/pretrain_00.txt'
    # with open(read_file, 'r') as f:
    #     lines = f.readlines(100)

    print('done')

    wandb.login(key='82907381b3e1440b8a77e83a83bd6a264a14c7bc')
