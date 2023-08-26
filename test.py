import pickle

if __name__ == '__main__':
    file_arm = './extract/a2ps-4.14_clang-7.0_arm_32_O1_a2ps_extract.pkl' # arm
    file_x86 = './extract/a2ps-4.14_clang-7.0_x86_32_O0_a2ps_extract.pkl' # x86
    file_mips = './extract/nettle-3.8.1_gcc-8.2.0_mips_64_O1_nettle-hash_extract.pkl' # mips

    file_arm_2 = './extract/a2ps-4.14_clang-7.0_arm_32_O1_a2ps_extract2.pkl' # arm
    file_x86_2 = './extract/a2ps-4.14_clang-7.0_x86_32_O0_a2ps_extract2.pkl' # x86
    file_mips_2 = './extract/nettle-3.8.1_gcc-8.2.0_mips_64_O1_nettle-hash_extract2.pkl' # mips

    with open(file_arm, 'rb') as f:
        pkl_arm = pickle.load(f)

    with open(file_arm_2, 'rb') as f:
        pkl_arm_2 = pickle.load(f)
    
    with open(file_mips, 'rb') as f:
        pkl_mips = pickle.load(f)
    
    with open(file_mips_2, 'rb') as f:
        pkl_mips_2 = pickle.load(f)
    
    with open(file_x86, 'rb') as f:
        pkl_x86 = pickle.load(f)

    with open(file_x86_2, 'rb') as f:
        pkl_x86_2 = pickle.load(f)

    print('done')
