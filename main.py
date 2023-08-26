import pickle

if __name__ == '__main__':
    with open('./extract/a2ps-4.14_clang-7.0_mips_64_Ofast_fixnt_extract2.pkl', 'rb') as f:
        pkl = pickle.load(f)

    print('helo')
