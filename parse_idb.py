import argparse
import subprocess
import time

from os import getenv
from os.path import abspath
from os.path import dirname
from os.path import isfile
from os.path import join
from os import walk
from multiprocessing import Pool
import ntpath

IDA_PATH = getenv("IDA_PATH", "/home/liu/.wine/drive_c/IDA/idat64.exe")
IDA_PLUGIN = join(dirname(abspath(__file__)), 'ida_disasm.py')
REPO_PATH = dirname(dirname(dirname(abspath(__file__))))
LOG_PATH = "acfg_disasm_log.txt"


def do_ida_python(parameters):
    idb_rel_path, output_dir, idb_path = parameters
    filename = idb_path.split('/')[-1][:-4]
    cmd = ['wine',
           IDA_PATH,
           '-A',
           '-Llog/{}.log'.format(filename),
           '-S{}'.format(IDA_PLUGIN),
           '-Odisasm:{}:{}'.format(
               idb_rel_path,
               output_dir),
           idb_path]

    print("[D] cmd: {}".format(cmd))

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    if proc.returncode == 0:
        print("[D] {}: success".format(idb_path))
    else:
        print("[!] Error in {} (returncode={})".format(idb_path, proc.returncode))


def main():
    parser = argparse.ArgumentParser(description="generate db.")
    parser.add_argument("--idb-folder", type=str, default='/home/liu/project/ida_script/idb_t')
    parser.add_argument("--output-dir", type=str, default='/home/liu/project/ida_script/extract')
    args = parser.parse_args()
    """Call ida_disasm.py IDA script."""
    try:
        if not isfile(IDA_PATH):
            print("[!] Error: IDA_PATH:{} not valid".format(IDA_PATH))
            print("Use 'export IDA_PATH=/full/path/to/idat64'")
            return

        print("[D] Output directory: {}".format(args.output_dir))

        idb_rel_path_list = []
        output_dir_list = []
        idb_path_list = []

        success_cnt, error_cnt = 0, 0
        start_time = time.time()
        for root, _, files in walk(args.idb_folder):
            for fname in files:
                if fname.endswith('.i64'):
                    idb_rel_path = fname
                    # print("\n[D] Processing: {}".format(idb_rel_path))

                    # Convert the relative path into a full path
                    idb_path = join(root, idb_rel_path)
                    # print("[D] IDB full path: {}".format(idb_path))

                    if not isfile(idb_path):
                        print("[!] Error: {} does not exist".format(idb_path))
                        continue
                    out_name = ntpath.basename(idb_path.replace(".i64", "_acfg_disasm.json"))

                    output_path = join(args.output_dir, out_name)
                    if isfile(output_path):
                        continue
                    idb_rel_path_list.append(idb_rel_path)
                    output_dir_list.append(args.output_dir)
                    idb_path_list.append(idb_path)

        print(len(idb_rel_path_list))
        multi_num = 16
        pool = Pool(processes=multi_num)
        zip_args = zip(idb_rel_path_list, output_dir_list, idb_path_list)
        pool.map(do_ida_python, zip_args)
        pool.close()
        pool.join()

        end_time = time.time()
        print("[D] Elapsed time: {}".format(end_time - start_time))
        with open(LOG_PATH, "a+") as f_out:
            f_out.write("elapsed_time: {}\n".format(end_time - start_time))

        print("\n# IDBs correctly processed: {}".format(success_cnt))
        print("# IDBs error: {}".format(error_cnt))

    except Exception as e:
        print("[!] Exception in cli_acfg_disasm\n{}".format(e))


if __name__ == '__main__':
    main()
