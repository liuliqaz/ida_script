import argparse
import subprocess

from os import getenv
from os import makedirs
from os import mkdir
from os import walk
from os.path import isdir
from os.path import isfile
from os.path import join
from os.path import relpath
from os.path import samefile
from os import remove
import multiprocessing
from multiprocessing import Pool

IDA_PATH = getenv("IDA_PATH", "/home/liu/.wine/drive_c/IDA/idat64.exe")
LOG_PATH = "generate_idbs_log.txt"


def export_idb(input_output_path):
    input_path, output_path = input_output_path
    print(input_path, output_path)
    """Launch IDA Pro and export the IDB. Inner function."""
    try:
        print("Export IDB for {}".format(input_path))
        ida_output = str(subprocess.check_output([
            "wine",
            IDA_PATH,
            "-Llog/{}".format(LOG_PATH),  # name of the log file. "Append mode"
            "-a-",  # enables auto analysis
            "-B",  # batch mode. IDA will generate .IDB and .ASM files
            "-o{}".format(output_path),
            input_path
        ]))

        if not isfile(output_path):
            print("[!] Error: file {} not found".format(output_path))
            print(ida_output)
            return False

        return True

    except Exception as e:
        print("[!] Exception in export_idb\n{}".format(e))


def directory_walk(input_folder, output_folder, num_jobs):
    """Walk the directory tree and launch IDA Pro."""
    try:
        print("[D] input_folder: {}".format(input_folder))
        print("[D] output_folder: {}".format(output_folder))

        export_error, export_success = 0, 0
        if not input_folder or not output_folder:
            print("[!] Error: missing input/output folder")
            return

        if not isdir(output_folder):
            mkdir(output_folder)

        input_path_list = []
        output_path_list = []
        for root, _, files in walk(input_folder):
            for fname in files:
                if fname.endswith(".log") or fname.endswith(".idb") or fname.endswith(".i64") or fname.endswith(".tar"):
                    continue

                tmp_out = output_folder
                if not samefile(root, input_folder):
                    tmp_out = join(output_folder, relpath(root, input_folder))
                    if not isdir(tmp_out):
                        makedirs(tmp_out)

                input_path = join(root, fname)
                del_ext = ['.id0', '.id1', '.id2', '.nam', '.til']
                for ext in del_ext:
                    del_path = join(tmp_out, fname + ext)
                    if isfile(del_path):
                        remove(del_path)
                output_path = join(tmp_out, fname + ".i64")
                if isfile(output_path):
                    print("[D] {} already exists".format(output_path))
                    continue
                input_path_list.append(input_path)
                output_path_list.append(output_path)
        
        global pool_sem
        print(len(input_path_list))
        pool_sem = multiprocessing.BoundedSemaphore(value=1)

        pool = Pool(processes=num_jobs)
        input_output_list = zip(input_path_list, output_path_list)
        pool.map(export_idb, input_output_list)
        pool.close()
        pool.join()

        print("# IDBs correctly exported: {}".format(export_success))
        print("# IDBs error: {}".format(export_error))

    except Exception as e:
        print("[!] Exception in directory_walk\n{}".format(e))


def main():
    parser = argparse.ArgumentParser(description="generate db.")
    parser.add_argument("--bin-folder", type=str, default='/home/liu/project/ida_script/data')
    parser.add_argument("--idb-folder", type=str, default='/home/liu/project/ida_script/idb')
    parser.add_argument("--num-jobs", type=int, default=32)
    args = parser.parse_args()
    """Launch IDA Pro and export the IDBs."""
    if not isfile(IDA_PATH):
        print("[!] Error: IDA_PATH:{} not valid".format(IDA_PATH))
        print("Use 'export IDA_PATH=/full/path/to/idat64'")
        return
    
    bin_folder = args.bin_folder
    idb_folder = args.idb_folder
    num_jobs = args.num_jobs

    directory_walk(bin_folder, idb_folder, num_jobs)

    print("[Done]")
    return


if __name__ == "__main__":
    main()
