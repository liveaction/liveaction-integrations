import csv
import os
import sys

def main(path: str):
    # check path validity
    if not os.path.exists(path):
        print("invalid path")
        return
    # read file and write needed columns to new local file
    with open("new_mappings.csv", "w") as w_f:
        w_f.write("Application,cl_eng_id,sel_id\n")
        with open(path, "r") as r_f:
            csvreader = csv.reader(r_f)
            first = True
            for row in csvreader:
                if first:
                    # skip headers
                    first = False
                    continue
                w_f.write(row[0]+","+row[3]+","+row[4]+"\n")


if __name__ == "__main__" and len(sys.argv) == 2:
    main(sys.argv[1])
    print("DONE")
else:
    print("Usage: `python3 gen_app_mappings.py path_to_csv_file")