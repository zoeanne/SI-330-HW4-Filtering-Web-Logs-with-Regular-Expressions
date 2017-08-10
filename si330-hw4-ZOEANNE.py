# -*- coding: utf-8 -*-
# !/usr/bin/python -tt
import re
import csv
from collections import defaultdict


def write_log_entries(filename, list_of_rows_to_write, fieldnames=["IP", "Ident", "Userid", "Timestamp", "Timezone", "HTTP_Request",
                                                "HTTP_Status", "HTTP_Duration", "HTTP_Referer", "Browser_Type"]):
    row_counter = 0
    with open(filename, 'w+', newline='') as f:
        row_writer = csv.DictWriter(f, delimiter='\t', quotechar='"', extrasaction='ignore',
                                    fieldnames = fieldnames)
        row_writer.writeheader()
        for row in list_of_rows_to_write:
            row_writer.writerow(row)
            row_counter += 1

    print("Wrote {} rows to {}".format(row_counter, filename))


def read_log_file(filename):
    """
    Input: the file name of the log file to process
    Output:  A two-element tuple with element 0 a list of valid rows, and element 1 a list of invalid rows
    """

    valid_entries = []
    invalid_entries = []

    with open(filename, 'r', newline='') as input_file:
        log_data_reader = csv.DictReader(input_file, delimiter='\t', quotechar='"', skipinitialspace=True,
                                         fieldnames=["IP", "Ident", "Userid", "Timestamp", "Timezone", "HTTP_Request",
                                                     "HTTP_Status", "HTTP_Duration", "HTTP_Referer", "Browser_Type"])
        for row in log_data_reader:
            not_a_valid_line = False

            if row['HTTP_Status'] != '200':
                not_a_valid_line = True
                if not_a_valid_line:
                    invalid_entries.append(row)
                    continue
            else:
                match = re.search(r"^\s*(GET|POST)\s*https?://([a-zA-Z]+[.])+([a-zA-Z]+)([/:][\S]*)?\s*(HTTP/1.0|HTTP/1[.]1)?$", row['HTTP_Request'])
                if match is None:
                    not_a_valid_line = True
                    if not_a_valid_line:
                        invalid_entries.append(row)
                else:
                    valid_entries.append(row)
                    row["Verb"] = match.group(1)
                    row["Version"] = match.group(5)
                    row["Top_Level_Domain"] = match.group(3)

    return (valid_entries, invalid_entries)


def main():
    valid_rows, invalid_rows = read_log_file('access_log.txt')

    write_log_entries('valid_access_log_ZOEANNE.txt', valid_rows)
    write_log_entries('invalid_access_log_ZOEANNE.txt', invalid_rows)

    write_log_entries('verbs_tlds_ZOEANNE.txt', valid_rows, fieldnames = ["Verb", "Top_Level_Domain", "Version"])


# This is boilerplate python code: it tells the interpreter to execute main() only
# if this module is being run as the main script by the interpreter, and
# not being imported as a module.
if __name__ == '__main__':
    main()
