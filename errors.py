import os
import sys
import subprocess
import traceback
import json
import argparse
import xml.etree.ElementTree as elemTree

parser = argparse.ArgumentParser()
parser.add_argument("-a", dest='ANALYZER_PATH', help='analyzer', required=True)
parser.add_argument("-t", dest='TARGET_SOURCE_PATH', help='target source', required=True)
parser.add_argument("-e", nargs='+', dest='ERROR_NAMES', help='error pattern in target source', required=True)
parser.add_argument("-r", nargs='+', dest="RULE_IDS", help='analyzers rule id')

option = parser.parse_args()


def collect_defect_from_source(source_file, defect_names):
    defects = []
    kinds = set()

    file_path = source_file
    with open(file_path, 'r') as sourcefile:
        try:
            lineno = 1
            for line in sourcefile.readlines():
                line = line.strip()
                if "ERROR:" in line:
                    kind = line[line.find('ERROR:')+6: line.rfind('*/')].strip()
                    kind = kind.upper().replace(' ', '')
                    if kind in defect_names:
                        print("[%s]%s[%d]" % (file_path, kind, lineno))
                        defects.append({'line': lineno, 'kind': kind})
                        kinds.add(kind)

                lineno += 1
        except:
            print("ERROR" + file_path)
            traceback.print_exc()

    return defects


def run_analyzer_and_collect_defect(ruleids, source_file_path, analyzer):
    ruleid_file_path = os.path.join(os.getcwd(), 'rules.ini')
    output_file_path = os.path.join(os.getcwd(), 'psionic.xml')
    cal_file_path = os.path.join(os.getcwd(), 'source.cal')

    # call cscc
    subprocess.call(['cscc', '--c99', '-o', cal_file_path,
                     '--gnu_version=50300',
                     '-I', r'C:\MinGW\lib\gcc\mingw32\5.3.0\include',
                     '-I', r'C:\MinGW\include',
                     '-D__declspec=', source_file_path])

    with open(ruleid_file_path, 'w') as f:
        for ruleid in ruleids:
            f.write(ruleid + "\n")

    # call analyzer for single file
    psionic = [analyzer, '-w', os.getcwd(), '-o', output_file_path, '-l', ruleid_file_path, cal_file_path]
    print(psionic)
    defects = []
    if subprocess.call(psionic) == 0:
        tree = elemTree.parse(output_file_path)
        xml_defects = tree.findall('./violation/defect')
        for defect in xml_defects :
            id = defect.attrib['id']
            atrributes = defect.attrib['attribute']
            function = atrributes.split(',')[2][5:]

            location = defect.attrib['location']
            line = location.split(',')[0]

            score = defect.attrib['score']

            if id in ruleids:
                defects.append({'function': function, 'line':line, 'score':score})

    return defects


defect_names = [ name.upper().replace(' ', '') for name in option.ERROR_NAMES]
#print(defect_names)
oracle_defects = collect_defect_from_source(option.TARGET_SOURCE_PATH, defect_names)
oracle_defect_lines = [int(defect['line']) for defect in oracle_defects]


defects = run_analyzer_and_collect_defect(option.RULE_IDS, option.TARGET_SOURCE_PATH, option.ANALYZER_PATH)
defect_lines = [int(defect['line']) for defect in defects]

print()

print(oracle_defect_lines)
print(defect_lines)

oracle_defect_lines_set = set(oracle_defect_lines)
defect_lines_set = set(defect_lines)
total_findings = defect_lines_set
true_positive = oracle_defect_lines_set.intersection(defect_lines_set)
false_nagative = oracle_defect_lines_set.difference(defect_lines_set)
false_positive = defect_lines_set.difference(oracle_defect_lines_set)

print("%s Result %s" %("=" * 30, "=" * 30))
if len(total_findings) != 0:
    print("  Precision = %d%%" % ((float(len(true_positive))/float(len(total_findings))) * 100.0))
else:
    print("  Precision = 0%%")

print("     Recall = %d%%" % ((float(len(true_positive))/float(len(oracle_defect_lines_set))) * 100.0))
print("  TotalTest = %d" % (len(oracle_defect_lines_set)))
print("   Missings = %s" % false_nagative)
print("False Alarm = %s" % false_positive)

