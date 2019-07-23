import os
import sys
import subprocess
import traceback
import json
import argparse
import xml.etree.ElementTree as elemTree

parser = argparse.ArgumentParser()
parser.add_argument("-a", dest='ANALYZER_PATH', help='analyzer', required=True)
option = parser.parse_args()

rules = {
    '8000': 'Use Free Heap',
    '8001': 'Unused value',
    '8002': 'Unreachable',
    '8003': 'Uninitialized variable',
    '8004': 'Type Underrun',
    '8005': 'Type Overrun',
    '8006': 'Use after Free',
    '8007': 'Free null pointer',
    '8008': 'Null pointer dereference',
    '8009': 'Memory leak',
    '8010': 'Invalid malloc size',
    '8011': 'Free stack variable',
    '8012': 'Return freed memory',
    '8013': 'Double Free',
    '8014': 'Divide by zero',
    '8015': 'malloc - delete[]',
    '8016': 'new - delete[]',
    '8017': 'malloc - delete',
    '8018': 'new[] - delete',
    '8019': 'new[] - free',
    '8020': 'new - free',
    '8021': 'Buffer Underrun',
    '8022': 'Buffer Overrun',
    '8023': 'Shift with negative value',
    '8024': 'memcpy with invalid value',
    '8025': 'Return local pointer'
}


def analysis(source_file_path, defect_name, rule_id):
    print("Analysis %s [%s]" % (source_file_path, rules[rule_id]))
    command = ['python', 'errors.py', '-a', option.ANALYZER_PATH, '-t', source_file_path, '-e', defect_name, '-r', rule_id]
    # print command line for replay
    #print(" ".join(['"'+cmd+'"' for cmd in command]))
    with open('stdout.txt', 'w') as stdout_file:
        subprocess.call(command, stdout=stdout_file)

    results = {'file': source_file_path, 'defect_name': rules[rule_id]}
    with open('stdout.txt') as stdout_file:
        for line in stdout_file.readlines():
            line = line.strip()
            if line.startswith('Precision'):
                results['precision'] = int(line.split('=')[1].replace('%', ''))
            if line.startswith('Recall'):
                results['recall'] = int(line.split('=')[1].replace('%', ''))
            if line.startswith('TotalTest'):
                results['total_test'] = int(line.split('=')[1])

    return results

# Value Analysis
values = []
values.append(analysis('01.w_Defects/buffer_overrun_dynamic.c', 'Buffer overrun', '8022'))
values.append(analysis('01.w_Defects/overrun_st.c', 'buffer overrun', '8022'))
values.append(analysis('01.w_Defects/buffer_underrun_dynamic.c', 'Buffer Underrun', '8021'))
values.append(analysis('01.w_Defects/underrun_st.c', 'Data Underrun', '8021'))
values.append(analysis('01.w_Defects/zero_division.c', 'division by zero', '8014'))
values.append(analysis('01.w_Defects/data_underflow.c', 'Data Underflow', '8004'))
values.append(analysis('01.w_Defects/data_overflow.c', 'Data Overflow', '8005'))


# Memory Analysis
memory = []
memory.append(analysis('01.w_Defects/uninit_var.c', 'Uninitialized Variable', '8003'))
memory.append(analysis('01.w_Defects/uninit_pointer.c', 'Uninitialized pointer', '8003'))
memory.append(analysis('01.w_Defects/uninit_memory_access.c', 'Uninitialized Memory Access', '8003'))
memory.append(analysis('01.w_Defects/return_local.c', 'return - pointer to local variable', '8025'))
memory.append(analysis('01.w_Defects/null_pointer.c', 'NULL pointer dereference', '8008'))
memory.append(analysis('01.w_Defects/memory_leak.c', 'Memory Leakage', '8009'))
memory.append(analysis('01.w_Defects/invalid_memory_access.c', 'Invalid memory access to already freed area', '8000'))
memory.append(analysis('01.w_Defects/free_null_pointer.c', 'Freeing a NULL pointer', '8007'))
memory.append(analysis('01.w_Defects/double_free.c', 'Double Free', '8013'))


# Dataflow
data = []
data.append(analysis('01.w_Defects/dead_code.c', 'Dead Code', '8002'))


## ----------------------------- compliant test -------------------------------

# Value Analysis
values_compliant = []
values_compliant.append(analysis('02.wo_Defects/buffer_overrun_dynamic.c', 'Buffer overrun', '8022'))
values_compliant.append(analysis('02.wo_Defects/overrun_st.c', 'buffer overrun', '8022'))
values_compliant.append(analysis('02.wo_Defects/buffer_underrun_dynamic.c', 'Buffer underrun', '8021'))
values_compliant.append(analysis('02.wo_Defects/underrun_st.c', 'Data Underrun', '8021'))
values_compliant.append(analysis('02.wo_Defects/zero_division.c', 'division by zero', '8014'))
values_compliant.append(analysis('02.wo_Defects/data_underflow.c', 'Data Underflow', '8004'))
values_compliant.append(analysis('02.wo_Defects/data_overflow.c', 'Data Overflow', '8005'))


# Memory Analysis
memory_compliant = []
memory_compliant.append(analysis('02.wo_Defects/uninit_var.c', 'Uninitialized Variable', '8003'))
memory_compliant.append(analysis('02.wo_Defects/uninit_pointer.c', 'Uninitialized pointer', '8003'))
memory_compliant.append(analysis('02.wo_Defects/uninit_memory_access.c', 'Uninitialized Memory Access', '8003'))
memory_compliant.append(analysis('02.wo_Defects/return_local.c', 'return - pointer to local variable', '8025'))
memory_compliant.append(analysis('02.wo_Defects/null_pointer.c', 'NULL pointer dereference', '8008'))
memory_compliant.append(analysis('02.wo_Defects/memory_leak.c', 'Memory Leakage', '8009'))
memory_compliant.append(analysis('02.wo_Defects/invalid_memory_access.c', 'Invalid memory access to already freed area', '8000'))
memory_compliant.append(analysis('02.wo_Defects/free_null_pointer.c', 'Freeing a NULL pointer', '8007'))
memory_compliant.append(analysis('02.wo_Defects/double_free.c', 'Double Free', '8013'))


def avg_write(lst, name):
    precision = sum([result['precision'] for result in lst])/len(lst)
    recall = sum([result['recall'] for result in lst])/len(lst)
    print('%s Analysis=%f, %f'%(name, precision, recall))
    with open('precision_'+name+'.plot','w') as f:
        f.write("YVALUE=%f" % precision)
    with open('recall_'+name+'.plot','w') as f:
        f.write("YVALUE=%f" % recall)


def print_result(lst):
    for v in lst:
        print("[precision: %3d%%, recall: %3d%%][# test: %3d][%s] %s" % (v['precision'], v['recall'], v['total_test'], v['defect_name'], v['file']))


print()
print('-'*80)
print('Non-Compliant Test')
print('-'*80)
print_result(values+memory+data)
print('='*80)
avg_write(values, 'value')
avg_write(memory, 'memory')
avg_write(data, 'data')
print()
print('+'*80)
avg_write(memory + values + data, 'total')


print()
print('-'*80)
print('Compliant Test')
print('-'*80)
print_result(values_compliant + memory_compliant)
print('='*80)
avg_write(memory_compliant, 'memory_compliant')
avg_write(values_compliant, 'value_compliant')
print('+'*80)
avg_write(values_compliant + memory_compliant, 'total_compliant')
print('-'*80)
