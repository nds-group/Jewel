#!/usr/bin/python3

from __future__ import print_function

import os
import sys
import pdb

SDE_INSTALL   = os.environ['SDE_INSTALL']
SDE_PYTHON2   = os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages')
sys.path.append(SDE_PYTHON2)
sys.path.append(os.path.join(SDE_PYTHON2, 'tofino'))

PYTHON3_VER   = '{}.{}'.format(
                    sys.version_info.major,
                    sys.version_info.minor)
SDE_PYTHON3   = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER, 'site-packages')
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

import grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as bfrt_client
#
import time
import socket, struct

filename_out = sys.argv[1]

#
# Connect to the BF Runtime Server
#
interface = bfrt_client.ClientInterface(
    grpc_addr = '172.16.19.101:50052', ## Addr of the switch from which it gets digests
    client_id = 1,
    device_id = 0)
print('Connected to BF Runtime Server')

#
# Get the information about the running program
#
bfrt_info = interface.bfrt_info_get()
print('The target runs the program ', bfrt_info.p4_name_get())

#
# Establish that you are using this program on the given connection
#
interface.bind_pipeline_config(bfrt_info.p4_name_get())

learn_filter = bfrt_info.learn_get("digest")

#
# Getting the Flow Action Table to modify whenever getting a digest notifying the classification of a flow
#
flow_act_tbl = bfrt_info.table_get('Ingress.flow_action_table')
print('Table max packet length info:', flow_act_tbl)

target = bfrt_client.Target(device_id=0, pipe_id=0xffff)

# List of registers used for Flow Management Block
registers = ['Ingress.reg_flow_ID','Ingress.reg_time_last_pkt','Ingress.reg_pkt_count', 'Ingress.reg_classified_flag']

# Header for the csv file to save all the classification results
header = 'source_addr,destin_addr,source_port,destin_port,protocol,pkt_count,flow_packet_class'

with open(filename_out, "w") as text_file:
    text_file.write(header)
    text_file.write("\n")
    
## Inference point
npkts = 3

while True:
    try:
        digest = interface.digest_get(timeout=400)
    except:
        break

    recv_target = digest.target
    digest_type = 1
    data_list = learn_filter.make_data_list(digest)
    
    if digest_type == 1:

        keys_reg = {'Ingress.reg_flow_ID': [],'Ingress.reg_time_last_pkt': [],
                    'Ingress.reg_pkt_count': [], 'Ingress.reg_classified_flag': []}
        datas_reg = {'Ingress.reg_flow_ID': [],'Ingress.reg_time_last_pkt': [],
                    'Ingress.reg_pkt_count': [], 'Ingress.reg_classified_flag': []}
        keys_table = []
        datas_table = []
        
        for data in data_list:
            data_dict = data.to_dict()
            
            # convert ip address into normal format
            source_addr = socket.inet_ntoa(struct.pack('!L', data_dict['source_addr']))
            destin_addr = socket.inet_ntoa(struct.pack('!L', data_dict['destin_addr']))
            #
            source_port = str(data_dict['source_port'])
            destin_port = str(data_dict['destin_port'])
            protocol = str(data_dict['protocol'])
            flow_packet_class = str(data_dict['class_value'])
            pkt_count = str(data_dict['packet_num'])
            register_index = data_dict['register_index']
            
            ## Store the classification result
            csv_row = source_addr + ',' + destin_addr + ',' + source_port + ',' + destin_port + ',' + protocol + ',' + pkt_count + ',' + flow_packet_class
            
            with open(filename_out, "a") as text_file:
                    text_file.write(csv_row)
                    text_file.write("\n")
            #
            ## Refresh the memory and update Flow Action table if n'th packet of a flow is classified
            if (data_dict['packet_num'] == npkts):
                ## Update Flow Action table (save keys and datas to be updated)
                # f_action == 0 :          Classified flow
                # f_action == 1 (default): Unclassified flow
                keys_table.append(flow_act_tbl.make_key(
                                [bfrt_client.KeyTuple('hdr.ipv4.src_addr', data_dict['source_addr']), bfrt_client.KeyTuple('hdr.ipv4.dst_addr', data_dict['destin_addr']), 
                                bfrt_client.KeyTuple('meta.hdr_dstport', data_dict['destin_port']), bfrt_client.KeyTuple('meta.hdr_srcport', data_dict['source_port']),
                                bfrt_client.KeyTuple('hdr.ipv4.protocol', data_dict['protocol'])]))

                datas_table.append(flow_act_tbl.make_data([
                                        bfrt_client.DataTuple('f_action', 0)
                                    ], 'Ingress.set_flow_action'))
                ## Refresh memory (save keys and datas to be cleaned)
                for reg_name in registers:
                    reg_tbl = bfrt_info.table_get(reg_name)
                    keys_reg[reg_name].append(reg_tbl.make_key([bfrt_client.KeyTuple('$REGISTER_INDEX', register_index)]))
                    datas_reg[reg_name].append(reg_tbl.make_data([bfrt_client.DataTuple(reg_name+'.f1', 0)]))


        ## Update Flow Action table and refresh memory
        flow_act_tbl.entry_mod(target, keys_table, datas_table, p4_name=bfrt_info.p4_name_get())
        for reg_name in registers:
            reg_tbl = bfrt_info.table_get(reg_name)
            reg_tbl.entry_mod(target, key_list=keys_reg[reg_name], data_list=datas_reg[reg_name], flags={"from_hw":True}, p4_name=bfrt_info.p4_name_get())