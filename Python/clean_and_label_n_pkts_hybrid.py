import pandas as pd
import numpy as np
import sys

filename_in = sys.argv[1]
filename_out = sys.argv[2]
n_packets = int(sys.argv[3])

# IoT device list
IoT_Device_List = pd.read_csv("iot_device_list.csv")

packet_data = pd.DataFrame()
print("NOW: LOADING AND CLEANING DATA...")
packet_data = pd.read_csv(filename_in, sep = '|', header=None)

packet_data.columns = ["frame.time_relative","ip.src","ip.dst","tcp.srcport","tcp.dstport","ip.len",
                   "tcp.flags.syn","tcp.flags.ack","tcp.flags.push","tcp.flags.fin",
                   "tcp.flags.reset","tcp.flags.ece","ip.proto","udp.srcport","udp.dstport",
                   "eth.src","eth.dst", "ip.hdr_len", "ip.tos", "ip.ttl", "tcp.window_size_value", 
                   "tcp.hdr_len", "udp.length"]

packet_data = packet_data[(packet_data["ip.proto"] != "1,17") & (packet_data["ip.proto"] != "1,6")].reset_index(drop=True)
packet_data = packet_data.dropna(subset=['ip.proto'])
#
packet_data['ip.proto'] = packet_data['ip.proto'].astype(int)
#
packet_data["ip.src"] = packet_data["ip.src"].astype(str)
packet_data["ip.dst"] = packet_data["ip.dst"].astype(str)
packet_data["ip.len"] = packet_data["ip.len"].astype("int")
##the new features from either tcp or udp might have some NA which we set to 0
packet_data["tcp.window_size_value"] = packet_data["tcp.window_size_value"].astype('Int64').fillna(0)
packet_data["tcp.hdr_len"] = packet_data["tcp.hdr_len"].astype('Int64').fillna(0)
# divide by 4 to get values comparable to those in the switch
packet_data["tcp.hdr_len"] = packet_data["tcp.hdr_len"]/4
packet_data["udp.length"] = packet_data["udp.length"].astype('Int64').fillna(0)
##
packet_data["tcp.srcport"] = packet_data["tcp.srcport"].astype('Int64')
packet_data["tcp.dstport"] = packet_data["tcp.dstport"].astype('Int64')
#
packet_data["tcp.flags.syn"] = packet_data["tcp.flags.syn"].astype('Int64').fillna(0)
packet_data["tcp.flags.ack"] = packet_data["tcp.flags.ack"].astype('Int64').fillna(0)
packet_data["tcp.flags.push"] = packet_data["tcp.flags.push"].astype('Int64').fillna(0)
packet_data["tcp.flags.fin"] = packet_data["tcp.flags.fin"].astype('Int64').fillna(0)
packet_data["tcp.flags.reset"] = packet_data["tcp.flags.reset"].astype('Int64').fillna(0)
packet_data["tcp.flags.ece"] = packet_data["tcp.flags.ece"].astype('Int64').fillna(0)
#
packet_data["udp.srcport"] = packet_data["udp.srcport"].astype('Int64')
packet_data["udp.dstport"] = packet_data["udp.dstport"].astype('Int64')
#
packet_data["srcport"] = np.where(packet_data["ip.proto"] == "6", packet_data["tcp.srcport"], packet_data["udp.srcport"])
packet_data["dstport"] = np.where(packet_data["ip.proto"] == "6", packet_data["tcp.dstport"], packet_data["udp.dstport"])
#
packet_data["srcport"] = np.where(packet_data["ip.proto"] == 6, packet_data["tcp.srcport"], packet_data["udp.srcport"])
packet_data["dstport"] = np.where(packet_data["ip.proto"] == 6, packet_data["tcp.dstport"], packet_data["udp.dstport"])
#
packet_data["srcport"] = packet_data["srcport"].astype('Int64')
packet_data["dstport"] = packet_data["dstport"].astype('Int64')

#===============================CREATE THE FLOW IDs AND DROP UNWANTED COLUMNS =============================================#
# packet_data["ID"] = packet_data["ip.src"].astype(str) + " " + packet_data["ip.dst"].astype(str) + " " + packet_data["srcport"].astype(str) + " " + packet_data["dstport"].astype(str) + " " + packet_data["ip.proto"].astype(str)
packet_data = packet_data.drop(["tcp.srcport","tcp.dstport","udp.srcport","udp.dstport"],axis=1)
packet_data = packet_data.reset_index(drop=True)

packet_data["flow.id"] = packet_data["ip.src"].astype(str) + " " + packet_data["ip.dst"].astype(str) + " " + packet_data["srcport"].astype(str) + " " + packet_data["dstport"].astype(str) + " " + packet_data["ip.proto"].astype(str)

# LABELING
print("NOW: LABELLING PACKETS...")
packet_data["label"] = [0] * len(packet_data)
for i in range(len(IoT_Device_List)):
    packet_data["label"] = np.where((packet_data["eth.src"]==IoT_Device_List["MAC ADDRESS"][i]), 
                                        IoT_Device_List["List of Devices"][i], packet_data["label"])
for i in range(len(IoT_Device_List)):
    packet_data["label"] = np.where((packet_data["eth.dst"] ==IoT_Device_List["MAC ADDRESS"][i]) & 
                                    (packet_data["eth.src"]=="14:cc:20:51:33:ea"), 
                                    IoT_Device_List["List of Devices"][i], packet_data["label"])
packet_data = packet_data[packet_data['label']!="TPLink Router Bridge LAN (Gateway)"]
packet_data = packet_data[packet_data['label']!="0"]
packet_data = packet_data[packet_data['label']!="Nest Dropcam"]
packet_data = packet_data[packet_data['label']!="MacBook/Iphone"]
packet_data = packet_data.reset_index(drop=True)
##

number_of_pkts_limit, min_number_of_packets = n_packets,n_packets
#===============================Extract flows from packets and calculate features=============================================#
main_packet_size = {}  # dictionary to store list of packet sizes for each flow (Here key = flowID, value = list of packet sizes)
flow_list = []  # contains the flowIDs (a combination of SIP,DIP,srcPort, dstPort, proto)
main_inter_arrival_time = {}  # dictionary to store list of IATs for each flow (Here key = flowID, value = list of IATs)
last_time = {}  # for each flow we store timestamp of the last packet arrival

avg_pkt_sizes = {}  # contains the flowID and their calculated average packet sizes
string = {}  # For each flow, we have a string of feature values (just for printing purpose, on screen)

tcp_window_sizes = {}
ip_header_lengths = {}
ttls = {}
tcp_hdr_lengths = {}
udp_lengths = {}
labels = {}

packet_count = {}  # contains flowID as key and number of packets as value
srcMAC = {}  # contains flowID as key and srcnac
dstMAC = {}  # contains flowID as key and dstmac as value
syn_flag_count = {}  # contains flowID as key and number of packets with SYN flag 'set' as value
ack_flag_count = {}  # contains flowID as key and number of packets with ACK flag 'set' as value
push_flag_count = {}  # contains flowID as key and number of packets with PSH flag 'set' as value
fin_flag_count = {}  # contains flowID as key and number of packets with FIN flag 'set' as value
rst_flag_count = {}  # contains flowID as key and number of packets with RST flag 'set' as value
ece_flag_count = {}  # contains flowID as key and number of packets with ECE flag 'set' as value

flow_label = {}  # contains label
ttl_list = {} 
syn_list= {}  # contains flowID as key and number of packets with SYN flag 'set' as value
ack_list = {}  # contains flowID as key and number of packets with ACK flag 'set' as value
push_list = {}  # contains flowID as key and number of packets with PSH flag 'set' as value
fin_list = {}  # contains flowID as key and number of packets with FIN flag 'set' as value
rst_list = {}  # contains flowID as key and number of packets with RST flag 'set' as value
ece_list = {} # contains flowID as key and number of packets with ECE flag 'set' as value

# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# print("NOW: COMPUTING AND WRITING FLOW FEATURES INTO CSV...")
header = "Flow ID,\
ip.len,ip.ttl,tcp.flags.syn,tcp.flags.ack,tcp.flags.push,\
tcp.flags.fin,tcp.flags.rst,tcp.flags.ece,ip.proto,srcport,dstport,\
ip.hdr_len,tcp.window_size_value,tcp.hdr_len,udp.length,\
Min Packet Length,Max Packet Length,Packet Length Mean,\
Packet Length Total,UDP Len Min,UDP Len Max,Packet Count,\
Flow IAT Min,Flow IAT Max,Flow IAT Mean,Flow Duration,\
SYN Flag Count,ACK Flag Count,PSH Flag Count,FIN Flag Count,\
RST Flag Count,ECE Flag Count,Label"

with open(filename_out, "w") as text_file:
    text_file.write(header)
    text_file.write("\n")
# ==============================================================================================================================#
    print("NOW: COLLECTING PACKETS INTO FLOWS...")
    for row in packet_data.itertuples(index=True, name='Pandas'):
        time = float(row[1])    # timestamp of the packet
        srcip = row[2]          #src ip
        dstip = row[3]          #dst ip
        pktsize = row[4]
        syn_flag = row[5]
        ack_flag = row[6]
        push_flag = row[7]
        fin_flag = row[8]
        rst_flag = row[9]
        ece_flag = row[10]
        proto = row[11]
        srcmac = row[12]
        dstmac = row[13]
        #
        ip_hdr_len = row[14]
        ip_tos = row[15]
        ip_ttl = row[16]
        tcp_window_size_value = row[17]
        tcp_hdr_len = row[18]
        udp_length = row[19]
        #
        srcport =  row[20]     #source port
        dstport =  row[21]     #destination port
        key = row[22]          #key which is a concatenation of the 5-tuple to identify the flow
        label = row[23]  

        if key in flow_list:  # check if the packet belongs to already existing flow
            if (len(main_packet_size[key]) < number_of_pkts_limit ):
                packet_count[key] = packet_count[key] + 1  # increment packet count
                main_packet_size[key].append(pktsize)  # append its packet size to the packet size list for this flow
                lasttime = last_time[key]
                diff = round(float(time) - float(lasttime), 9)  # calculate inter-arrival time (seconds)
                main_inter_arrival_time[key].append(diff)  # append IAT
                ##
                tcp_window_sizes[key].append(tcp_window_size_value)
                ip_header_lengths[key].append(ip_hdr_len)
                ttls[key].append(ip_ttl)
                tcp_hdr_lengths[key].append(tcp_hdr_len)
                udp_lengths[key].append(udp_length)
                # labels[key] = label
                ##
                syn_list[key].append(syn_flag) 
                ack_list[key].append(ack_flag) 
                push_list[key].append(push_flag) 
                fin_list[key].append(fin_flag) 
                rst_list[key].append(rst_flag) 
                ece_list[key].append(ece_flag) 
                ##
                srcMAC[key] = srcmac
                dstMAC[key] = dstmac

                if syn_flag == 1:  # check if the tcp flags are set, and update the count if 1
                    syn_flag_count[key] = syn_flag_count[key] + 1
                if ack_flag == 1:
                    ack_flag_count[key] = ack_flag_count[key] + 1
                if push_flag == 1:
                    push_flag_count[key] = push_flag_count[key] + 1
                if fin_flag == 1:
                    fin_flag_count[key] = fin_flag_count[key] + 1
                if rst_flag == 1:
                    rst_flag_count[key] = rst_flag_count[key] + 1
                if ece_flag == 1:
                    ece_flag_count[key] = ece_flag_count[key] + 1

                last_time[key] = time  # update last time for the flow, to the timestamp of this packet
                ##
                if (len(main_packet_size[key]) < (number_of_pkts_limit)):
                    pkt_data = key + "," + str(pktsize) + "," + str(ip_ttl) + "," + str(syn_flag) + "," + str(ack_flag) + "," + str(push_flag) \
                        + "," + str(fin_flag) + "," + str(rst_flag) + "," + str(ece_flag) + "," + str(proto) + "," + str(srcport) + "," + str(dstport) \
                        + "," + str(ip_hdr_len) + "," + str(tcp_window_size_value) + "," + str(tcp_hdr_len) + "," + str(udp_length) \
                        + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) \
                        + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) \
                        + "," + str(-1) + "," + str(label)
                    ##
                    text_file.write(pkt_data)
                    text_file.write("\n")
                ##
                
        else:  # if this packet is the first one in this NEW flow
            flow_list.append(key)  # make its entry in the existing flow List
            packet_count[key] = 1  # first packet arrived for this flow, set count =1
            main_packet_size[key] = [pktsize]  # make its entry in the packet size dictionary
            ##
            tcp_window_sizes[key] = [tcp_window_size_value]
            ip_header_lengths[key] = [ip_hdr_len]
            ttls[key] = [ip_ttl]
            tcp_hdr_lengths[key] = [tcp_hdr_len]
            udp_lengths[key] = [udp_length]
            labels[key] = label
            ##
            syn_list[key] = [syn_flag]
            ack_list[key] = [ack_flag] 
            push_list[key]= [push_flag] 
            fin_list[key] = [fin_flag]
            rst_list[key] = [rst_flag] 
            ece_list[key] = [ece_flag] 
            ##
            main_inter_arrival_time[key] = []  # create a blank list in this dictionary, as it is the first packet
            ##
            srcMAC[key] = srcmac
            dstMAC[key] = dstmac

            if push_flag == 1:  # initialize tcp flag counts for this new flow
                push_flag_count[key] = 1
            else:
                push_flag_count[key] = 0

            if syn_flag == 1:
                syn_flag_count[key] = 1
            else:
                syn_flag_count[key] = 0

            if ack_flag == 1:
                ack_flag_count[key] = 1
            else:
                ack_flag_count[key] = 0

            if fin_flag != 1:
                fin_flag_count[key] = 0
            else:
                fin_flag_count[key] = 1

            if rst_flag == 1:
                rst_flag_count[key] = 1
            else:
                rst_flag_count[key] = 0
            if ece_flag == 1:
                ece_flag_count[key] = 1
            else:
                ece_flag_count[key] = 0

            last_time[key] = time

            pkt_data = key + "," + str(pktsize) + "," + str(ip_ttl) + "," + str(syn_flag) + "," + str(ack_flag) + "," + str(push_flag) \
                + "," + str(fin_flag) + "," + str(rst_flag) + "," + str(ece_flag) + "," + str(proto) + "," + str(srcport) + "," + str(dstport) \
                + "," + str(ip_hdr_len) + "," + str(tcp_window_size_value) + "," + str(tcp_hdr_len) + "," + str(udp_length) \
                + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) \
                + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) + "," + str(-1) \
                + "," + str(-1) + "," + str(label)
                
            text_file.write(pkt_data)
            text_file.write("\n")

    print("NOW: COMPUTING FLOW LEVEL FEATURES...")
    # -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Calculate features related to packet size
    for key in flow_list:
        packet_list = main_packet_size[key]  # packet_list contains the list of packet sizes for the flow in consideration
        length = len(packet_list)  # number of packets
        avg_pkt_sizes[key] = sum(packet_list) / length  # calculate avg packet size, and store
        min_pkt_size = min(packet_list)
        max_pkt_size = max(packet_list)

        string[key] = key + "," + str(packet_list[len(packet_list)-1]) + "," + str(ttls[key][len(ttls[key])-1]) \
            + "," + str(syn_list[key][len(syn_list[key])-1]) + "," + str(ack_list[key][len(ack_list[key])-1]) \
                + "," + str(push_list[key][len(push_list[key])-1]) + "," + str(fin_list[key][len(fin_list[key])-1])\
                    + "," + str(rst_list[key][len(rst_list[key])-1]) + "," + str(ece_list[key][len(ece_list[key])-1]) \
                        + "," + str(key.split(' ')[4]) + "," + str(key.split(' ')[2]) + "," + str(key.split(' ')[3])\
                            + "," + str(ip_header_lengths[key][len(ip_header_lengths[key])-1]) + "," + str(tcp_window_sizes[key][len(tcp_window_sizes[key])-1]) \
                                + "," + str(tcp_hdr_lengths[key][len(tcp_hdr_lengths[key])-1]) + "," + str(udp_lengths[key][len(udp_lengths[key])-1]) \
                                    + "," + str(min_pkt_size) + "," + str(max_pkt_size) + "," + str(avg_pkt_sizes[key]) + "," + str(sum(packet_list)) \
                                        + "," + str(min(udp_lengths[key]))+ "," + str(max(udp_lengths[key])) + "," + str(len(packet_list)) 

    # ------------------- ---------------------------------------------------------------------------------------------------------------------------------------------------
    # Now calculate IAT-related features
        inter_arrival_time_list = main_inter_arrival_time[key]  # a list containing IATs for the flow
        length = len(inter_arrival_time_list)
        if length == 0:
            min_IAT = 0
            max_IAT = 0
        else:
            min_IAT = min(inter_arrival_time_list)
            min_IAT_ms = round(1000000000*min_IAT, 9) # convert in nanoseconds
            max_IAT = max(inter_arrival_time_list)
            max_IAT_ms = round(1000000000*max_IAT, 9) # convert in nanoseconds

        if length > 0:
            flow_duration = sum(inter_arrival_time_list)  # flow duration seconds
            flow_duration_ms = round(1000000000*flow_duration, 9) # convert in nanoseconds
            avg_iat = flow_duration / length  # Average IAT
            avg_iat_in_ms = round(1000000000*avg_iat, 9)  # convert in nanoseconds

        if(len(main_packet_size[key]) >= min_number_of_packets):
            string[key] = string[key] + "," + str(min_IAT_ms) + "," + str(max_IAT_ms) + "," + str(avg_iat_in_ms) + "," + str(flow_duration_ms) + "," + str(syn_flag_count[key]) + "," + str(ack_flag_count[key]) + "," + str(push_flag_count[key]) + "," + str(fin_flag_count[key]) + "," + str(rst_flag_count[key]) + "," + str(ece_flag_count[key])
            string[key] = string[key] + "," + labels[key]
            text_file.write(string[key])
            text_file.write("\n")