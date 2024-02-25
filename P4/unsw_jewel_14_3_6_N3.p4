/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "./include/types.p4"
#include "./include/headers.p4"
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.total_len = hdr.ipv4.total_len;
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP:  parse_tcp;
            TYPE_UDP:  parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.hdr_dstport = hdr.tcp.dst_port;
        meta.hdr_srcport = hdr.tcp.src_port;
        meta.tcp_hdr_len = hdr.tcp.data_offset;
        meta.tcp_windows_size = hdr.tcp.window;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.hdr_dstport = hdr.udp.dst_port;
        meta.hdr_srcport = hdr.udp.src_port;
        meta.tcp_hdr_len = 0;
        meta.tcp_windows_size = 0;
        transition accept;
    }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
/***************** M A T C H - A C T I O N  *********************/
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* Registers for flow management */

    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_classified_flag;
    /* Register read action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_classified_flag)
    read_classified_flag = {
        void apply(inout bit<8> classified_flag, out bit<8> output) {
            output = classified_flag;
        }
    };
    /* Register update action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_classified_flag)
    update_classified_flag = {
        void apply(inout bit<8> classified_flag) {
            if (meta.pkt_count == 3){
                classified_flag = meta.final_class;
            }

        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_flow_ID;
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_ID)
    update_flow_ID = {
        void apply(inout bit<32> flow_ID) {
            flow_ID = meta.flow_ID;
        }
    };
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_flow_ID)
    read_only_flow_ID = {
        void apply(inout bit<32> flow_ID, out bit<32> output) {
            output = flow_ID;
        }
    };

    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_time_last_pkt;
    /* Register read action */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(reg_time_last_pkt)
    read_time_last_pkt = {
        void apply(inout bit<32> time_last_pkt, out bit<32> output) {
            output = time_last_pkt;
            time_last_pkt = ig_prsr_md.global_tstamp[31:0];
        }
    };

    //registers for ML inference - features
    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_pkt_count;
    /* Register read action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_pkt_count)
    read_pkt_count = {
        void apply(inout bit<8> pkt_count, out bit<8> output) {
            pkt_count = pkt_count + 1;
            output = pkt_count;
        }
    };

    /* Declaration of the hashes*/
    Hash<bit<32>>(HashAlgorithm_t.CRC32)              flow_id_calc;
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)   idx_calc;

    /* Calculate hash of the 5-tuple to represent the flow ID */
    action get_flow_ID(bit<16> srcPort, bit<16> dstPort) {
        meta.flow_ID = flow_id_calc.get({hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol});
    }
    /* Calculate hash of the 5-tuple to use as 1st register index */
    action get_register_index(bit<16> srcPort, bit<16> dstPort) {
        meta.register_index = idx_calc.get({hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,srcPort, dstPort, hdr.ipv4.protocol});
    }

    /* Assign class if at leaf node */
    action SetClass0(bit<8> classe) {
        meta.class0 = classe;
    }
    action SetClass1(bit<8> classe) {
        meta.class1 = classe;
    }
    action SetClass2(bit<8> classe) {
        meta.class2 = classe;
    }

    /* Forward to a specific port upon classification */
    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    /* Custom Do Nothing Action */
    action nop(){}

    /* Set the final class if there is majority */
    action set_final_class(bit<8> class_result) {
        meta.final_class = class_result;
    }

    /* Set the final class as the result returned by the most successful tree, if thr voting table does not experience a hit */
    action set_default_class() {
        meta.final_class = meta.class2;
    }

    /* Feature table actions */
    action SetCode0(bit<103> code0, bit<99> code1, bit<114> code2) {
        meta.codeword0[479:377] = code0;
        meta.codeword1[479:381] = code1;
        meta.codeword2[479:366] = code2;
    }
    action SetCode1(bit<83> code0, bit<80> code1, bit<91> code2) {
        meta.codeword0[376:294] = code0;
        meta.codeword1[380:301] = code1;
        meta.codeword2[365:275] = code2;
    }
    action SetCode2(bit<91> code0, bit<116> code1, bit<95> code2) {
        meta.codeword0[293:203] = code0;
        meta.codeword1[300:185] = code1;
        meta.codeword2[274:180] = code2;
    }
    action SetCode3(bit<79> code0, bit<94> code1, bit<79> code2) {
        meta.codeword0[202:124] = code0;
        meta.codeword1[184:91] = code1;
        meta.codeword2[179:101] = code2;
    }
    action SetCode4(bit<94> code0, bit<80> code1, bit<86> code2) {
        meta.codeword0[123:30] = code0;
        meta.codeword1[90:11] = code1;
        meta.codeword2[100:15] = code2;
    }
    action SetCode5(bit<30> code0, bit<11> code1, bit<15> code2) {
        meta.codeword0[29:0] = code0;
        meta.codeword1[10:0] = code1;
        meta.codeword2[14:0] = code2;
    }

    /* Target traffic table storing the information if a flow is classified or not */
    action set_flow_action(bit<2> f_action) {
        meta.f_action = f_action;
    }

    /* Feature tables */
    table table_feature0{
	    key = {meta.tcp_windows_size: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 240;
        const default_action = nop();
	}
    table table_feature1{
        key = {meta.total_len: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 200;
        const default_action = nop();
	}
	table table_feature2{
	    key = {meta.hdr_srcport: range @name("feature2");}
	    actions = {@defaultonly nop; SetCode2;}
	    size = 230;
        const default_action = nop();
	}
    table table_feature3{
	    key = {meta.hdr_dstport: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 240;
        const default_action = nop();
	}
	table table_feature4{
	    key = {hdr.ipv4.ttl: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 90;
        const default_action = nop();
	}
    table table_feature5{
	    key = {meta.tcp_hdr_len: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 15;
        const default_action = nop();
	}

    /* Code tables */
	table code_table0{
	    key = {meta.codeword0: ternary;}
	    actions = {@defaultonly nop; SetClass0;}
	    size = 481;
        const default_action = nop();
	}
	table code_table1{
        key = {meta.codeword1: ternary;}
	    actions = {@defaultonly nop; SetClass1;}
	    size = 481;
        const default_action = nop();
	}
	table code_table2{
        key = {meta.codeword2: ternary;}
	    actions = {@defaultonly nop; SetClass2;}
	    size = 481;
        const default_action = nop();
	}

    /* Voting Table */
    table voting_table {
        key = {
            meta.class0: exact;
            meta.class1: exact;
            meta.class2: exact;
        }
        actions = {set_final_class; @defaultonly set_default_class;}
        size = 2048;
        const default_action = set_default_class();
    }

    /* Forwarding-Inference Block Table */
    table flow_action_table {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            meta.hdr_srcport: exact;
            meta.hdr_dstport: exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {set_flow_action; @defaultonly ipv4_forward;}
        size = 63000;
        const default_action = ipv4_forward(260);
    }

    apply {
        // Forward, if flow is already classified. Otherwise, run model.
        flow_action_table.apply();
        bit<32> tmp_flow_ID;
        //compute flow_ID and hash index
        get_flow_ID(meta.hdr_srcport, meta.hdr_dstport);
        get_register_index(meta.hdr_srcport, meta.hdr_dstport);

        // code here to execute if table experienced a hit
        if (meta.f_action != 0) {

            // modify timestamp register
            meta.time_last_pkt = read_time_last_pkt.execute(meta.register_index);
            
            // check if register array is empty
            if (meta.time_last_pkt == 0){ // we do not yet know this flow
                // Start storing the flow information in the register
                update_flow_ID.execute(meta.register_index);
                meta.pkt_count = read_pkt_count.execute(meta.register_index);
            }
            else { // not the first packet - get flow_ID from register
                tmp_flow_ID = read_only_flow_ID.execute(meta.register_index);
                if(meta.flow_ID != tmp_flow_ID){ // hash collision

                    // To indicate there is a collision in the digest
                    meta.pkt_count = 0;
                }
                else { // not first packet and not hash collision

                    //read and update packet count
                    meta.pkt_count = read_pkt_count.execute(meta.register_index);

                } //END OF CHECK ON IF NO COLLISION
            } // END OF CHECK ON WHETHER FIRST CLASS
            // IF it is less than (N+1)th packet, RUN the joint inference model
            if (meta.pkt_count < 4){
                // apply feature tables to assign codes
                table_feature0.apply();
                table_feature1.apply();
                table_feature2.apply();
                table_feature3.apply();
                table_feature4.apply();
                table_feature5.apply();

                // apply code tables to assign labels
                code_table0.apply();
                code_table1.apply();
                code_table2.apply();

                // decide final class
                voting_table.apply();

                // Update the class in the register
                update_classified_flag.execute(meta.register_index);

                // Activate the digest after classification
                ig_dprsr_md.digest_type = 1;

                ipv4_forward(260);
            }
            // IF it is more than (N)th packet, GET THE CLASS ASSIGNED before and FORWARD the packet
            else {
                meta.classified_flag = read_classified_flag.execute(meta.register_index);
                ipv4_forward(260); 
            } 
        } 
        // If a flow that the packet belongs to was classified before, FORWARD the packet
        ipv4_forward(260);
        // }  
    } //END OF APPLY
} //END OF INGRESS CONTROL

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    // Checksum() ipv4_checksum;

    Digest<flow_class_digest>() digest;

    apply {
        // Create the digest
        if (ig_dprsr_md.digest_type == 1) {
            
            digest.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.hdr_srcport, meta.hdr_dstport, hdr.ipv4.protocol, meta.final_class, meta.pkt_count, meta.register_index});
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
#include "./include/egress.p4"

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
