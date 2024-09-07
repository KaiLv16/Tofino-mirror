/*
    packet length compression in P4
    Copyright (C) 2022 Kai Lv, ICT, CAS
*/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

typedef bit<8>  pkt_type_t;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

#if __TARGET_TOFINO__ == 1
typedef bit<3> mirror_type_t;
#else
typedef bit<4> mirror_type_t;
#endif
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;

header current_stage_t {
    bit<16> current_stage;
}

struct stat_data_t {
    bit<16> sample_len;
    bit<32> s1;
    bit<32> s2;
    bit<32> s3;
    bit<32> s4;
}

header mirror_data_h {
    stat_data_t mirror_data;
}

struct metadata_t {
    bit<1> do_ing_mirroring;  // Enable ingress mirroring
    bit<1> do_egr_mirroring;  // Enable egress mirroring
    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
    MirrorId_t egr_mir_ses;   // Egress mirror session ID
    pkt_type_t pkt_type;
    current_stage_t current_stage;
    bit<32> sign_reg_1;
    bit<32> sign_reg_2;
    bit<32> sign_reg_3;
    bit<32> sign_reg_4;
}

header mirror_bridged_metadata_h {
    pkt_type_t pkt_type;
    @flexible bit<1> do_egr_mirroring;  //  Enable egress mirroring
    @flexible MirrorId_t egr_mir_ses;   // Egress mirror session ID
}

header mirror_h {
    pkt_type_t  pkt_type;
}

const ether_type_t ETHERTYPE_CHANGESIZE = 16w0x1234;
header changecolpkt_h {
    bit<16> new_size;
}

struct headers_t {
    mirror_bridged_metadata_h bridged_md;
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    changecolpkt_h changecolpkt;
    ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;
    mirror_data_h mir_hdr_data;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_CHANGESIZE : parse_newsize;
            default : reject;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default : reject;
        }
    }

    state parse_newsize {
        pkt.extract(hdr.changecolpkt);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_mir_hdr_data;
    }
    
    state parse_mir_hdr_data {
        pkt.extract(hdr.mir_hdr_data);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Mirror() mirror;

    apply {

        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
            mirror.emit<mirror_h>(ig_md.ing_mir_ses, {ig_md.pkt_type});
        }

        pkt.emit(hdr);
        //pkt.emit(hdr.bridged_md);
        //pkt.emit(hdr.ethernet);
        //pkt.emit(hdr.ipv4);
        //pkt.emit(hdr.udp);
    }
}

// ---------------------------------------------------------------------------
// Switch Ingress MAU
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    bit<16> column_num;

    const bit<32> col_num_register_size = 1;
    Register<bit<16>, bit<32>>(col_num_register_size, 0x000c) col_num_register;
    RegisterAction<bit<16>, bit<32>, bit<16>>(col_num_register) change = {
        void apply(inout bit<16> col_num, out bit<16> col_num_t) {
            if (hdr.changecolpkt.isValid()) {
                col_num = hdr.changecolpkt.new_size;
            }
            col_num_t = col_num;
        }
    };

    // used to determine the index of a packet.
    const bit<32> w16_register_table_size = 1;
    Register<bit<16>, bit<32>>(w16_register_table_size, 0x0001) w16_register_table;
    RegisterAction<bit<16>, bit<32>, bit<16>>(w16_register_table) add = {
        void apply(inout bit<16> size, out bit<16> size_t) {
            if(size >= column_num) {
                size = 0x0001;
            }else{
                size = size + 1;
            }
            size_t = size;
        }
    };
    /*
    4 registers to accumulate packet length. 
    Since the total length of 12 packets cannot exceed 32768 (actually, 12*1500 < 2^15),
            what really matters are the low 16 digits. 
    However, one can make use of the high 16 digits for other purposes.
    */
    const bit<32> int16_register_table_size = 1;
    #define GEN_RESULT_REGISTER(X)                                                                      \
    bit<32> length_tmp_## X ##;                                                                         \
    Register<bit<32>, bit<32>>(int16_register_table_size, 0x00000000) int16_register_table_## X ##_t;   \
    RegisterAction<bit<32>, bit<32>, bit<32>>(int16_register_table_## X ##_t) plus_## X ## = {          \
        void apply(inout bit<32> value, out bit<32> value_t) {                                          \
            if (ig_md.current_stage.current_stage == 0x0002){                                           \
                value = 0x00000000 + ig_md.sign_reg_## X ##;                                            \
            } else {                                                                                    \
                value = value + ig_md.sign_reg_## X ##;                                                 \
            }                                                                                           \
            value_t = value;                                                                            \
        }                                                                                               \
    };                                                                                                  \

    bit<32> Total_len = (bit<32>)hdr.ipv4.total_len;
    #define GEN_LOOKUP_TABLE(X, s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12)                 \
    bit<32> reg_tmp_## X ##;                                                            \
    action setsign_1_## X ##() {                                                        \
        ig_md.sign_reg_## X ## = 0x08000000 + Total_len;                                \
    }                                                                                   \
    action setsign_2_## X ##() {                                                        \
        ig_md.sign_reg_## X ## = 0x00800000 - Total_len;                                \
    }                                                                                   \
    table table_## X ##_t {                                                             \
        key = {                                                                         \
            ig_md.current_stage.current_stage : exact;                                  \
        }                                                                               \
        actions = {                                                                     \
            setsign_1_## X ##;                                                          \
            setsign_2_## X ##;                                                          \
        }                                                                               \
        size = 16;                                                                      \
        const entries = {                                                               \
                (0x0002) : setsign_## s1 ##_## X ##();                                  \
                (0x0003) : setsign_## s2 ##_## X ##();                                  \
                (0x0004) : setsign_## s3 ##_## X ##();                                  \
                (0x0005) : setsign_## s4 ##_## X ##();                                  \
                (0x0006) : setsign_## s5 ##_## X ##();                                  \
                (0x0007) : setsign_## s6 ##_## X ##();                                  \
                (0x0008) : setsign_## s7 ##_## X ##();                                  \
                (0x0009) : setsign_## s8 ##_## X ##();                                  \
                (0x000a) : setsign_## s9 ##_## X ##();                                  \
                (0x000b) : setsign_## s10 ##_## X ##();                                 \
                (0x000c) : setsign_## s11 ##_## X ##();                                 \
                (0x0001) : setsign_## s12 ##_## X ##();                                 \
        }                                                                               \
    }                                                                                   \

    /*
    Attention: NO " ; " here, otherwise the compiler will treat them as functions.
    1 stands for "+1", 2 stands for "-1".
    Table entries pre-defined in data plane for convenience. 
            One can simply modify this to make table entires asserted from control plane.
    */
    /*
    GEN_LOOKUP_TABLE(1, 2, 1, 2, 1, 1, 1, 2, 2, 1, 1, 2, 2)
    GEN_LOOKUP_TABLE(2, 1, 1, 2, 1, 1, 2, 2, 1, 2, 2, 2, 1)
    GEN_LOOKUP_TABLE(3, 2, 2, 1, 2, 2, 1, 1, 2, 2, 1, 1, 2)
    GEN_LOOKUP_TABLE(4, 2, 2, 1, 2, 1, 2, 2, 1, 1, 2, 1, 1)
    */

    GEN_LOOKUP_TABLE(1, 2,2,2,2,2,2,2,2,2,2,2,2)
    GEN_LOOKUP_TABLE(2, 2,1,1,1,1,1,1,1,1,1,1,1)
    GEN_LOOKUP_TABLE(3, 1,1,1,1,1,1,1,2,1,1,2,2)
    GEN_LOOKUP_TABLE(4, 1,1,1,1,1,1,2,2,1,1,1,1)

    GEN_RESULT_REGISTER(1)
    GEN_RESULT_REGISTER(2)
    GEN_RESULT_REGISTER(3)
    GEN_RESULT_REGISTER(4)

    action set_mirror_type() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
        ig_md.pkt_type = PKT_TYPE_MIRROR;
    }

    action set_normal_pkt() {
        hdr.bridged_md.setValid();
        hdr.bridged_md.pkt_type = PKT_TYPE_NORMAL;
    }

    action set_md(PortId_t dest_port, bit<1> ing_mir, MirrorId_t ing_ses, bit<1> egr_mir, MirrorId_t egr_ses) {
        ig_tm_md.ucast_egress_port = dest_port;
        ig_md.do_ing_mirroring = ing_mir;
        ig_md.ing_mir_ses = ing_ses;
        hdr.bridged_md.do_egr_mirroring = egr_mir;
        hdr.bridged_md.egr_mir_ses = egr_ses;
    }

    action attach_data() {
        hdr.udp.dst_port = 124;
        hdr.udp.src_port = 12123;
        hdr.mir_hdr_data.mirror_data.sample_len = column_num;
        hdr.mir_hdr_data.mirror_data.s1 = reg_tmp_1;
        hdr.mir_hdr_data.mirror_data.s2 = reg_tmp_2;
        hdr.mir_hdr_data.mirror_data.s3 = reg_tmp_3;
        hdr.mir_hdr_data.mirror_data.s4 = reg_tmp_4;
        hdr.mir_hdr_data.setValid();
    }

    table  mirror_fwd {
        key = {
            ig_intr_md.ingress_port : exact;
        }

        actions = {
            set_md;
        }

        size = 16;
    }

    apply {
        column_num = change.execute(1);

        if(hdr.udp.dst_port == 123) {
            if(ig_intr_md.ingress_port == 142){
            ig_tm_md.ucast_egress_port = 141;
            }
            if(ig_intr_md.ingress_port == 141){
                ig_tm_md.ucast_egress_port = 142;
            }
            Total_len = (bit<32>)hdr.ipv4.total_len;
            ig_md.current_stage.current_stage = add.execute(1);
            table_1_t.apply();
            table_2_t.apply();
            table_3_t.apply();
            table_4_t.apply();
            reg_tmp_1 = plus_1.execute(1);
            reg_tmp_2 = plus_2.execute(1);
            reg_tmp_3 = plus_3.execute(1);
            reg_tmp_4 = plus_4.execute(1);
            if (ig_md.current_stage.current_stage == 1) {
                mirror_fwd.apply();
                attach_data();
            }
            // attach_data();
            if (ig_md.do_ing_mirroring == 1) {
                set_mirror_type();
            }
            set_normal_pkt();
        }
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_metadata;
    }

    state parse_metadata {
        mirror_h mirror_md = pkt.lookahead<mirror_h>();
        transition select(mirror_md.pkt_type) {
            PKT_TYPE_MIRROR : parse_mirror_md;
            PKT_TYPE_NORMAL : parse_bridged_md;
            default : accept;
        }
    }

    state parse_bridged_md {
        pkt.extract(hdr.bridged_md);
        transition accept;
    }

    state parse_mirror_md {
        mirror_h mirror_md;
        pkt.extract(mirror_md);
        transition accept;
    }


}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    Mirror() mirror;

    apply {

        if (eg_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
            mirror.emit<mirror_h>(eg_md.egr_mir_ses, {eg_md.pkt_type});
        }
    }
}

// ---------------------------------------------------------------------------
// Switch Egress MAU
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout headers_t hdr,
        inout metadata_t eg_md,
        in    egress_intrinsic_metadata_t                 eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    action set_mirror() {
        eg_md.egr_mir_ses = hdr.bridged_md.egr_mir_ses;
        eg_md.pkt_type = PKT_TYPE_MIRROR;
        eg_dprsr_md.mirror_type = MIRROR_TYPE_E2E;
#if __TARGET_TOFINO__ != 1
        eg_dprsr_md.mirror_io_select = 1; // E2E mirroring for Tofino2 & future ASICs
#endif
    }

    apply {

        if (hdr.bridged_md.do_egr_mirroring == 1) {
            set_mirror();
        }
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
