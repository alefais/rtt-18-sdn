/*
    Created by Alessandra Fais
    SDN part of the RTT course
    MCSN - University of Pisa
    A.A. 2017/18
 */
 
/*
 * This program describes the pipeline implementing In-band Network Telemetry (INT)
 * application for collecting and reporting network state by the data plane called IntP4App.
 */

#include <core.p4>
#include "./psa.p4"

//------------------------------------------------------------------------------
// DEFINITIONS
//------------------------------------------------------------------------------

#define MAX_PORTS 255

typedef bit<48> MacAddr_t;
typedef bit<32> Ip4Addr_t;
typedef bit<16> Ptype_t;
typedef bit<32> PathId_t;

const Ptype_t ETH_TYPE_INT = 0x1515; /* In-band Network Telemetry (INT) */
const Ptype_t ETH_TYPE_IPV4 = 0x800; /* IPv4 */

//------------------------------------------------------------------------------
// HEADERS
//------------------------------------------------------------------------------

header ethernet_t {
    MacAddr_t dst_addr;
    MacAddr_t src_addr;
    Ptype_t ether_type;
}

header int_t {
    Ptype_t proto_id;
    PathId_t path_id;
    Timestamp_t ingress_timestamp;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    Ip4Addr_t src_addr;
    Ip4Addr_t dst_addr;
}

@controller_header("packet_in")
header packet_in_header_t {
	bit<10> packet_in_type;
    PortId_t ingress_port;
    Timestamp_t ingress_global_timestamp;
    Timestamp_t egress_global_timestamp;
    PortId_t egress_port;
}

@controller_header("packet_out")
header packet_out_header_t {
    PortId_t egress_port;
}

header clone_i2e_metadata_t {
    bit<8> custom_tag;
    MacAddr_t src_addr;
}

struct fwd_metadata_t {
    bit<32> outport;
    PortId_t ingress_port;
    Timestamp_t ingress_timestamp;
}

struct empty_metadata_t {}

struct metadata_t {
    fwd_metadata_t fwd_metadata;
    clone_i2e_metadata_t clone_meta;
    bit<3> custom_clone_id;
}

struct headers_t {
    packet_out_header_t pkt_out_hdr;
    packet_in_header_t pkt_in_hdr;
    packet_in_header_t pkt_int_hdr;
    ethernet_t eth_hdr;
    int_t int_hdr;
    ipv4_t ipv4_hdr;
}

//------------------------------------------------------------------------------
// PARSER
//------------------------------------------------------------------------------

parser CommonParser(packet_in packet,
                out headers_t headers,
                inout metadata_t meta) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(headers.eth_hdr);
        transition select(headers.eth_hdr.ether_type) {
			ETH_TYPE_INT: parse_int;
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_int {
    	packet.extract(headers.int_hdr);
        transition select(headers.int_hdr.proto_id) {
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(headers.ipv4_hdr);
        transition accept;
    }
}

parser IngressParserImpl(packet_in packet,
                out headers_t headers,
                inout metadata_t user_meta,
                in psa_ingress_parser_input_metadata_t istd,
                in empty_metadata_t resubmit_meta,
                in empty_metadata_t recirculate_meta) {

    CommonParser() p;

    state start {
    	transition select(istd.ingress_port) {
            PSA_PORT_CPU: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(headers.pkt_out_hdr);
        transition parse_ethernet;
    }

    state parse_ethernet {
        p.apply(packet, headers, user_meta);
        transition accept;
    }
}

parser EgressParserImpl(packet_in packet,
                out headers_t parsed_hdr,
                inout metadata_t user_meta,
                in psa_egress_parser_input_metadata_t istd,
                in metadata_t normal_meta,
                in clone_i2e_metadata_t clone_i2e_meta,
                in empty_metadata_t clone_e2e_meta) {

    CommonParser() p;

    state start {
        transition select (istd.packet_path) {
           PSA_PacketPath_t.CLONE_I2E: copy_clone_i2e_meta;
           PSA_PacketPath_t.NORMAL: parse_ethernet;
        }
    }

    state copy_clone_i2e_meta {
        user_meta.clone_meta = clone_i2e_meta;
        transition parse_ethernet;
    }

    state parse_ethernet {
        p.apply(packet, parsed_hdr, user_meta);
        transition accept;
    }
}

//------------------------------------------------------------------------------
// CHECKSUM VERIFICATION
//------------------------------------------------------------------------------

control c_verify_checksum(inout headers_t headers, inout metadata_t meta) {
    apply {} /* assume checksum is always correct */
}

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control c_ingress(inout headers_t headers,
                  inout metadata_t meta,
                  in psa_ingress_input_metadata_t istd,
                  inout psa_ingress_output_metadata_t ostd) {

	// TODO: sistema l'implementazione dei counter per PSA
    //Counter(MAX_PORTS, PSA_CounterType_t.PACKETS_AND_BYTES) tx_port_counter;
    //Counter(MAX_PORTS, PSA_CounterType_t.PACKETS_AND_BYTES) rx_port_counter;

    action send_to_cpu() {
        ostd.egress_port = PSA_PORT_CPU;
		headers.pkt_in_hdr.setValid();
		headers.pkt_in_hdr.packet_in_type = 0;
		headers.pkt_in_hdr.ingress_port = istd.ingress_port;
		headers.pkt_in_hdr.ingress_global_timestamp = 0;
		headers.pkt_in_hdr.egress_global_timestamp = 0;
		headers.pkt_in_hdr.egress_port = 0;
		meta.fwd_metadata.ingress_port = istd.ingress_port;
    }

    action set_out_port(PortId_t port) {
        ostd.egress_port = port;
    }

    action _drop() {
        ingress_drop(ostd);
    }

   action int_ingress(PathId_t path_id) {
        headers.int_hdr.setValid();
        headers.int_hdr.path_id = path_id;
        headers.int_hdr.proto_id = headers.eth_hdr.ether_type;
        headers.int_hdr.ingress_timestamp = istd.ingress_timestamp;
        headers.eth_hdr.ether_type = ETH_TYPE_INT;
   }

   action do_clone(CloneSessionId_t session_id) {
        ostd.clone = true;
        ostd.clone_session_id = session_id;
        meta.custom_clone_id = 1;
   }

   action int_egress(PortId_t port) {
        ostd.egress_port = port;
        meta.fwd_metadata.ingress_timestamp = headers.int_hdr.ingress_timestamp;

        headers.eth_hdr.ether_type = headers.int_hdr.proto_id;
        headers.int_hdr.setInvalid();
   }
    
    //DirectCounter(PSA_CounterType_t.PACKETS_AND_BYTES) l2_fwd_counter;

    table t_l2_fwd {
        key = {
            istd.ingress_port  : ternary;
            headers.eth_hdr.dst_addr    : ternary;
            headers.eth_hdr.src_addr    : ternary;
            headers.eth_hdr.ether_type  : ternary;
        }
        actions = {
            set_out_port;
            send_to_cpu;
            _drop;
            NoAction;
        }
        default_action = NoAction();
        //counters = l2_fwd_counter;
    }

    table t_int_ingress {
        key = {
            headers.ipv4_hdr.dst_addr : lpm;
        }
        actions = {
            int_ingress;
            _drop;
        }
        default_action = _drop();
    }

    table t_int_fwd {
        key = {
            headers.int_hdr.path_id : exact;
        }
        actions = {
            set_out_port;
            int_egress;
            _drop;
        }
        default_action = _drop();
    }

    table t_clone {
        key = {
            meta.fwd_metadata.outport : exact;
        }
        actions = {
            do_clone;
        }
    }

    apply {
        if (istd.ingress_port == PSA_PORT_CPU) {
            ostd.egress_port = headers.pkt_out_hdr.egress_port;
            headers.pkt_out_hdr.setInvalid();
        } else {
            if (t_l2_fwd.apply().hit) {
                return;
            }
            if (!headers.int_hdr.isValid() && headers.ipv4_hdr.isValid()) {
                t_int_ingress.apply();
            }
            if (headers.int_hdr.isValid()) {
                t_clone.apply();
                t_int_fwd.apply();
            }
        }

	/* TODO: sistema l'implementazione dei counter per PSA
        if (ostd.egress_port < MAX_PORTS) {
            tx_port_counter.count((bit<32>) ostd.egress_port);
        }
        if (istd.ingress_port < MAX_PORTS) {
            rx_port_counter.count((bit<32>) istd.ingress_port);
        }
     */
    }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control c_egress(inout headers_t headers,
                 inout metadata_t meta,
                 in psa_egress_input_metadata_t istd,
                 inout psa_egress_output_metadata_t ostd) {

    action send_clone_to_cpu() {
        //ostd.egress_port = PSA_PORT_CPU; // TODO: controlla come settare la porta di uscita nella egress pipeline
  		headers.pkt_in_hdr.setValid();
  		headers.pkt_in_hdr.packet_in_type = 1;
  		headers.pkt_in_hdr.ingress_port = meta.fwd_metadata.ingress_port;
   		headers.pkt_in_hdr.ingress_global_timestamp = meta.fwd_metadata.ingress_timestamp;
   		headers.pkt_in_hdr.egress_global_timestamp = istd.egress_timestamp;
   		headers.pkt_in_hdr.egress_port = istd.egress_port;
    }

    table t_int_egress {
    	key = {
    		meta.custom_clone_id : exact;
    	}
    	actions = {
    	    send_clone_to_cpu;
    	    NoAction;
    	}
    	default_action = NoAction();
    }

    apply {
        t_int_egress.apply();
    }
}

//------------------------------------------------------------------------------
// CHECKSUM COMPUTATION
//------------------------------------------------------------------------------

control c_compute_checksum(inout headers_t headers, inout metadata_t meta) {
    apply {}
}

//------------------------------------------------------------------------------
// DEPARSER
//------------------------------------------------------------------------------

control DeparserImpl(packet_out packet, inout headers_t headers) {
    apply {
    	packet.emit(headers.pkt_in_hdr);
    	packet.emit(headers.pkt_int_hdr);
    	packet.emit(headers.eth_hdr);
    	packet.emit(headers.int_hdr);
    	packet.emit(headers.ipv4_hdr);
    }
}

control IngressDeparserImpl(packet_out packet,
        out clone_i2e_metadata_t clone_i2e_meta,
        out empty_metadata_t resubmit_meta,
        out metadata_t normal_meta,
        inout headers_t hdr,
        in metadata_t meta,
        in psa_ingress_output_metadata_t istd) {

    DeparserImpl() common_deparser;

    apply {
        if (psa_clone_i2e(istd)) {
            clone_i2e_meta.custom_tag = (bit<8>) meta.custom_clone_id;
            if (meta.custom_clone_id == 1) {
                clone_i2e_meta.src_addr = hdr.eth_hdr.src_addr;
                //normal_meta = meta; // salva anche altre info (?)
            }
        }
        common_deparser.apply(packet, hdr);
    }
}

control EgressDeparserImpl(packet_out packet,
        out empty_metadata_t clone_e2e_meta,
        out empty_metadata_t recirculate_meta,
        inout headers_t hdr,
        in metadata_t meta,
        in psa_egress_output_metadata_t istd,
        in psa_egress_deparser_input_metadata_t edstd) {

    DeparserImpl() common_deparser;

    apply {
        common_deparser.apply(packet, hdr);
    }
}

//------------------------------------------------------------------------------
// SWITCH INSTANTIATION
//------------------------------------------------------------------------------

IngressPipeline(IngressParserImpl(),
                c_ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               c_egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;