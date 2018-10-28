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
#include <v1model.p4>

//------------------------------------------------------------------------------
// DEFINITIONS
//------------------------------------------------------------------------------

#define MAX_PORTS 255

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9> port_t;
typedef bit<16> ptype_t;

typedef bit<48> timestamp_t;
typedef bit<32> path_id_t;

const ptype_t ETH_TYPE_INT = 0x1515; /* In-band Network Telemetry (INT) */
const ptype_t ETH_TYPE_IPV4 = 0x800; /* IPv4 */
const port_t CPU_PORT = 255;

//------------------------------------------------------------------------------
// HEADERS
//------------------------------------------------------------------------------

header ethernet_t {
    macAddr_t dst_addr;
    macAddr_t src_addr;
    ptype_t ether_type;
}

header int_t {
    ptype_t proto_id;
    path_id_t path_id;
    timestamp_t ingress_timestamp;
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
    ip4Addr_t src_addr;
    ip4Addr_t dst_addr;
}

@controller_header("packet_in")
header packet_in_header_t {
	bit<9> packet_in_type;
    port_t ingress_port;
    timestamp_t ingress_global_timestamp;
    timestamp_t egress_global_timestamp;
    port_t egress_port;
}

@controller_header("packet_out")
header packet_out_header_t {
    port_t egress_port;
}

struct headers_t {
    packet_out_header_t pkt_out_hdr;
    packet_in_header_t pkt_in_hdr;
    packet_in_header_t pkt_int_hdr;
    ethernet_t eth_hdr;
    int_t int_hdr;
    ipv4_t ipv4_hdr;
}

struct metadata_t {
	port_t egress_port;
	timestamp_t ingress_timestamp;
}

//------------------------------------------------------------------------------
// PARSER
//------------------------------------------------------------------------------

parser c_parser(packet_in packet,
                out headers_t headers,
                inout metadata_t meta,
                inout standard_metadata_t standard_meta) {

    state start {
        transition select(standard_meta.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(headers.pkt_out_hdr);
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
                  inout standard_metadata_t standard_meta) {

    counter(MAX_PORTS, CounterType.packets_and_bytes) tx_port_counter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) rx_port_counter;

    action send_to_cpu() {
        standard_meta.egress_spec = CPU_PORT;
		headers.pkt_in_hdr.setValid();
		headers.pkt_in_hdr.packet_in_type = 0;
		headers.pkt_in_hdr.ingress_port = standard_meta.ingress_port;
		headers.pkt_in_hdr.ingress_global_timestamp = 0;
		headers.pkt_in_hdr.egress_global_timestamp = 0;
		headers.pkt_in_hdr.egress_port = 0;
    }

    action set_out_port(port_t port) {
        standard_meta.egress_spec = port;
    }

    action _drop() {
        mark_to_drop();
    }

   action int_ingress(path_id_t path_id) {
        headers.int_hdr.setValid();
        headers.int_hdr.path_id = path_id;
        headers.int_hdr.proto_id = headers.eth_hdr.ether_type;
        headers.int_hdr.ingress_timestamp = standard_meta.ingress_global_timestamp;
        headers.eth_hdr.ether_type = ETH_TYPE_INT;
    }

    action int_egress(port_t port) { // clone the packet as I2E clone
		clone(CloneType.I2E, 1234); // need mirroring_mapping_add(1234, CPU_PORT) in the runner's initialization routine
        standard_meta.egress_spec = port;
        meta.egress_port = port;
        meta.ingress_timestamp = headers.int_hdr.ingress_timestamp;
        
		headers.eth_hdr.ether_type = headers.int_hdr.proto_id;
        headers.int_hdr.setInvalid();
    }
    
    direct_counter(CounterType.packets_and_bytes) l2_fwd_counter;

    table t_l2_fwd {
        key = {
            standard_meta.ingress_port  : ternary;
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
        counters = l2_fwd_counter;
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

    apply {
        if (standard_meta.ingress_port == CPU_PORT) {
            standard_meta.egress_spec = headers.pkt_out_hdr.egress_port;
            headers.pkt_out_hdr.setInvalid();
        } else {
            if (t_l2_fwd.apply().hit) {
                return;
            }
            if (!headers.int_hdr.isValid() && headers.ipv4_hdr.isValid()) {
                t_int_ingress.apply();
            }
            if (headers.int_hdr.isValid()) {
                t_int_fwd.apply();
            }
        }

        if (standard_meta.egress_spec < MAX_PORTS) {
            tx_port_counter.count((bit<32>) standard_meta.egress_spec);
        }
        if (standard_meta.ingress_port < MAX_PORTS) {
            rx_port_counter.count((bit<32>) standard_meta.ingress_port);
        }
     }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control c_egress(inout headers_t headers,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_meta) {

    action send_clone_to_cpu() { // send the I2E clone to the CPU
        standard_meta.egress_spec = CPU_PORT;
  		headers.pkt_in_hdr.setValid();
  		headers.pkt_in_hdr.packet_in_type = 1;
  		headers.pkt_in_hdr.ingress_port = standard_meta.ingress_port;
   		headers.pkt_in_hdr.ingress_global_timestamp = meta.ingress_timestamp;
   		headers.pkt_in_hdr.egress_global_timestamp = standard_meta.egress_global_timestamp;
   		headers.pkt_in_hdr.egress_port = meta.egress_port; // non serve più se la egress deve solo inoltrare il clone alla CPU
    }
    
    table t_int_egress {
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

control c_deparser(packet_out packet, in headers_t headers) {
    apply {
    	packet.emit(headers.pkt_in_hdr);
    	packet.emit(headers.pkt_int_hdr);
    	packet.emit(headers.eth_hdr);
    	packet.emit(headers.int_hdr);
    	packet.emit(headers.ipv4_hdr);
    }
}

//------------------------------------------------------------------------------
// SWITCH INSTANTIATION
//------------------------------------------------------------------------------

V1Switch(c_parser(),
         c_verify_checksum(),
         c_ingress(),
         c_egress(),
         c_compute_checksum(),
         c_deparser()) main;
