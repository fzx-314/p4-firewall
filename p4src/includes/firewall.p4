
control Firewall( inout headers_t hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    action drop() {
        mark_to_drop(standard_metadata);
    }

    action allow_pkt( egressSpec_t port){
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table firewall_tb_udp {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.udp.dstPort : exact;
        }
        actions = {
            drop;
            allow_pkt;
        }
        default_action = drop;
    }

    table firewall_tb_tcp {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.tcp.dstPort : exact;
        }
        actions = {
            drop;
            allow_pkt;
        }
        default_action = drop;
    }


    apply {
        if ( hdr.ipv4.isValid() && hdr.udp.isValid() ) {
            firewall_tb_udp.apply();
        }
        else if ( hdr.ipv4.isValid() && hdr.tcp.isValid() ) {
            firewall_tb_tcp.apply();
        }
        else if ( hdr.icmp.isValid() ) {
            /** Drop all ICMP traffic including iith private IP */
            drop();
        }
        else {
            /** For now dropping all traffic without rule except TCP, UDP and ICMP */
            drop();
        }
    }
}
