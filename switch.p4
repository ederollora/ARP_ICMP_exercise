/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "includes/defines.p4"
#include "includes/arp.p4"
#include "includes/icmp.p4"
#include "includes/standard_h.p4"


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    // Construct the parser

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
        }
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // (1)
    // Create a table that can forward based on an aux (meta) parameter of size IPAddr
    // We need this table to forward ARP packets based on TPA or any IP packets
    // The action must be regular forwarding, just setting the output port.
    // The key must be based , as said, on an aux parameter/variable see
    // standard_h.p4 file, meta struct.
    // We do this because broadcasting is not straightforward in Bmv2, thus we
    //make a hack to handle ARP broadcasts 

    // (2)
    // Besides, create an "ARP answering" table to check if the current packet being analysed
    // needs to be automatically answered of not. Base your decision on checking
    // the TPA field of ARP packets. The action has to construct an ARP response

    // (3)
    // Finally create an "ICMP answering" table. Its goal is to decide if the
    // current ICMP request has to be answered by the switch or forwarded to the
    // destination. Base your decision on the destination Ipv4 address. The action
    // has to create an ICMP response.

    // (4)
    // The apply block needs first to assign either ARP tpa field or IPv4 destination
    // address to the meta.ipAddr. This will help in regular forwarding
    // Besides here you have to apply the (2) arp table and (3) ICMP table only when
    // those headers are valid and the type is a REQUEST (check defines.p4)
    // Finally if the packet is not an ARP or ICMP packet just apply the regular
    // forwarding table.


    // (1)
    // regular fwd table and action here

    table fwd_tb {
        key = {
            // key
        }
        actions = {
            // your action
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    // (2)
    // "ARP answering" table and action here

    // (3)
    // "ICMP answering" table and action here

    // (4)
    // Main logic of apply logic here
    apply {


        // Here we first assign either ARP tpa or IPv4 dstAddr to aux variable

        // Here construct your main logic, for instance:
        // if this is ARP packet and ARP REQ
        //    apply table ARP
        //    if no hit in table:
        //        apply fwd table

        // else (do the same for ICMP)

        // finally if none of above just apply regular fwd_tb table

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    	update_checksum(
    	    hdr.ipv4.isValid(),{
                hdr.ipv4.version,
    	        hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

        update_checksum_with_payload(
            hdr.icmp.isValid(),{
                hdr.icmp.tp,
                hdr.icmp.code,
                hdr.icmp.id,
                hdr.icmp.seqNum},
            hdr.icmp.chk,
            HashAlgorithm.csum16
        );

        /*update_checksum(
            hdr.icmp.isValid(),{
                hdr.icmp.tp,
                hdr.icmp.code,
                hdr.icmp.id,
                hdr.icmp.seqNum,
                hdr.icmp_ts.timestamp,
                hdr.icmp_p.payload },
            hdr.icmp.chk,
            HashAlgorithm.csum16
        );*/
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
