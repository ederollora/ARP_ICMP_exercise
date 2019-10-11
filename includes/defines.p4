
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> ARP_REQ = 0x0001;
const bit<16> ARP_REP = 0x0002;

const bit<16> TYPE_ARP  = 0x0806;
const bit<16> TYPE_IPV4 = 0x0800;

const bit<8> TYPE_ICMP = 0x01;
const bit<8> TYPE_TCP  = 0x06;
const bit<8> TYPE_UDP  = 0x11;

const bit<8> ICMP_REQ = 0x08;
const bit<8> ICMP_REP = 0x00;
