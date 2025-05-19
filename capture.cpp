#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cerrno>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <infiniband/verbs.h>
#include <cuda_runtime.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <cassert>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <pcap.h>
#include <sys/time.h> // Include for gettimeofday()
#include <codifio.h>


// Define the interfaces and MTU
const char* interfaces[] = {"ens3f0np0", "ens3f1np1", "ens6f0np0", "ens6f1np1"};
const int MTU = (9000/64 + 1) * 64; // 9000 bytes, aligned to 64 bytes
const int num_frames = 100;

const int ETH_HDR_SIZE = 14; // Ethernet header size
const int IP_HDR_SIZE = 20; // IP header size
const int UDP_HDR_SIZE = 8; // UDP header size
const int CODIF_HDR_SIZE = 64; // CODIF header size
const int TOTAL_HDR_SIZE = ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + CODIF_HDR_SIZE;

// Define a structure to hold multicast IP address and port
struct MulticastGroup {
    char ip[16];       // Multicast IP address (IPv4, max length 15 + null terminator)
    uint16_t port;     // Port number
};

// Pre-defined list of multicast groups
const MulticastGroup multicast_groups[] = {
    {"239.17.0.1", 36001},
    {"239.17.0.2", 36002},
    {"239.17.0.3", 36003},
    {"239.17.0.4", 36004}
};

inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true) {
    if (code != cudaSuccess) {
        std::cerr << "GPUassert: " << cudaGetErrorString(code) << " " << file << " " << line << std::endl;
    }
}

// Define the GPUERRCHK macro
#define GPUERRCHK(ans) { gpuAssert((ans), __FILE__, __LINE__); }

/**
 * Function to create and attach a default flow to the QP.
 * This flow matches all packets and is used as a fallback.
 * @param qp Pointer to the QP to attach the flow to.
 * @return Pointer to the created flow.
 */
struct ibv_flow* create_and_attach_default_flow(ibv_qp* qp) {
    struct ibv_flow_attr *flow_attr;
    struct ibv_flow_spec_eth *eth_spec;
    void *buf;

    buf = calloc(1, sizeof(*flow_attr) + sizeof(*eth_spec));
    flow_attr = (struct ibv_flow_attr*) buf;
    eth_spec = (struct ibv_flow_spec_eth *)(flow_attr + 1);

    flow_attr->type = IBV_FLOW_ATTR_NORMAL;
    flow_attr->size = sizeof(*flow_attr) + sizeof(*eth_spec);
    flow_attr->priority = 0;
    flow_attr->num_of_specs = 0; // Should be 1. 
    flow_attr->port = 1;
    flow_attr->flags = 0;

    eth_spec->type = IBV_FLOW_SPEC_ETH;
    eth_spec->size = sizeof(*eth_spec);
    memset(&eth_spec->val, 0, sizeof(eth_spec->val));   // Match all
    memset(&eth_spec->mask, 0, sizeof(eth_spec->mask)); // No filtering

    struct ibv_flow *flow = ibv_create_flow(qp, flow_attr);
    if (! flow) {
        std::cerr << "Failed to create flow: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        free(buf);
        exit(1);
    }
    return flow;
}

/**
 * ]Function to create a flow that matches UDP packets with a specific destination port.
 * @param qp Pointer to the QP to attach the flow to.
 * @param udp_dport The destination port to match.
 */
struct ibv_flow* create_udp_flow(ibv_qp* qp, uint16_t udp_dport, uint32_t src_ip=0) {
    // Allocate memory for flow attributes and specs
    size_t flow_size = sizeof(struct ibv_flow_attr) +
                       sizeof(struct ibv_flow_spec_eth) +
                       sizeof(struct ibv_flow_spec_ipv4) +
                       sizeof(struct ibv_flow_spec_tcp_udp);
    void* flow_mem = calloc(1, flow_size);

    struct ibv_flow_attr* flow_attr = (struct ibv_flow_attr*)flow_mem;
    struct ibv_flow_spec_eth* eth_spec = (struct ibv_flow_spec_eth*)(flow_attr + 1);
    struct ibv_flow_spec_ipv4* ipv4_spec = (struct ibv_flow_spec_ipv4*)(eth_spec + 1);
    struct ibv_flow_spec_tcp_udp* udp_spec = (struct ibv_flow_spec_tcp_udp*)(ipv4_spec + 1);

    // Configure flow attributes
    flow_attr->type = IBV_FLOW_ATTR_NORMAL;
    flow_attr->size = flow_size;
    flow_attr->priority = 0;
    flow_attr->num_of_specs = 3; // ETH + IPv4 + UDP
    flow_attr->port = 1;         // Port number (depends on your setup)
    flow_attr->flags = 0;

    // Configure Ethernet spec (match all Ethernet frames)
    eth_spec->type = IBV_FLOW_SPEC_ETH;
    eth_spec->size = sizeof(struct ibv_flow_spec_eth);
    memset(&eth_spec->val, 0, sizeof(eth_spec->val));   // Match all
    memset(&eth_spec->mask, 0, sizeof(eth_spec->mask)); // No filtering

    // Configure IPv4 spec (match all IPv4 packets)
    ipv4_spec->type = IBV_FLOW_SPEC_IPV4;
    ipv4_spec->size = sizeof(struct ibv_flow_spec_ipv4);
    memset(&ipv4_spec->val, 0, sizeof(ipv4_spec->val));   // Match all
    memset(&ipv4_spec->mask, 0, sizeof(ipv4_spec->mask)); // No filtering
    if (src_ip != 0) {
        ipv4_spec->val.src_ip = htonl(src_ip); //match given source IP
        ipv4_spec->mask.src_ip = 0xFFFFFFFF; // Filter on source IP
        struct in_addr ip_addr;
        ip_addr.s_addr = ntohl(src_ip);
        std::cout << "IP Address: " << inet_ntoa(ip_addr) << std::endl;
    }

    // Configure UDP spec (filter by destination port)
    udp_spec->type = IBV_FLOW_SPEC_UDP;
    udp_spec->size = sizeof(struct ibv_flow_spec_tcp_udp);
    udp_spec->val.dst_port = htons(udp_dport); // Destination port to match
    udp_spec->mask.dst_port = 0xFFFF;          // Exact match on destination port
    udp_spec->val.src_port = 0;                // Match all source ports
    udp_spec->mask.src_port = 0;               // No filtering on source port


    // Attach the flow to the QP
    struct ibv_flow* flow = ibv_create_flow(qp, flow_attr);
    if (!flow) {
        std::cerr << "Failed to create flow: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        free(flow_mem);
        return nullptr;
    }

    free(flow_mem);
    return flow;
}

// Function to initialize the context and QP
ibv_qp* init_qp(ibv_context* context, ibv_pd* pd, ibv_cq* cq) {
    ibv_qp_init_attr qp_init_attr = {};
    qp_init_attr.send_cq = cq;
    qp_init_attr.recv_cq = cq;
    qp_init_attr.cap.max_send_wr = 1;
    qp_init_attr.cap.max_recv_wr = num_frames;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 2;
    qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;

    ibv_qp* qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp) {
        std::cerr << "Failed to create QP: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        exit(1);
    }

    ibv_qp_attr attr = {};
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = 1;
    //attr.pkey_index = 0; // don't do for raw packet - g et invalid argument
    //attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE; 
    
    if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_PORT)) {
        std::cerr << "Failed to modify QP to INIT: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        exit(1);
    }

    attr.qp_state = IBV_QPS_RTR;
    if (ibv_modify_qp(qp, &attr, IBV_QP_STATE)) {
        std::cerr << "Failed to modify QP to RTR: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        exit(1);
    }

    attr.qp_state = IBV_QPS_RTS;
    if (ibv_modify_qp(qp, &attr, IBV_QP_STATE)) {
        std::cerr << "Failed to modify QP to RTS: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        exit(1);
    }

    //create_and_attach_default_flow(qp);

    return qp;
}

void ibname_to_ethname(const char* ibname, char* ethname) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/infiniband/%s/device/net", ibname);

    DIR *dir = opendir(path);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    //printf("Network interfaces for RDMA device %s:\n",  ibname);
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            printf("  %s\n", entry->d_name);
            strcpy(ethname, entry->d_name);
            return;
        }
    }

    closedir(dir);
}

void get_interface_ip(const char* interface_name, struct sockaddr_in* addr) {
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Failed to get network interfaces: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        return;
    }

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || strcmp(ifa->ifa_name, interface_name) != 0) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET) { // IPv4
            char ip[INET_ADDRSTRLEN];
            *addr = *(struct sockaddr_in*)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            //std::cout << "Interface: " << interface_name << ", IP Address: " << ip << std::endl;
            freeifaddrs(ifaddr);
            return;
        }        
    }

    std::cerr << "No IPv4 address found for interface: " << interface_name << std::endl;
    freeifaddrs(ifaddr);
    addr = nullptr;
}

void subscribe_to_multicast(const char* interface_name, ibv_qp* qp, const char* multicast_ip, uint16_t udp_port) {

    // Get IP
    char ethname[256];
    ibname_to_ethname(interface_name, ethname);
    //std::cout << "Device " << interface_name << " " << ethname << " " << std::endl;
    struct sockaddr_in ipaddr;
    get_interface_ip(ethname, &ipaddr);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        return;
    }

    // Bind the socket to the specified port
    struct sockaddr_in local_addr = {};
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(udp_port);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Bind to all local interfaces

    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        std::cerr << "Failed to bind socket to port " << udp_port << ": " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        close(sock);
        return;
    }

    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));

    // Set the multicast group address
    mreq.imr_multiaddr.s_addr = inet_addr(multicast_ip);
    if (mreq.imr_multiaddr.s_addr == INADDR_NONE) {
        std::cerr << "Invalid multicast IP address: " << multicast_ip << std::endl;
        close(sock);
        return;
    }

    if (ipaddr.sin_addr.s_addr == 0) {
        std::cerr << "Failed to get IP address for interface: " << interface_name << std::endl;
        close(sock);
        return;
    }

    // Set the interface for the multicast group
    mreq.imr_interface.s_addr = ipaddr.sin_addr.s_addr;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &mreq.imr_interface.s_addr, ip_str, INET_ADDRSTRLEN);
    std::cout << "Joining multicast group " << multicast_ip << " on interface " << ip_str << std::endl;

    // Subscribe to the multicast group
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        std::cerr << "Failed to join multicast group: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        close(sock);
        return;
    }

    std::cout << "Successfully subscribed " << interface_name << " to multicast group " 
              << multicast_ip << " on port " << udp_port << std::endl;

    // Close the socket
    //close(sock);
}


void parse_packet(char *packet, 
    struct ether_header** eth,
                   struct ip** ip_hdr, 
                   struct udphdr** udp_hdr,
                    struct codif_header** codif_hdr) {
    *eth = (struct ether_header *)packet;
    *ip_hdr = nullptr;
    *udp_hdr = nullptr;

    if (ntohs((*eth)->ether_type) != ETHERTYPE_IP) {
       // printf("Not an IP packet\n");
        return;        
    }

    *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

    if ((*ip_hdr)->ip_p != IPPROTO_UDP) {
       // printf("Not a UDP packet\n");
        return;
    }

    int ip_hdr_len = (*ip_hdr)->ip_hl * 4;
    *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_hdr_len);

    *codif_hdr = (struct codif_header *)(packet + sizeof(struct ether_header) + ip_hdr_len + UDP_HDR_SIZE);

    //printf("UDP Source Port: %u\n", ntohs((*udp_hdr)->uh_sport));
    //printf("UDP Dest Port  : %u\n", ntohs((*udp_hdr)->uh_dport));
}

void post_recv(ibv_qp* qp, ibv_mr* header_mr, ibv_mr* mr, char* header_buffer, char* data_buffer, 
    uint32_t frame_id, uint32_t qpid, bool separate_header) {
    ibv_sge sge[2] = {}; // Array to hold up to 2 SGEs

    if (separate_header) {
        // First SGE: Headers in the header buffer
        sge[0].addr = reinterpret_cast<uintptr_t>(header_buffer + frame_id * MTU);
        sge[0].length = TOTAL_HDR_SIZE; // Length of the headers
        sge[0].lkey = header_mr->lkey;

        // Second SGE: Rest of the packet in the data buffer
        sge[1].addr = reinterpret_cast<uintptr_t>(data_buffer + frame_id * MTU );
        sge[1].length = MTU - TOTAL_HDR_SIZE; // Remaining packet size
        sge[1].lkey = mr->lkey;
    } else {
        // Single SGE: Entire packet in the data buffer
        sge[0].addr = reinterpret_cast<uintptr_t>(data_buffer + frame_id * MTU);
        sge[0].length = MTU; // Full packet size
        sge[0].lkey = mr->lkey;
    }

    ibv_recv_wr wr = {};
    wr.wr_id = static_cast<uint64_t>(qpid) << 32 | frame_id; // Encode QP ID and frame ID
    wr.sg_list = sge;
    wr.num_sge = separate_header ? 2 : 1; // Use 2 SGEs if save_gpu is enabled, otherwise 1

    ibv_recv_wr* bad_wr;
    if (ibv_post_recv(qp, &wr, &bad_wr)) {
        std::cerr << "Failed to post receive work request: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        exit(1);
    }
}
void print_device_list()
{
    int num_devices = 0;
    // Get the list of devices
    ibv_device** device_list = ibv_get_device_list(&num_devices);
    if (!device_list) {
        std::cerr << "Failed to get IB devices list: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        exit(-1);
    }
    
    // Print the list of devices
    std::cout << "Available devices:" << std::endl;
    for (int i = 0; i < num_devices; ++i) {
        interfaces[i] = ibv_get_device_name(device_list[i]);
        char ethname[256];
        ibname_to_ethname(interfaces[i], ethname);
        std::cout << "Device " << i << ": " << interfaces[i] << " " << ethname << " " << std::endl;
        struct sockaddr_in ipaddr;
        get_interface_ip(ethname, &ipaddr);
    }

    // Free the device list
    ibv_free_device_list(device_list);
}
// Define the format enum
enum class Format {
    NONE,      // No format specified
    RAW,       // Write raw packets
    CODIFHDR   // Write only CODIF headers
};

int main(int argc, char* argv[]) {
    bool save_gpu = false;
    int cuda_dev = 0;
    int num_devices = 1; // Default value
    int num_frames = 100; // Default value
    int num_blocks = 1; // Number of blocks to capture
    int num_muliticast_groups = 1;
    int num_sge = 1; // Number of scatter gather entries per work request
    bool verbose = false;
    int num_antennas = 1; // Default value for num_antennas
    Format format = Format::NONE; // Default: no format specified
    std::string formatstr("none");

    // Define long options
    static struct option long_options[] = {
        {"save-gpu", no_argument, nullptr, 'g'},
        {"cuda-dev", required_argument, nullptr, 'd'},
        {"num-devices", required_argument, nullptr, 'n'},
        {"num-frames", required_argument, nullptr, 'f'},
        {"num-blocks", required_argument, nullptr, 'b'},
        {"num-multicast-groups", required_argument, nullptr, 'm'},
        {"num-sge", required_argument, nullptr, 's'},
        {"num-antennas", required_argument, nullptr, 'a'}, // New option for num_antennas
        {"verbose", no_argument, nullptr, 'v'},
        {"format", required_argument, nullptr, 'F'}, // New format option
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "gd:n:f:b:m:s:a:vF:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'g':
                save_gpu = true;
                break;
            case 'd':
                cuda_dev = std::atoi(optarg);
                break;
            case 'n':
                num_devices = std::atoi(optarg);
                break;
            case 'f':
                num_frames = std::atoi(optarg);
                break;
            case 'b':
                num_blocks = std::atoi(optarg);
                break;
            case 'm':
                num_muliticast_groups = std::atoi(optarg);
                break;
            case 's':
                num_sge = std::atoi(optarg);
                break;
            case 'a': // Handle the num_antennas option
                num_antennas = std::atoi(optarg);
                if (num_antennas <= 0) {
                    std::cerr << "Invalid number of antennas: " << num_antennas << ". Must be greater than 0." << std::endl;
                    return 1;
                }
                break;
            case 'v':
                verbose = true;
                break;
            case 'F': // Handle the format option
                if (strcmp(optarg, "raw") == 0) {
                    format = Format::RAW;
                } else if (strcmp(optarg, "codifhdr") == 0) {
                    format = Format::CODIFHDR;
                } else {
                    std::cerr << "Invalid format: " << optarg << ". Supported formats are 'raw' and 'codifhdr'." << std::endl;
                    return 1;
                }
                formatstr.assign(optarg);
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " [--save-gpu] [--cuda-dev <device>] [--num-devices <count>] [--num-frames <count>] [--num-blocks <count>] [--num-multicast-groups <count>] [--num-antennas <count>] [--format <raw|codifhdr>]" << std::endl;
                return 1;
        }
    }

    // Print the number of antennas for debugging
    if (verbose) {
        std::cout << "Number of antennas: " << num_antennas << std::endl;
    }

    if (save_gpu) {
        GPUERRCHK(cudaSetDevice(cuda_dev));
        cudaDeviceProp prop;
        GPUERRCHK(cudaGetDeviceProperties(&prop, cuda_dev));
        std::cout << "Using GPU device: " << cuda_dev << " " << prop.name <<
            " Supports GPUDirect? " << (prop.tccDriver ? "Yes (TCC mode)" : "No (likely WDDM or not supported)") << std::endl;
    }

    pcap_t* pcap = pcap_open_dead(DLT_EN10MB, MTU); // Ethernet link-layer, max packet size
    if (!pcap) {
        std::cerr << "Failed to open pcap handle" << std::endl;
        return -1;
    }
    const char* pcap_filename = "capture.pcap";
    pcap_dumper_t* dumper = pcap_dump_open(pcap, pcap_filename);
    if (!dumper) {
        std::cerr << "Failed to open pcap file: " << pcap_geterr(pcap) << std::endl;
        pcap_close(pcap);
        return -1;
    }

    print_device_list();
    
    int num_qps = num_muliticast_groups * num_antennas;
    int num_threads = 2;
    
    std::vector<ibv_context*> contexts(num_devices);
    std::vector<ibv_cq*> shared_cqs(num_devices);

    std::vector<ibv_pd*> pds(num_qps);
    std::vector<ibv_qp*> qps(num_qps);
    std::vector<std::ofstream> files(num_qps);
    std::vector<char*> gpu_buffers(num_qps);
    std::vector<char*> cpu_buffers(num_qps);
    std::vector<ibv_mr*> header_mrs(num_qps);
    std::vector<ibv_mr*> mrs(num_qps);
    std::vector<uint64_t> frame_numbers(num_threads*num_qps*20);
    std::fill(frame_numbers.begin(), frame_numbers.end(), 0);


    for (int idevice = 0; idevice < num_devices; idevice++) {
        std::cout << "Opening device " << idevice << interfaces[idevice] << "..." << std::endl;

        contexts[idevice] = ibv_open_device(ibv_get_device_list(nullptr)[idevice]);
        if (!contexts[idevice]) {
            std::cerr << "Failed to open device " << interfaces[idevice] << ": " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
            exit(1);
        }
        shared_cqs[idevice] = ibv_create_cq(contexts[idevice], num_frames * num_muliticast_groups, nullptr, nullptr, 0);
        if (!shared_cqs[idevice]) {
            std::cerr << "Failed to create shared CQ for device " << idevice << ": " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
            exit(1);
        }
    }

    for (int igroup = 0; igroup < num_muliticast_groups; ++igroup) {
        for (int iant = 0; iant < num_antennas; iant++) {
            int iqp = igroup * num_antennas + iant;
            int idevice = igroup % num_devices; // Multicast group goes to the device
            
            std::string filename = std::string(multicast_groups[iqp].ip) 
            + std::string("ant") 
            + std::to_string(iant) 
            + "." + formatstr;
            if (format != Format::NONE) {
                files[iqp].open(filename, std::ios::binary);
            }

            pds[iqp] = ibv_alloc_pd(contexts[idevice]);
            if (!pds[iqp]) {
                std::cerr << "Failed to allocate PD: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
                exit(1);
            }

            // Use the shared CQ for the corresponding device context
            qps[iqp] = init_qp(contexts[idevice], pds[iqp], shared_cqs[idevice]);

            // Allocate CPU memory
            cpu_buffers[iqp] = (char*)malloc(num_frames * MTU);
            memset(cpu_buffers[iqp], 0, num_frames * MTU);

            if (save_gpu) {
                GPUERRCHK(cudaMalloc(&gpu_buffers[iqp], num_frames * MTU));
                GPUERRCHK(cudaDeviceSynchronize()); // Ensure memory is ready
                GPUERRCHK(cudaMemset(gpu_buffers[iqp], 0, num_frames * MTU));
                // Also make the CPU buffer a MR
                header_mrs[iqp] = ibv_reg_mr(pds[iqp], cpu_buffers[iqp], num_frames * MTU,
                    IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);

            } else {
                gpu_buffers[iqp] = cpu_buffers[iqp];
            }

            // Register memory region
            mrs[iqp] = ibv_reg_mr(pds[iqp], gpu_buffers[iqp], num_frames * MTU,
                                    IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
            if (!mrs[iqp]) {
                std::cerr << "Failed to register memory region: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
                exit(1);
            }

            for (int jframe = 0; jframe < num_frames; ++jframe) {
                post_recv(qps[iqp], header_mrs[iqp], mrs[iqp], cpu_buffers[iqp], gpu_buffers[iqp], jframe, iqp, save_gpu);
            }
            // now attach to flow
            uint32_t antip = (130 << 24) | (155 << 16) | (178 << 8) | (211 + iant);
            create_udp_flow(qps[iqp], multicast_groups[igroup].port, antip);

        }
}

    uint64_t busy_wait = 0;
    uint64_t total_bytes = 0;
    uint64_t total_packets = 0;
    uint64_t num_mismatches = 0;

    // We'll all ready - now subscribe
    for (int igroup = 0; igroup < num_muliticast_groups; ++igroup) {
        int idevice = igroup % num_devices;
        subscribe_to_multicast(interfaces[idevice], qps[igroup], 
            multicast_groups[igroup].ip, multicast_groups[igroup].port);
    }

    for (int blk = 0; blk < num_blocks; blk++) { 
        // Main loop to capture packets
        int j = 0;
        while (j < num_frames) {
            for (int idevice = 0; idevice < num_devices; ++idevice) {
                ibv_wc wc;
                // Poll the shared CQ for the current device
                if (ibv_poll_cq(shared_cqs[idevice], 1, &wc) < 1) { // Busy wait
                    busy_wait += 1;
                    continue;
                }

                if (wc.status != IBV_WC_SUCCESS) {
                    std::cerr << "Failed to poll CQ: " << ibv_wc_status_str(wc.status) << " (status: " << wc.status << ")" << std::endl;
                    exit(1);
                }

                auto size_to_copy = wc.byte_len;
                uint64_t wrid = wc.wr_id; // ID - set to the frame number where the data was written
                int iqp = static_cast<int>(wc.wr_id >> 32); // Extract the qp number from wr_id
                //int iqp = igroup * num_antennas + iant;
                int iant = iqp % num_antennas; // Extract the antenna number from the QP ID
                int igroup = iqp / num_antennas; // Extract the group number from the QP ID

                int jframe = static_cast<int>(wc.wr_id & 0xFFFFFFFF); // Extract the frame number from wr_id
                assert(igroup >= 0 && igroup < num_muliticast_groups);
                
                total_bytes += wc.byte_len;
                total_packets += 1;

                char* packet = cpu_buffers[iqp] + jframe * MTU;
                struct ether_header* eth;
                struct ip* ip_hdr;
                struct udphdr* uudp_hdr;
                struct codif_header* codif_hdr;
                parse_packet(packet, &eth, &ip_hdr, &uudp_hdr, &codif_hdr);
                bool is_codif;
                                
                if (uudp_hdr != nullptr) {
                    auto dport = (uudp_hdr->uh_dport);
                    is_codif = wc.byte_len == 8298; // My dport parsing is no good. && dport > 36000; // There are more rigorous checks, but this is easy.
                } else {
                    //std::cout << "Not an IP packet" << std::endl;
                    is_codif = false;
                }

                //
                int antid = codif_hdr->groupid - 257;
                assert(antid >= 0 && antid < 6);

                int totalid = codif_hdr->threadid  + num_threads*iqp;
                // Only track for device = i

                if (verbose) {
                    printf("blk =%d dev=%d igroup=%d iant=%d iqp=%d j=%d jframe=%d byte_len=%d codif?=%d sync=%x %d-%d-%d antid=%d totalid=%d %d\n",
                         blk, idevice, igroup, iant, iqp, j, jframe, wc.byte_len, is_codif,
                        codif_hdr->sync, codif_hdr->secondaryid,  codif_hdr->groupid,
                        codif_hdr->threadid, antid, totalid, codif_hdr->frame);
                }

                assert(totalid >= 0 && totalid < frame_numbers.size());

                if (frame_numbers[totalid] == 0) {
                    frame_numbers[totalid] = codif_hdr->frame;
                }
                if (frame_numbers[totalid] != codif_hdr->frame) {
                    if (!verbose) {
                        printf("blk =%d dev=%d igroup=%d iant=%d iqp=%d j=%d jframe=%d byte_len=%d codif?=%d sync=%x %d-%d-%d antid=%d totalid=%d %d",
                            blk, idevice, igroup, iant, iqp, j, jframe, wc.byte_len, is_codif,
                        codif_hdr->sync, codif_hdr->secondaryid,  codif_hdr->groupid,
                        codif_hdr->threadid, antid, totalid, codif_hdr->frame);
                    }
                    std::cout << "Frame number mismatch: " << frame_numbers[totalid] << " != " << codif_hdr->frame << std::endl;
                    num_mismatches += 1;
                }
                frame_numbers[totalid] = (codif_hdr->frame + 1) % 1000000;
                

                // Write based on the specified format
                if (format == Format::RAW) {
                    files[iqp].write(packet, size_to_copy);
                } else if (format == Format::CODIFHDR && is_codif) {
                    files[iqp].write(packet + ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE, CODIF_HDR_SIZE);
                }

                // Write to PCAP only if format is specified
                if (format != Format::NONE) {
                    // Create a PCAP packet header
                    struct timeval tv;
                    gettimeofday(&tv, nullptr);
                    struct pcap_pkthdr header;
                    memset(&header, 0, sizeof(header));
                    header.ts.tv_sec = tv.tv_sec; // Current timestamp (seconds)
                    header.ts.tv_usec = tv.tv_usec; // Microseconds
                    header.caplen = size_to_copy; // Captured length
                    header.len = wc.byte_len; // Original packet length

                    // Write the packet to the PCAP file
                    pcap_dump(reinterpret_cast<u_char*>(dumper), &header, reinterpret_cast<const u_char*>(packet));
                }

                // send the buffer back to the QP
                post_recv(qps[iqp], header_mrs[iqp], mrs[iqp], 
                    cpu_buffers[iqp], gpu_buffers[iqp], jframe, iqp, save_gpu);

                
                // Increment count 
                j += 1;
            }
        }
    }

    std::cout << "Total bytes: " << total_bytes << std::endl;
    std::cout << "Total packets: " << total_packets << std::endl;
    std::cout << "Busy wait: " << busy_wait << std::endl;
    std::cout << "Average bytes per packet: " << (total_bytes / total_packets) << std::endl;
    std::cout << "Busy wait / packet " << (busy_wait / total_packets) << std::endl;
    std::cout << "Num mismatches " << num_mismatches << std::endl;


    // Cleanup
    for (int i = 0; i < num_muliticast_groups; ++i) {
        files[i].close();
        ibv_dereg_mr(mrs[i]);
        ibv_destroy_qp(qps[i]);
        ibv_dealloc_pd(pds[i]);

        if (save_gpu) {
            GPUERRCHK(cudaFree(gpu_buffers[i]));
        } else {
            free(gpu_buffers[i]);
        }
    }

    for (int i = 0; i < num_devices; i++) {
        ibv_destroy_cq(shared_cqs.at(i)); // Destroy the shared CQ for each device
        ibv_close_device(contexts.at(i));
    }

    // Close the PCAP file
    pcap_dump_close(dumper);
    pcap_close(pcap);

    return 0;
}
