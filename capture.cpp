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

// Define the interfaces and MTU
const char* interfaces[] = {"ens3f0np0", "ens3f1np1", "ens6f0np0", "ens6f1np1"};
const int MTU = 9000;
const int num_frames = 100;

const int ETH_HDR_SIZE = 14; // Ethernet header size
const int IP_HDR_SIZE = 20; // IP header size
const int UDP_HDR_SIZE = 8; // UDP header size
const int CODIF_HDR_SIZE = 64; // CODIF header size
const int TOTAL_HDR_SIZE = ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + CODIF_HDR_SIZE;


inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true) {
    if (code != cudaSuccess) {
        std::cerr << "GPUassert: " << cudaGetErrorString(code) << " " << file << " " << line << std::endl;
    }
}

// Define the GPUERRCHK macro
#define GPUERRCHK(ans) { gpuAssert((ans), __FILE__, __LINE__); }

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

// Function to initialize the context and QP
ibv_qp* init_qp(ibv_context* context, ibv_pd* pd, ibv_cq* cq) {
    ibv_qp_init_attr qp_init_attr = {};
    qp_init_attr.send_cq = cq;
    qp_init_attr.recv_cq = cq;
    qp_init_attr.cap.max_send_wr = num_frames;
    qp_init_attr.cap.max_recv_wr = num_frames;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
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

    create_and_attach_default_flow(qp);

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
    printf("Network interfaces for RDMA device %s:\n",  ibname);
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
            std::cout << "Interface: " << interface_name << ", IP Address: " << ip << std::endl;
            freeifaddrs(ifaddr);
            return;
        }        
    }

    std::cerr << "No IPv4 address found for interface: " << interface_name << std::endl;
    freeifaddrs(ifaddr);
    addr = nullptr;
}

void subscribe_to_multicast(const char* interface_name, const char* multicast_ip, uint16_t udp_port) {
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

    // Get the IP address of the interface
    struct sockaddr_in addr;
    get_interface_ip(interface_name, &addr);
    if (addr.sin_addr.s_addr == 0) {
        std::cerr << "Failed to get IP address for interface: " << interface_name << std::endl;
        close(sock);
        return;
    }

    // Set the interface for the multicast group
    mreq.imr_interface.s_addr = addr.sin_addr.s_addr;

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

void post_recv(ibv_qp* qp, ibv_mr* mr, void* buffer, uint64_t id, int num_frames) {
    ibv_sge sge = {};
    sge.addr = reinterpret_cast<uintptr_t>(buffer);
    sge.length = num_frames * MTU;
    sge.lkey = mr->lkey;

    ibv_recv_wr wr = {};
    wr.wr_id = id;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    ibv_recv_wr* bad_wr;
    if (ibv_post_recv(qp, &wr, &bad_wr)) {
        std::cerr << "Failed to post receive work request: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        exit(1);
    }
}
int main(int argc, char* argv[]) {
    bool save_gpu = false;
    int cuda_dev = 0;
    int num_devices = 2; // Default value
    int num_frames = 100; // Default value
    int num_blocks = 1; // Number of blocks to capture

    // Define long options
    static struct option long_options[] = {
        {"save-gpu", no_argument, nullptr, 'g'},
        {"cuda-dev", required_argument, nullptr, 'd'},
        {"num-devices", required_argument, nullptr, 'n'},
        {"num-frames", required_argument, nullptr, 'f'},
        {"num-blocks", required_argument, nullptr, 'b'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "gd:n:f:", long_options, nullptr)) != -1) {
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
            default:
                std::cerr << "Usage: " << argv[0] << " [--save-gpu] [--cuda-dev <device>] [--num-devices <count>] [--num-frames <count>] [--num-blocks <count>]" << std::endl;
                return 1;
        }
    }

    if (save_gpu) {
        GPUERRCHK(cudaSetDevice(cuda_dev));
        cudaDeviceProp prop;
        GPUERRCHK(cudaGetDeviceProperties(&prop, cuda_dev));
        std::cout << "Using GPU device: " << cuda_dev << " " << prop.name <<
            " Supports GPUDirect? " << (prop.tccDriver ? "Yes (TCC mode)" : "No (likely WDDM or not supported)") << std::endl;
    }

    // Get the list of devices
    ibv_device** device_list = ibv_get_device_list(&num_devices);
    if (!device_list) {
        std::cerr << "Failed to get IB devices list: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        return 1;
    }

    num_devices = 2; // For testing, we will only use one device

    std::vector<ibv_context*> contexts(num_devices);
    std::vector<ibv_pd*> pds(num_devices);
    std::vector<ibv_cq*> cqs(num_devices);
    std::vector<ibv_qp*> qps(num_devices);
    std::vector<std::ofstream> files(num_devices);
    std::vector<char*> gpu_buffers(num_devices);
    std::vector<char*> cpu_buffers(num_devices);
    std::vector<ibv_mr*> mrs(num_devices);    

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

    for (int i = 0; i < num_devices; ++i) {
        files[i].open(std::string(interfaces[i]) + ".raw", std::ios::binary);

        std::cout << "Opening device " << interfaces[i] << "..." << std::endl;
        contexts[i] = ibv_open_device(ibv_get_device_list(nullptr)[i]);

        // Get IP
        char ethname[256];
        ibname_to_ethname(interfaces[i], ethname);
        std::cout << "Device " << i << ": " << interfaces[i] << " " << ethname << " " << std::endl;
        struct sockaddr_in ipaddr;
        get_interface_ip(ethname, &ipaddr);
        if (i == 0) {
            subscribe_to_multicast(ethname, "239.17.0.1", 36001);
            subscribe_to_multicast(ethname, "239.17.0.1", 36002);
        } else if (i == 1) {
            subscribe_to_multicast(ethname, "239.17.0.2", 36003);
            subscribe_to_multicast(ethname, "239.17.0.3", 36004);
        }

        if (!contexts[i]) {
            std::cerr << "Failed to open device " << interfaces[i] << ": " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
            exit(1);
        }

        pds[i] = ibv_alloc_pd(contexts[i]);
        if (!pds[i]) {
            std::cerr << "Failed to allocate PD: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
            exit(1);
        }

        cqs[i] = ibv_create_cq(contexts[i], num_frames, nullptr, nullptr, 0);
        if (!cqs[i]) {
            std::cerr << "Failed to create CQ: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
            exit(1);
        }

        qps[i] = init_qp(contexts[i], pds[i], cqs[i]);

        // Allocate GPU memory
        cpu_buffers[i] = (char*) malloc(num_frames * MTU);
        memset(cpu_buffers[i], 0, num_frames * MTU);

        if (save_gpu) {
            GPUERRCHK(cudaMalloc(&gpu_buffers[i], num_frames * MTU));
            GPUERRCHK(cudaDeviceSynchronize()); // Ensure memory is ready
            GPUERRCHK(cudaMemset(gpu_buffers[i], 0, num_frames * MTU));
        } else {
            gpu_buffers[i] = cpu_buffers[i];            
        }
        

        // Register memory region
        mrs[i] = ibv_reg_mr(pds[i], gpu_buffers[i], num_frames * MTU, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
        if (!mrs[i]) {
            std::cerr << "Failed to register memory region: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
            exit(1);
        }
    }

    // Post recieve work requests
    for (int i = 0; i < num_devices; ++i) {
        for (int j = 0; j < num_frames; ++j) {
            post_recv(qps[i], mrs[i], gpu_buffers[i] + j*MTU, j, 1);
        }
    }

    for (int blk = 0; blk < num_blocks; blk++) { 
        // Main loop to capture packets
        for (int j = 0; j < num_frames; ++j) {
            for (int i = 0; i < num_devices; ++i) {
                
                ibv_wc wc;
                //std::cout << "Waiting for poll completion " << std::endl;
                while (ibv_poll_cq(cqs[i], 1, &wc) < 1) { // busy wait.
                    //printf("Header: 0x%x\n", *(uint32_t*)gpu_buffers[i]);
                }
                //std::cout << " Completion polled " << std::endl;
                if (wc.status != IBV_WC_SUCCESS) {
                    std::cerr << "Failed to poll CQ: " << ibv_wc_status_str(wc.status) << " (status: " << wc.status << ")" << std::endl;
                    exit(1);
                }
                auto size_to_copy = wc.byte_len;
                auto jframe = wc.wr_id; // ID - set to the frame number where the data was written
                
                // size_to_copy = MTU; // Copy everything back
                size_to_copy = TOTAL_HDR_SIZE; // Don't copy all the data
                if (save_gpu) {
                    GPUERRCHK(cudaMemcpy(cpu_buffers[i] + jframe*MTU, gpu_buffers[i] + jframe*MTU, size_to_copy, cudaMemcpyDeviceToHost));
                } 

                // Write whole packet to file
                // files[i].write(reinterpret_cast<char*>(cpu_buffers[i]) + j * MTU , MTU);
                
                // Only write the CODIF header
                bool is_codif = wc.byte_len == 8298; // There are more rigorous checks, but this is easy.
                //std::cout << "Byte len" << wc.byte_len << " is codif " << is_codif << std::endl;
                files[i].write(reinterpret_cast<char*>(cpu_buffers[i]) + jframe * MTU + ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE, CODIF_HDR_SIZE);

                // send the buffer back to the QP
                post_recv(qps[i], mrs[i], gpu_buffers[i] + jframe*MTU, j, 1);                
            }
        }
    }

    // Cleanup
    for (int i = 0; i < num_devices; ++i) {
        files[i].close();
        ibv_dereg_mr(mrs[i]);
        ibv_destroy_qp(qps[i]);
        ibv_destroy_cq(cqs[i]);
        ibv_dealloc_pd(pds[i]);
        ibv_close_device(contexts[i]);
        if (save_gpu) {
            GPUERRCHK(cudaFree(gpu_buffers[i]));
        } else {
            free(gpu_buffers[i]);
        }
    }

    return 0;
}
