#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cerrno>
#include <infiniband/verbs.h>
#include <cuda_runtime.h>

// Define the interfaces and MTU
const char* interfaces[] = {"ens3f0np0", "ens3f1np1", "ens6f0np0", "ens6f1np1"};
const int MTU = 9000;
const int num_frames = 1000;


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

int main() {
    bool save_gpu = false;
    if (save_gpu) {
        GPUERRCHK(cudaSetDevice(0));
    }

    // Get the list of devices
    int num_devices = 0;
    ibv_device** device_list = ibv_get_device_list(&num_devices);
    if (!device_list) {
        std::cerr << "Failed to get IB devices list: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
        return 1;
    }

    num_devices = 1; // For testing, we will only use one device

    std::vector<ibv_context*> contexts(num_devices);
    std::vector<ibv_pd*> pds(num_devices);
    std::vector<ibv_cq*> cqs(num_devices);
    std::vector<ibv_qp*> qps(num_devices);
    std::vector<std::ofstream> files(num_devices);
    std::vector<void*> gpu_buffers(num_devices);
    std::vector<ibv_mr*> mrs(num_devices);

    // Print the list of devices
    std::cout << "Available devices:" << std::endl;
    for (int i = 0; i < num_devices; ++i) {
        std::cout << "Device " << i << ": " << ibv_get_device_name(device_list[i]) << std::endl;
        interfaces[i] = ibv_get_device_name(device_list[i]);
    }

    // Free the device list
    ibv_free_device_list(device_list);

    for (int i = 0; i < num_devices; ++i) {
        files[i].open(std::string(interfaces[i]) + ".raw", std::ios::binary);

        std::cout << "Opening device " << interfaces[i] << "..." << std::endl;
        contexts[i] = ibv_open_device(ibv_get_device_list(nullptr)[i]);
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
        if (save_gpu) {
            GPUERRCHK(cudaMalloManaged(&gpu_buffers[i], num_frames * MTU));
        } else {
            gpu_buffers[i] = malloc(num_frames * MTU);
        }
        memset(gpu_buffers[i], 0, num_frames * MTU);
        

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
            ibv_recv_wr wr = {};
            ibv_sge sge = {};
            sge.addr = reinterpret_cast<uintptr_t>(gpu_buffers[i]) + j * MTU;
            sge.length = MTU;
            sge.lkey = mrs[i]->lkey;
            wr.sg_list = &sge;
            wr.num_sge = 1;

            ibv_recv_wr* bad_wr;
            if (ibv_post_recv(qps[i], &wr, &bad_wr)) {
                std::cerr << "Failed to post recv: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
                exit(1);
            }

        }
    }
    // Main loop to capture packets
    for (int j = 0; j < num_frames; ++j) {
        for (int i = 0; i < num_devices; ++i) {
            
            ibv_wc wc;
            std::cout << "Waiting for poll completion " << std::endl;
            while (ibv_poll_cq(cqs[i], 1, &wc) < 1) {
                //printf("Header: 0x%x\n", *(uint32_t*)gpu_buffers[i]);
            }
            std::cout << " Completion polled " << std::endl;
            if (wc.status != IBV_WC_SUCCESS) {
                std::cerr << "Failed to poll CQ: " << ibv_wc_status_str(wc.status) << " (status: " << wc.status << ")" << std::endl;
                exit(1);
            }

            files[i].write(reinterpret_cast<char*>(gpu_buffers[i]) + j * MTU, MTU);
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
        GPUERRCHK(cudaFree(gpu_buffers[i]));
    }

    return 0;
}
