#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cerrno>
#include <infiniband/verbs.h>
#include <cuda_runtime.h>

// Define the interfaces and MTU
const char* interfaces[] = {"ens3f0np0", "ens3f1np1", "ens6f0np0", "ens6f1np1"};
const int num_interfaces = 4;
const int MTU = 8000;
const int num_frames = 1000;


inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true) {
    if (code != cudaSuccess) {
        std::cerr << "GPUassert: " << cudaGetErrorString(code) << " " << file << " " << line << std::endl;
    }
}

// Define the GPUERRCHK macro
#define GPUERRCHK(ans) { gpuAssert((ans), __FILE__, __LINE__); }

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

    return qp;
}

int main() {
    std::vector<ibv_context*> contexts(num_interfaces);
    std::vector<ibv_pd*> pds(num_interfaces);
    std::vector<ibv_cq*> cqs(num_interfaces);
    std::vector<ibv_qp*> qps(num_interfaces);
    std::vector<std::ofstream> files(num_interfaces);
    std::vector<void*> gpu_buffers(num_interfaces);
    std::vector<ibv_mr*> mrs(num_interfaces);
    bool save_gpu = true;

    if (save_gpu) {
        GPUERRCHK(cudaSetDevice(0));
    }

    for (int i = 0; i < num_interfaces; ++i) {
        files[i].open(std::string(interfaces[i]) + ".raw", std::ios::binary);

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
            cudaMalloc(&gpu_buffers[i], num_frames * MTU);
        } else {
            gpu_buffers[i] = malloc(num_frames * MTU);
        }
        

        // Register memory region
        mrs[i] = ibv_reg_mr(pds[i], gpu_buffers[i], num_frames * MTU, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
        if (!mrs[i]) {
            std::cerr << "Failed to register memory region: " << strerror(errno) << " (errno: " << errno << ")" << std::endl;
            exit(1);
        }
    }

    // Post recieve work requests
    for (int i = 0; i < num_interfaces; ++i) {
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
    for (int i = 0; i < num_interfaces; ++i) {
        for (int j = 0; j < num_frames; ++j) {
            
            ibv_wc wc;
            while (ibv_poll_cq(cqs[i], 1, &wc) < 1);
            if (wc.status != IBV_WC_SUCCESS) {
                std::cerr << "Failed to poll CQ: " << ibv_wc_status_str(wc.status) << " (status: " << wc.status << ")" << std::endl;
                exit(1);
            }

            files[i].write(reinterpret_cast<char*>(gpu_buffers[i]) + j * MTU, MTU);
        }
    }

    // Cleanup
    for (int i = 0; i < num_interfaces; ++i) {
        files[i].close();
        ibv_dereg_mr(mrs[i]);
        ibv_destroy_qp(qps[i]);
        ibv_destroy_cq(cqs[i]);
        ibv_dealloc_pd(pds[i]);
        ibv_close_device(contexts[i]);
        cudaFree(gpu_buffers[i]);
    }

    return 0;
}
