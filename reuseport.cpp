#include <array>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include <linux/filter.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>

std::array<uint64_t, 512> packets_per_thread;

// Loads BPF for socket
bool load_bpf(int sockfd, uint32_t threads_per_port) {
    std::cout << "Loading BPF to implement random UDP traffic distribution over "
                 "available threads"
              << std::endl;

    struct sock_filter bpf_random_load_distribution[3] = {
        /* Load random to A */
        { BPF_LD | BPF_W | BPF_ABS, 0, 0, 0xfffff038 },
        /* A = A % mod */
        { BPF_ALU | BPF_MOD, 0, 0, threads_per_port },
        /* return A */
        { BPF_RET | BPF_A, 0, 0, 0 },
    };

    // There is an alternative way to pass number of therads
    bpf_random_load_distribution[1].k = uint32_t(threads_per_port);

    struct sock_fprog bpf_programm;

    bpf_programm.len    = 3;
    bpf_programm.filter = bpf_random_load_distribution;

    // UDP support for this feature is available since Linux 4.5
    int attach_filter_result = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &bpf_programm, sizeof(bpf_programm));

    if (attach_filter_result != 0) {
        std::cerr << "Can't attach reuse port BPF filter "
                  << " errno: " << errno << " error: " << strerror(errno) << std::endl;
        return false;
    }

    std::cout << "Successfully loaded reuse port BPF" << std::endl;

    return true;
}

bool create_and_bind_socket(std::size_t thread_id, const std::string& host, unsigned int port, uint32_t threads_per_port, int& sockfd) {
    std::cout << "We will listen on " << host << ":" << port << " udp port" << std::endl;

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    // AI_PASSIVE to handle empty host as bind on all interfaces
    // AI_NUMERICHOST to allow only numerical host
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    addrinfo* servinfo = NULL;

    std::string port_as_string = std::to_string(port);

    int getaddrinfo_result = getaddrinfo(host.c_str(), port_as_string.c_str(), &hints, &servinfo);

    if (getaddrinfo_result != 0) {
        std::cerr << "getaddrinfo function failed with code: " << getaddrinfo_result << " please check host syntax" << std::endl;
        return false;
    }

    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);

    std::cout << "Setting reuse port" << std::endl;

    int reuse_port_optval = 1;

    auto set_reuse_port_res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse_port_optval, sizeof(reuse_port_optval));

    if (set_reuse_port_res != 0) {
        std::cerr << "Cannot enable reuse port mode" << std::endl;
        return false;
    }

    int bind_result = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen);

    if (bind_result) {
        std::cerr << "Can't bind on port: " << port << " on host " << host << " errno:" << errno
                  << " error: " << strerror(errno) << std::endl;

        return false;
    }

    std::cout << "Successful bind" << std::endl;

    // Free up memory for server information structure
    freeaddrinfo(servinfo);

    return true;
}

void capture_traffic_from_socket(int sockfd, std::size_t thread_id) {
    std::cout << "Started capture" << std::endl;

    const unsigned int udp_buffer_size = 65536;
    char udp_buffer[udp_buffer_size];

    while (true) {
        int received_bytes = recv(sockfd, udp_buffer, udp_buffer_size, 0);

        if (received_bytes > 0) {
            packets_per_thread[thread_id]++;
        }
    }
}

void print_speed(uint32_t number_of_thread) {
    std::array<uint64_t, 512> packets_per_thread_previous = packets_per_thread;

    std::cout << "Thread ID"
              << "\t"
              << "UDP packet / second" << std::endl;

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        for (uint32_t i = 0; i < number_of_thread; i++) {
            std::cout << "Thread " << i << "\t" << packets_per_thread[i] - packets_per_thread_previous[i] << std::endl;
        }

        packets_per_thread_previous = packets_per_thread;
    }
}

bool set_process_name(std::thread& thread, const std::string& process_name) {
    if (process_name.size() > 15) {
        return false;
    }

    // The buffer specified by name should be at least 16 characters in length.
    char new_process_name[16];
    strcpy(new_process_name, process_name.c_str());

    int result = pthread_setname_np(thread.native_handle(), new_process_name);

    if (result != 0) {
        return false;
    }

    return true;
}

int main() {
    std::string host = "::";
    uint32_t port    = 2055;

    uint32_t number_of_threads = 2;

    class worker_data_t {
        public:
        int socket_fd    = 0;
        size_t thread_id = 0;
    };

    std::vector<worker_data_t> workers;

    std::vector<std::thread> thread_group;

    for (size_t thread_id = 0; thread_id < number_of_threads; thread_id++) {
        int socket_fd = 0;

        bool result = create_and_bind_socket(thread_id, host, port, number_of_threads, socket_fd);

        if (!result) {
            std::cerr << "Cannot create / bind socket" << std::endl;
            exit(1);
        }

        worker_data_t worker_data;
        worker_data.socket_fd = socket_fd;
        worker_data.thread_id = thread_id;

        workers.push_back(worker_data);
    }

    std::cout << "Starting packet capture" << std::endl;

    for (const auto& worker_data : workers) {
        bool bpf_result = load_bpf(worker_data.socket_fd, number_of_threads);

        if (!bpf_result) {
            std::cerr << "Cannot load BPF" << std::endl;
            exit(1);
        }

        std::thread current_thread(capture_traffic_from_socket, worker_data.socket_fd, worker_data.thread_id);
        set_process_name(current_thread, "udp_thread_" + std::to_string(worker_data.thread_id));
        thread_group.push_back(std::move(current_thread));
    }

    // Add some delay to be sure that both threads started
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Start speed printer
    std::thread speed_printer(print_speed, number_of_threads);

    // Wait for all threads to finish
    for (auto& thread : thread_group) {
        thread.join();
    }
}
