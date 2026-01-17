// SPDX-License-Identifier: BSD-3-Clause

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <endian.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "protocol/components.h"

constexpr const char *kDispatcherDir = "checker/.dispatcher";
constexpr const char *kPipesDir = "checker/.pipes";
constexpr const char *kInstallReqPipe = "checker/.dispatcher/install_req_pipe";
constexpr const char *kConnectReqPipe = "checker/.dispatcher/connection_req_pipe";

class FileDescriptor { // ignore for now
public:
    FileDescriptor() = default;
    explicit FileDescriptor(int fd) : fd_(fd) {}
    ~FileDescriptor() { close(); }

    FileDescriptor(const FileDescriptor &) = delete;
    FileDescriptor &operator=(const FileDescriptor &) = delete;

    FileDescriptor(FileDescriptor &&other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }

    FileDescriptor &operator=(FileDescriptor &&other) noexcept {
        if (this != &other) {
            close();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    int get() const { return fd_; }
    bool valid() const { return fd_ >= 0; }

    void reset(int fd) {
        close();
        fd_ = fd;
    }

private:
    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = -1;
    }

    int fd_ = -1;
};

bool read_exact(int fd, void *buf, size_t len) {
    auto *ptr = static_cast<char *>(buf); // good for ensuring compatibility from what i read
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, ptr + off, len - off);
        if (r <= 0) {
            return false;
        }
        off += static_cast<size_t>(r);
    }
    return true;
}

bool write_exact(int fd, const void *buf, size_t len) {
    auto *ptr = static_cast<const char *>(buf);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, ptr + off, len - off);
        if (w <= 0) {
            return false;
        }
        off += static_cast<size_t>(w);
    }
    return true;
}

bool is_fifo(const std::string &path) {
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    return S_ISFIFO(st.st_mode);
}

bool ensure_fifo(const std::string &path) {
    if (mkfifo(path.c_str(), 0620) == 0) {
        return true;
    }

    if (errno == EEXIST) {
        if (is_fifo(path)) {
            return true;
        }
        unlink(path.c_str());
        if (mkfifo(path.c_str(), 0620) == 0) {
            return true;
        }
    }

    return false;
}

bool setup_runtime_dirs() {
    if (ensure_fifo(kInstallReqPipe) && ensure_fifo(kConnectReqPipe)) {
        return true;
    }

    const std::string base = "."; // first create folders
    const std::string dispatcher_dir = base + "/.dispatcher";
    const std::string pipes_dir = base + "/.pipes";

    mkdir(dispatcher_dir.c_str(), 0777);
    mkdir(pipes_dir.c_str(), 0777);

    if (!ensure_fifo(dispatcher_dir + "/install_req_pipe") ||
        !ensure_fifo(dispatcher_dir + "/connection_req_pipe")) {
        return false;
    }

    return true;
}

struct ServiceInfo {
    std::string version;
    std::string call_pipe;
    std::string return_pipe;
    FileDescriptor call_fd;
    FileDescriptor return_fd;
    std::mutex mutex;
    std::condition_variable ready_cv;
    bool ready = false;
};

// dispatcher stuff

namespace {
    std::mutex services_mutex_;
    std::map<std::string, std::shared_ptr<ServiceInfo>> services_;
    std::mutex service_rpc_mutex_; 
    std::atomic<uint64_t> next_client_id_{1};
}

void install_loop();
void connect_loop();
void handle_install(std::string install_pipe);
void handle_connect(std::string response_pipe, std::string access_path);
void client_loop(std::shared_ptr<ServiceInfo> info,
                 std::string client_call_pipe,
                 std::string client_return_pipe);

void initialize() {
    setup_runtime_dirs();
}

void run_dispatcher() {
    std::thread install_listener(install_loop);
    std::thread connect_listener(connect_loop);

    install_listener.join();
    connect_listener.join();
}

void install_loop() {
    FileDescriptor fd(open(kInstallReqPipe, O_RDWR));
    if (!fd.valid()) {
        std::cerr << "Failed to open install request pipe" << std::endl;
        return;
    }

    while (true) {
        InstallRequestHeader header{};
        if (!read_exact(fd.get(), &header, sizeof(header))) {
            continue;
        }

        uint16_t ipn_len = be16toh(header.m_IpnLen);
        if (ipn_len == 0) {
            continue;
        }

        std::string install_pipe(ipn_len, '\0');
        if (!read_exact(fd.get(), install_pipe.data(), ipn_len)) {
            continue;
        }

        // detach thread so app can continue
        std::thread(handle_install, install_pipe).detach();
    }
}

void connect_loop() {
    FileDescriptor fd(open(kConnectReqPipe, O_RDWR));
    if (!fd.valid()) {
        std::cerr << "Failed to open connect request pipe" << std::endl;
        return;
    }

    while (true) {
        ConnectionRequestHeader header{};
        if (!read_exact(fd.get(), &header, sizeof(header))) {
            continue;
        }

        uint32_t rpn_len = be32toh(header.m_RpnLen);
        uint32_t ap_len = be32toh(header.m_ApLen);

        if (rpn_len == 0 || ap_len == 0) {
            continue;
        }

        std::string response_pipe(rpn_len, '\0');
        if (!read_exact(fd.get(), response_pipe.data(), rpn_len)) {
            continue;
        }

        std::string access_path(ap_len, '\0');
        if (!read_exact(fd.get(), access_path.data(), ap_len)) {
            continue;
        }

        std::thread(handle_connect, response_pipe, access_path).detach();
    }
}
void handle_install(std::string install_pipe) {
    ensure_fifo(install_pipe);

    FileDescriptor fd(open(install_pipe.c_str(), O_RDONLY));
    if (!fd.valid()) {
        return;
    }

    InstallHeader header{};
    if (!read_exact(fd.get(), &header, sizeof(header))) {
        return;
    }

    uint8_t version_len = header.m_VersionLen;
    uint16_t call_len = be16toh(header.m_CpnLen);
    uint16_t ret_len = be16toh(header.m_RpnLen);
    uint16_t ap_len = be16toh(header.m_ApLen);

    size_t payload_len = static_cast<size_t>(version_len) + call_len +
                         ret_len + ap_len;
    if (payload_len == 0) {
        return;
    }

    std::string payload(payload_len, '\0');
    if (!read_exact(fd.get(), payload.data(), payload_len)) {
        return;
    }

    size_t offset = 0;
    std::string version = payload.substr(offset, version_len);
    offset += version_len;
    std::string call_pipe = payload.substr(offset, call_len);
    offset += call_len;
    std::string return_pipe = payload.substr(offset, ret_len);
    offset += ret_len;
    std::string access_path = payload.substr(offset, ap_len);

    ensure_fifo(call_pipe);
    ensure_fifo(return_pipe);

    auto info = std::make_shared<ServiceInfo>();
    info->version = std::move(version);
    info->call_pipe = std::move(call_pipe);
    info->return_pipe = std::move(return_pipe);

    {
        std::lock_guard<std::mutex> lock(services_mutex_);
        services_[access_path] = info;
    }

    FileDescriptor call_fd(open(info->call_pipe.c_str(), O_WRONLY));
    if (!call_fd.valid()) {
        return;
    }

    FileDescriptor return_fd(open(info->return_pipe.c_str(), O_RDONLY));
    if (!return_fd.valid()) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(info->mutex);
        info->call_fd = std::move(call_fd);
        info->return_fd = std::move(return_fd);
        info->ready = true;
    }
    info->ready_cv.notify_all();
}

void handle_connect(std::string response_pipe, std::string access_path) {
    std::shared_ptr<ServiceInfo> info;
    {
        std::lock_guard<std::mutex> lock(services_mutex_);
        auto it = services_.find(access_path);
        if (it == services_.end()) {
            return;
        }
        info = it->second;
    }

    {
        std::unique_lock<std::mutex> lock(info->mutex);
        info->ready_cv.wait(lock, [&info] { return info->ready; });
    }

    ensure_fifo(response_pipe);
    FileDescriptor fd(open(response_pipe.c_str(), O_WRONLY));
    if (!fd.valid()) {
        return;
    }

    uint64_t client_id = next_client_id_.fetch_add(1);
    
    std::string client_call_pipe =
        std::string(kPipesDir) + "/dispatcher_call_" +
        std::to_string(client_id);
    std::string client_return_pipe =
        std::string(kPipesDir) + "/dispatcher_return_" +
        std::to_string(client_id);

    if (!ensure_fifo(client_call_pipe) || !ensure_fifo(client_return_pipe)) {
        return;
    }

    ConnectHeader header{};
    header.m_VersionLen = static_cast<uint8_t>(info->version.size());
    header.m_CpnLen =
        htobe32(static_cast<uint32_t>(client_call_pipe.size()));
    header.m_RpnLen =
        htobe32(static_cast<uint32_t>(client_return_pipe.size()));

    std::vector<iovec> iov(4);
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = const_cast<char *>(info->version.data());
    iov[1].iov_len = info->version.size();
    iov[2].iov_base = const_cast<char *>(client_call_pipe.data());
    iov[2].iov_len = client_call_pipe.size();
    iov[3].iov_base = const_cast<char *>(client_return_pipe.data());
    iov[3].iov_len = client_return_pipe.size();

    ssize_t total =
        writev(fd.get(), iov.data(), static_cast<int>(iov.size()));
    if (total < 0) {
        write_exact(fd.get(), &header, sizeof(header));
        write_exact(fd.get(), info->version.data(), info->version.size());
        write_exact(fd.get(), client_call_pipe.data(),
                    client_call_pipe.size());
        write_exact(fd.get(), client_return_pipe.data(),
                    client_return_pipe.size());
    }

    std::thread(client_loop, info, client_call_pipe, client_return_pipe).detach();
}

void client_loop(std::shared_ptr<ServiceInfo> info,
                    std::string client_call_pipe,
                    std::string client_return_pipe) {
    FileDescriptor client_call_fd(open(client_call_pipe.c_str(), O_RDONLY));
    if (!client_call_fd.valid()) {
        return;
    }

    FileDescriptor client_return_fd(
        open(client_return_pipe.c_str(), O_WRONLY));
    if (!client_return_fd.valid()) {
        return;
    }

    while (true) {
        CallingHeader call_header{};
        if (!read_exact(client_call_fd.get(), &call_header,
                        sizeof(call_header))) {
            break;
        }

        uint32_t args_len = be32toh(call_header.m_ArgumentsLen);
        size_t payload_len = static_cast<size_t>(call_header.m_FnLen) +
                                4 * static_cast<size_t>(call_header.m_ArgsCnt) +
                                args_len;

        std::vector<char> payload(payload_len);
        if (payload_len > 0 &&
            !read_exact(client_call_fd.get(), payload.data(), payload_len)) {
            break;
        }

        std::vector<char> response_payload;
        CallingHeader response_header{};

        {
            std::lock_guard<std::mutex> lock(service_rpc_mutex_);
            std::vector<iovec> iov(2);
            iov[0].iov_base = &call_header;
            iov[0].iov_len = sizeof(call_header);
            iov[1].iov_base = payload.data();
            iov[1].iov_len = payload_len;

            ssize_t total = writev(info->call_fd.get(), iov.data(),
                                    static_cast<int>(iov.size()));
            if (total < 0) {
                if (!write_exact(info->call_fd.get(), &call_header,
                                    sizeof(call_header))) {
                    break;
                }
                if (payload_len > 0 &&
                    !write_exact(info->call_fd.get(), payload.data(),
                                    payload_len)) {
                    break;
                }
            }

            if (!read_exact(info->return_fd.get(), &response_header,
                            sizeof(response_header))) {
                break;
            }

            uint32_t resp_args_len =
                be32toh(response_header.m_ArgumentsLen);
            size_t resp_payload_len =
                static_cast<size_t>(response_header.m_FnLen) +
                4 * static_cast<size_t>(response_header.m_ArgsCnt) +
                resp_args_len;
            response_payload.resize(resp_payload_len);
            if (resp_payload_len > 0 &&
                !read_exact(info->return_fd.get(), response_payload.data(),
                            resp_payload_len)) {
                break;
            }
        }

        std::vector<iovec> out_iov(2);
        out_iov[0].iov_base = &response_header;
        out_iov[0].iov_len = sizeof(response_header);
        out_iov[1].iov_base = response_payload.data();
        out_iov[1].iov_len = response_payload.size();

        ssize_t out_total = writev(client_return_fd.get(), out_iov.data(),
                                    static_cast<int>(out_iov.size()));
        if (out_total < 0) {
            if (!write_exact(client_return_fd.get(), &response_header,
                                sizeof(response_header))) {
                break;
            }
            if (!response_payload.empty() &&
                !write_exact(client_return_fd.get(), response_payload.data(),
                                response_payload.size())) {
                break;
            }
        }
    }

    unlink(client_call_pipe.c_str());
    unlink(client_return_pipe.c_str());
}

int main() {
    initialize();
    run_dispatcher();
    return 0;
}
