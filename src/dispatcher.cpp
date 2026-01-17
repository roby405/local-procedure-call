// SPDX-License-Identifier: BSD-3-Clause

#include <endian.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "../src/protocol/components.h"

#define REQ_PIPE ".dispatcher/connection_req_pipe"

static void fatal(const char *msg) {
    std::cerr << msg << std::endl;
    exit(1);
}

int main() {
    // cream pipe ul global de dispatcher 
    mkfifo(REQ_PIPE, 0666);

    int reqFd = open(REQ_PIPE, O_RDONLY);
    if (reqFd < 0) fatal("Could not open dispatcher request pipe");

    std::cout << "[dispatcher] Ready" << std::endl;

    int clientIdx = 0;

    while (true) {
        ConnectionRequestHeader hdr;

        ssize_t n = read(reqFd, &hdr, sizeof(hdr));
        if (n == 0) {
            close(reqFd);
            reqFd = open(REQ_PIPE, O_RDONLY);
            continue;
        }
        if (n != sizeof(hdr))
            fatal("Could not read ConnectionRequestHeader");

        uint32_t rpnLen = be32toh(hdr.m_RpnLen);
        uint32_t apLen  = be32toh(hdr.m_ApLen);

        std::vector<char> buf(rpnLen + apLen);
        if (read(reqFd, buf.data(), buf.size()) != (ssize_t)buf.size())
            fatal("Could not read request payload");

        std::string rpn(buf.data(), rpnLen);
        std::string ap(buf.data() + rpnLen, apLen);

        std::cout << "[dispatcher] New connection request: RPN=" << rpn
                  << " AP=" << ap << std::endl;

        // cream piperuile call si return pentru fiecare client
        std::string callPipe   = ".pipes/call_"   + std::to_string(clientIdx);
        std::string returnPipe = ".pipes/return_" + std::to_string(clientIdx);

        mkfifo(callPipe.c_str(), 0666);
        mkfifo(returnPipe.c_str(), 0666);

        // O sa cream headerul ConnectionHeader
        std::string version = "v1";

        ConnectHeader ch;
        ch.m_VersionLen = version.size();
        ch.m_CpnLen     = htobe32(callPipe.size());
        ch.m_RpnLen     = htobe32(returnPipe.size());

        // construim raspunsul pentru buffer
        size_t totalSize = sizeof(ch) +
                           version.size() +
                           callPipe.size() +
                           returnPipe.size();

        std::vector<char> out(totalSize);

        size_t off = 0;
        memcpy(out.data() + off, &ch, sizeof(ch));
        off += sizeof(ch);

        memcpy(out.data() + off, version.data(), version.size());
        off += version.size();

        memcpy(out.data() + off, callPipe.data(), callPipe.size());
        off += callPipe.size();

        memcpy(out.data() + off, returnPipe.data(), returnPipe.size());
        off += returnPipe.size();

        // trimitem raspunsul catre client
        std::string connectPipe = std::string(".pipes/connect_pipe") +
                                  std::to_string(clientIdx);

        mkfifo(connectPipe.c_str(), 0666);

        int cfd = open(connectPipe.c_str(), O_WRONLY);
        if (cfd < 0) fatal("Could not open client connect pipe");

        write(cfd, out.data(), out.size());
        close(cfd);

        std::cout << "[dispatcher] Sent connect response to client "
                  << clientIdx << std::endl;

        clientIdx++;
    }

    return 0;
}
