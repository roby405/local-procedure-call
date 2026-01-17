// SPDX-License-Identifier: BSD-3-Clause

#include <endian.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/ioctl.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <memory>
#include <mutex>

#include "../src/protocol/components.h"

#define REQ_PIPE ".dispatcher/connection_req_pipe"
#define INSTALL_REQ_PIPE ".dispatcher/install_req_pipe"

static void fatal(const char *msg) {
	std::cerr << msg << std::endl;
	exit(1);
}

static bool read_full(int fd, void *buf, size_t len) {
	char *p = static_cast<char *>(buf);
	size_t off = 0;
	while (off < len) {
		ssize_t n = read(fd, p + off, len - off);
		if (n == 0)
			return false;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		off += static_cast<size_t>(n);
	}
	return true;
}

static uint32_t fnv1a32(const std::string &s) {
	uint32_t hash = 2166136261u;
	for (unsigned char c : s) {
		hash ^= c;
		hash *= 16777619u;
	}
	return hash;
}

static bool has_pattern(const std::vector<char> &data, const char *pat, size_t patLen) {
	if (patLen == 0 || data.size() < patLen)
		return false;
	for (size_t i = 0; i + patLen <= data.size(); ++i) {
		if (memcmp(data.data() + i, pat, patLen) == 0)
			return true;
	}
	return false;
}

static bool is_suspicious_payload(const std::vector<char> &payload) {
	// incercam sa evitam shellcode urile basic
	if (has_pattern(payload, "/bin/sh", 7) || has_pattern(payload, "/bin/bash", 9) ||
		has_pattern(payload, "/bin//sh", 8))
		return true;

	int nopRun = 0;
	for (size_t i = 0; i < payload.size(); ++i) {
		unsigned char b = static_cast<unsigned char>(payload[i]);
		if (b == 0x90) {
			if (++nopRun >= 8)
				return true;
		} else {
			nopRun = 0;
		}

		if (i + 1 < payload.size()) {
			unsigned char b2 = static_cast<unsigned char>(payload[i + 1]);
			if ((b == 0xCD && b2 == 0x80) || (b == 0x0F && b2 == 0x05))
				return true;
		}
	}

	return false;
}

struct ServiceInfo {
	std::string inPipe;
	std::string outPipe;
	std::shared_ptr<std::mutex> ioMutex;
	int inFd{-1};
	int outFd{-1};
	bool hasExt{false};
	uint8_t extFlags{0};
	uint32_t extChecksum{0};
};

class Dispatcher {
public:
	Dispatcher() {
		mkdir(".dispatcher", 0777);
		mkdir(".pipes", 0777);

		mkfifo_safe(REQ_PIPE);
		mkfifo_safe(INSTALL_REQ_PIPE);

		reqFd = open(REQ_PIPE, O_RDWR);
		if (reqFd < 0)
			fatal("Could not open dispatcher request pipe");

		installFd = open(INSTALL_REQ_PIPE, O_RDWR);
		if (installFd < 0)
			fatal("Could not open install request pipe");
	}

	~Dispatcher() {
		if (reqFd >= 0)
			close(reqFd);
		if (installFd >= 0)
			close(installFd);
	}

	void run() {
		std::cout << "[dispatcher] Waiting for service install..." << std::endl;
		// instalam serviciul in background
		std::thread(&Dispatcher::install_loop, this).detach();
		// stabilim o conexiune permanenta pentru serviciul clientului
		connect_loop();
	}

private:
	int reqFd{-1};
	int installFd{-1};
	std::unordered_map<std::string, ServiceInfo> services;

	void mkfifo_safe(const std::string &path) {
		unlink(path.c_str());
		if (mkfifo(path.c_str(), 0666) < 0 && errno != EEXIST)
			fatal(("mkfifo failed for " + path).c_str());
	}

	void mkfifo_if_missing(const std::string &path) {
		if (mkfifo(path.c_str(), 0666) < 0 && errno != EEXIST)
			fatal(("mkfifo failed for " + path).c_str());
	}

	void install_loop() {
		while (true) {
			InstallRequestHeader ir;
			ssize_t n = read(installFd, &ir, sizeof(ir));

			if (n == 0) {
				close(installFd);
				installFd = open(INSTALL_REQ_PIPE, O_RDWR);
				if (installFd < 0) fatal("Could not reopen install request pipe");
				continue;
			}

			if (n != (ssize_t)sizeof(ir))
				fatal("Could not read InstallRequestHeader");

			uint16_t ipnLen = be16toh(ir.m_IpnLen);
			std::vector<char> buf(ipnLen);

			if (read(installFd, buf.data(), buf.size()) != (ssize_t)buf.size())
				fatal("Could not read install pipe name");

			std::string installPipeName(buf.data(), ipnLen);
			std::cout << "[dispatcher] Install request on pipe: "
					  << installPipeName << std::endl;

			mkfifo_safe(installPipeName);

			int sfd = open(installPipeName.c_str(), O_RDONLY);
			if (sfd < 0)
				fatal("Could not open service install pipe");

			InstallHeader hdr;
			if (read(sfd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
				fatal("Could not read InstallHeader");

			uint16_t vLen   = hdr.m_VersionLen;
			uint16_t cpnLen = be16toh(hdr.m_CpnLen);
			uint16_t rpnLen = be16toh(hdr.m_RpnLen);
			uint16_t apLen  = be16toh(hdr.m_ApLen);

			std::vector<char> buf2(vLen + cpnLen + rpnLen + apLen);
			if (read(sfd, buf2.data(), buf2.size()) != (ssize_t)buf2.size())
				fatal("Could not read install payload");

			size_t off = 0;
			std::string version(buf2.data() + off, vLen);   off += vLen;
			std::string inPipe(buf2.data() + off, cpnLen);  off += cpnLen;
			std::string outPipe(buf2.data() + off, rpnLen); off += rpnLen;
			std::string accessPath(buf2.data() + off, apLen);

			mkfifo_safe(inPipe);
			mkfifo_safe(outPipe);

			std::cout << "[dispatcher] Installed service: AP=" << accessPath
					  << " inPipe=" << inPipe << " outPipe=" << outPipe
					  << " version=" << version << std::endl;

			ServiceInfo info{inPipe, outPipe, std::make_shared<std::mutex>(), -1, -1};

	
			// extensia de protocol(1 extra byte + 4 bytes pentru checksum)
			int available = 0;
			if (ioctl(sfd, FIONREAD, &available) == 0 && available >= 5) {
				uint8_t flags = 0;
				uint32_t checksum = 0;
				if (read_full(sfd, &flags, sizeof(flags)) &&
					read_full(sfd, &checksum, sizeof(checksum))) {
					info.hasExt = true;
					info.extFlags = flags;
					info.extChecksum = be32toh(checksum);
					uint32_t expected = fnv1a32(accessPath);
					if (info.extChecksum != expected) {
						std::cerr << "[dispatcher] Warning: access path checksum mismatch"
								  << std::endl;
					}
				}
			}

			// dechidem pipe-urile pentru serviciu si le pastram
			info.inFd = open(inPipe.c_str(), O_WRONLY);
			if (info.inFd < 0)
				fatal("Could not open service input pipe");

			info.outFd = open(outPipe.c_str(), O_RDONLY);
			if (info.outFd < 0)
				fatal("Could not open service output pipe");
			services[accessPath] = info;

			close(sfd);
		}
	}

	void connect_loop() {
		int clientIdx = 0;

		while (true) {
			ConnectionRequestHeader hdr;

			ssize_t n = read(reqFd, &hdr, sizeof(hdr));
			if (n == 0) {
				close(reqFd);
				reqFd = open(REQ_PIPE, O_RDWR);

				if (reqFd < 0)
					fatal("Could not reopen dispatcher request pipe");
				continue;
			}
			if (n != (ssize_t)sizeof(hdr))
				fatal("Could not read ConnectionRequestHeader");

			uint32_t rpnLen = be32toh(hdr.m_RpnLen);
			uint32_t apLen = be32toh(hdr.m_ApLen);

			std::vector<char> buf(rpnLen + apLen);
			if (read(reqFd, buf.data(), buf.size()) != (ssize_t)buf.size())
				fatal("Could not read request payload");

			std::string rpn(buf.data(), rpnLen);
			std::string ap(buf.data() + rpnLen, apLen);

			mkfifo_if_missing(rpn);

			std::cout << "[dispatcher] New connection request: RPN=" << rpn
					  << " AP=" << ap << std::endl;

			// daca serviciul nu e instalat asteapteptam dupa el
			ServiceInfo svc;
			bool found = false;
			for (int tries = 0; tries < 200; ++tries) { // incearca aproximativ 2 secunde
				auto it = services.find(ap);
				if (it != services.end()) {
					svc = it->second;
					found = true;
					break;
				}
				usleep(10000);
			}
			if (!found) {
				std::cerr << "[dispatcher] No service for access path: "
						  << ap << std::endl;
				continue;
			}

			std::string callPipe   = ".pipes/call_" + std::to_string(clientIdx);
			std::string returnPipe = ".pipes/return_" + std::to_string(clientIdx);

			mkfifo_safe(callPipe);
			mkfifo_safe(returnPipe);

			std::string version = "v1";

			ConnectHeader ch;
			ch.m_VersionLen = version.size();
			ch.m_CpnLen = htobe32(callPipe.size());
			ch.m_RpnLen = htobe32(returnPipe.size());

			size_t totalSize = sizeof(ch) + version.size() +
							   callPipe.size() + returnPipe.size();

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

			std::string rpnCopy = rpn;
			std::vector<char> outCopy = out;
			std::thread([rpnCopy, outCopy]() {
				int cfd = -1;
				for (int attempt = 0; attempt < 200; ++attempt) { // up to ~2s
					cfd = open(rpnCopy.c_str(), O_WRONLY | O_NONBLOCK);
					if (cfd >= 0)
						break;
					if (errno != ENXIO && errno != ENOENT)
						break;
					usleep(10000);
				}
				if (cfd < 0)
					fatal("Could not open client connect pipe");
				write(cfd, outCopy.data(), outCopy.size());
				close(cfd);
			}).detach();

			std::cout << "[dispatcher] Sent connect response to client "
					  << clientIdx << std::endl;

			std::thread(&Dispatcher::client_loop, this,
						svc, callPipe, returnPipe).detach();

			clientIdx++;
		}
	}

	void client_loop(ServiceInfo svc,
					 std::string callPipe,
					 std::string returnPipe) {
		int clientCallFd = open(callPipe.c_str(), O_RDONLY);
		if (clientCallFd < 0)
			fatal("Could not open client call pipe");

		int clientReturnFd = open(returnPipe.c_str(), O_WRONLY);
		if (clientReturnFd < 0)
			fatal("Could not open client return pipe");

		while (true) {
			CallingHeader ch;
			ssize_t n = read(clientCallFd, &ch, sizeof(ch));

			if (n == 0)
				break;

			if (n != (ssize_t)sizeof(ch))
				fatal("Could not read CallingHeader from client");

			uint32_t argsLen = be32toh(ch.m_ArgumentsLen);
			size_t payloadSize = ch.m_FnLen + 4 * ch.m_ArgsCnt + argsLen;
			std::vector<char> payload(payloadSize);

			if (read(clientCallFd, payload.data(), payloadSize) != (ssize_t)payloadSize)
				fatal("Could not read call payload from client");

			if (is_suspicious_payload(payload)) {
				std::string fnName(payload.data(), ch.m_FnLen);
				std::string msg = "SECURITY_BLOCKED";

				CallingHeader rh;
				rh.m_FnLen = ch.m_FnLen;
				rh.m_ArgsCnt = 1;
				rh.m_ArgumentsLen = htobe32(msg.size());
				memcpy(rh.m_Token, ch.m_Token, 32);

				uint32_t msgLen = htobe32(msg.size());
				size_t totalSize = sizeof(rh) + fnName.size() + sizeof(msgLen) + msg.size();
				std::vector<char> out(totalSize);

				size_t off = 0;
				memcpy(out.data() + off, &rh, sizeof(rh));
				off += sizeof(rh);
				memcpy(out.data() + off, fnName.data(), fnName.size());
				off += fnName.size();
				memcpy(out.data() + off, &msgLen, sizeof(msgLen));
				off += sizeof(msgLen);
				memcpy(out.data() + off, msg.data(), msg.size());

				write(clientReturnFd, out.data(), out.size());
				continue;
			}

			std::lock_guard<std::mutex> lock(*svc.ioMutex);

			struct iovec iov_call[2];
			iov_call[0].iov_base = &ch;
			iov_call[0].iov_len = sizeof(ch);
			iov_call[1].iov_base = payload.data();
			iov_call[1].iov_len = payloadSize;

			writev(svc.inFd, iov_call, 2);

			CallingHeader rh;
			if (!read_full(svc.outFd, &rh, sizeof(rh)))
				fatal("Could not read CallingHeader from service");

			uint32_t rArgsLen = be32toh(rh.m_ArgumentsLen);
			size_t respSize = rh.m_FnLen + 4 * rh.m_ArgsCnt + rArgsLen;
			std::vector<char> resp(respSize);

			if (!read_full(svc.outFd, resp.data(), respSize))
				fatal("Could not read response payload from service");

			struct iovec iov_resp[2];
			iov_resp[0].iov_base = &rh;
			iov_resp[0].iov_len  = sizeof(rh);
			iov_resp[1].iov_base = resp.data();
			iov_resp[1].iov_len  = respSize;

			writev(clientReturnFd, iov_resp, 2);
		}

		close(clientCallFd);
		close(clientReturnFd);
	}
};

int main() {
	Dispatcher dispatcher;
	dispatcher.run();
	return 0;
}
