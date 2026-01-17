// SPDX-License-Identifier: BSD-3-Clause

#include <endian.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../src/protocol/components.h"

#define REQ_PIPE ".dispatcher/connection_req_pipe"
#define INSTALL_REQ_PIPE ".dispatcher/install_req_pipe"

static void fatal(const char *msg) {
	std::cerr << msg << std::endl;
	exit(1);
}

struct ServiceInfo {
	std::string inPipe;   // where dispatcher writes calls, service reads
	std::string outPipe;  // where service writes responses, dispatcher reads
};

class Dispatcher {
public:
	Dispatcher() {
		// ensure directories exist
		mkdir(".dispatcher", 0777);
		mkdir(".pipes", 0777);

		// recreate global FIFOs
		mkfifo_safe(REQ_PIPE);
		mkfifo_safe(INSTALL_REQ_PIPE);

		// open with O_RDWR to avoid blocking/EOF issues
		reqFd = open(REQ_PIPE, O_RDWR);
		if (reqFd < 0) fatal("Could not open dispatcher request pipe");

		installFd = open(INSTALL_REQ_PIPE, O_RDWR);
		if (installFd < 0) fatal("Could not open install request pipe");
	}

	~Dispatcher() {
		if (reqFd >= 0) close(reqFd);
		if (installFd >= 0) close(installFd);
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

			services[accessPath] = { inPipe, outPipe };

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

			std::cout << "[dispatcher] New connection request: RPN=" << rpn
					  << " AP=" << ap << std::endl;

			auto it = services.find(ap);
			if (it == services.end()) {
				std::cerr << "[dispatcher] No service for access path: "
						  << ap << std::endl;
				continue;
			}

			ServiceInfo svc = it->second;

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

			std::string connectPipe = std::string(".pipes/connect_pipe") +
									  std::to_string(clientIdx);

			mkfifo_safe(connectPipe);

			int cfd = open(connectPipe.c_str(), O_WRONLY);
			if (cfd < 0) fatal("Could not open client connect pipe");

			write(cfd, out.data(), out.size());
			close(cfd);

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

		int svcInFd = open(svc.inPipe.c_str(), O_WRONLY);
		if (svcInFd < 0)
			fatal("Could not open service input pipe");

		int svcOutFd = open(svc.outPipe.c_str(), O_RDONLY);
		if (svcOutFd < 0)
			fatal("Could not open service output pipe");

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

			write(svcInFd, &ch, sizeof(ch));
			write(svcInFd, payload.data(), payloadSize);

			CallingHeader rh;
			if (read(svcOutFd, &rh, sizeof(rh)) != (ssize_t)sizeof(rh))
				fatal("Could not read CallingHeader from service");

			uint32_t rArgsLen = be32toh(rh.m_ArgumentsLen);
			size_t respSize = rh.m_FnLen + 4 * rh.m_ArgsCnt + rArgsLen;
			std::vector<char> resp(respSize);

			if (read(svcOutFd, resp.data(), respSize) != (ssize_t)respSize)
				fatal("Could not read response payload from service");

			write(clientReturnFd, &rh, sizeof(rh));
			write(clientReturnFd, resp.data(), respSize);
		}

		close(clientCallFd);
		close(clientReturnFd);
		close(svcInFd);
		close(svcOutFd);
	}
};

int main() {
	Dispatcher dispatcher;
	dispatcher.run();
	return 0;
}
