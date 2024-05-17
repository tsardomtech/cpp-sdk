#include "ntp_client.h"

#include <iomanip>
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>

namespace tsar {
    int64_t utilities::get_ntp_time() {
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != S_OK) {
            return NULL;
        }

        addrinfo hints;
        addrinfo* info = nullptr;
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo("time.cloudflare.com", nullptr, &hints, &info) != S_OK) {
            WSACleanup();
            return EXIT_FAILURE;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(123);
        addr.sin_addr = reinterpret_cast<sockaddr_in*>(info->ai_addr)->sin_addr;

        freeaddrinfo(info);

        auto sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            WSACleanup();
            return EXIT_FAILURE;
        }

        constexpr auto TIME_OUT = 5000;
        auto timeout = reinterpret_cast<const char*>(&TIME_OUT);
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, timeout, sizeof(TIME_OUT));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, timeout, sizeof(TIME_OUT));

        constexpr auto PACKET_SIZE = 48;
        const char request[PACKET_SIZE] = { 0x23 };

        if (sendto(sock, request, PACKET_SIZE, 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            closesocket(sock);
            WSACleanup();
            return EXIT_FAILURE;
        }

        char response[PACKET_SIZE] = { 0 };
        if (recvfrom(sock, response, PACKET_SIZE, 0, nullptr, nullptr) == SOCKET_ERROR) {
            closesocket(sock);
            WSACleanup();
            return EXIT_FAILURE;
        }

        closesocket(sock);
        auto timestamp = ntohl(*reinterpret_cast<unsigned int*>(&response[40]));
        auto ntptime = static_cast<time_t>(timestamp - 2208988800u);

        return ntptime;
    }
}