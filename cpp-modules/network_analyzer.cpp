#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// IP Header structure
struct IPHeader
{
    unsigned char iph_verlen;   // Version and header length
    unsigned char iph_tos;      // Type of service
    unsigned short iph_len;     // Total length
    unsigned short iph_id;      // Identification
    unsigned short iph_flag;    // Flags
    unsigned char iph_ttl;      // Time to live
    unsigned char iph_protocol; // Protocol (TCP, UDP, etc.)
    unsigned short iph_chksum;  // Checksum
    unsigned int iph_srcaddr;   // Source address
    unsigned int iph_destaddr;  // Destination address
};

// TCP Header structure
struct TCPHeader
{
    unsigned short tcp_srcport;     // Source port
    unsigned short tcp_destport;    // Destination port
    unsigned int tcp_seq;           // Sequence number
    unsigned int tcp_ack;           // Acknowledgment number
    unsigned char tcp_reserved : 4, // Reserved
        tcp_offset : 4;             // Data offset
    unsigned char tcp_flags;        // Flags
    unsigned short tcp_window;      // Window size
    unsigned short tcp_checksum;    // Checksum
    unsigned short tcp_urgent;      // Urgent pointer
};

// Network statistics structure
struct NetworkStats
{
    std::string src_ip;
    std::string dst_ip;
    int src_port;
    int dst_port;
    std::string protocol;
    size_t packet_count;
    size_t bytes_transferred;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    bool is_suspicious;
};

class NetworkPacketAnalyzer
{
private:
    SOCKET raw_socket;
    std::atomic<bool> is_running;
    std::mutex stats_mutex;
    std::unordered_map<std::string, NetworkStats> connection_stats;
    std::vector<std::string> suspicious_patterns;

    // Port scan detection
    std::unordered_map<std::string, std::vector<int>> port_scan_tracker;
    std::mutex scan_mutex;

    // Anomaly detection thresholds
    const size_t MAX_CONNECTIONS_PER_IP = 100;
    const size_t RAPID_CONNECTION_THRESHOLD = 50;
    const std::chrono::seconds PORT_SCAN_WINDOW{60};

public:
    NetworkPacketAnalyzer() : is_running(false), raw_socket(INVALID_SOCKET)
    {
        // Initialize suspicious patterns
        suspicious_patterns = {
            "192.168.", "10.", "172.16.", // Internal network probes from external
            "0.0.0.0",                    // Null route attempts
            "255.255.255.255"             // Broadcast attempts
        };
    }

    ~NetworkPacketAnalyzer()
    {
        stop();
    }

    bool initialize()
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            std::cerr << "WSAStartup failed" << std::endl;
            return false;
        }

        // Create raw socket for packet capture
        raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (raw_socket == INVALID_SOCKET)
        {
            std::cerr << "Raw socket creation failed: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return false;
        }

        // Get local IP address
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
        {
            std::cerr << "Failed to get hostname" << std::endl;
            return false;
        }

        struct addrinfo *result = nullptr;
        if (getaddrinfo(hostname, nullptr, nullptr, &result) != 0)
        {
            std::cerr << "Failed to get address info" << std::endl;
            return false;
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr;
        addr.sin_port = 0;

        freeaddrinfo(result);

        // Bind socket
        if (bind(raw_socket, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
        {
            std::cerr << "Socket bind failed: " << WSAGetLastError() << std::endl;
            return false;
        }

        // Set socket to promiscuous mode
        DWORD flag = 1;
        if (ioctlsocket(raw_socket, SIO_RCVALL, &flag) == SOCKET_ERROR)
        {
            std::cerr << "Failed to set promiscuous mode: " << WSAGetLastError() << std::endl;
            return false;
        }

        return true;
    }

    void start()
    {
        if (!initialize())
        {
            return;
        }

        is_running = true;
        std::thread capture_thread(&NetworkPacketAnalyzer::capturePackets, this);
        std::thread analysis_thread(&NetworkPacketAnalyzer::analyzeTraffic, this);

        capture_thread.detach();
        analysis_thread.detach();

        std::cout << "Network packet analyzer started..." << std::endl;
    }

    void stop()
    {
        is_running = false;
        if (raw_socket != INVALID_SOCKET)
        {
            closesocket(raw_socket);
            raw_socket = INVALID_SOCKET;
        }
        WSACleanup();
    }

    std::vector<NetworkStats> getSuspiciousConnections()
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        std::vector<NetworkStats> suspicious;

        for (const auto &pair : connection_stats)
        {
            if (pair.second.is_suspicious)
            {
                suspicious.push_back(pair.second);
            }
        }

        return suspicious;
    }

    std::vector<std::string> detectPortScans()
    {
        std::lock_guard<std::mutex> lock(scan_mutex);
        std::vector<std::string> scanners;
        auto now = std::chrono::system_clock::now();

        for (const auto &pair : port_scan_tracker)
        {
            if (pair.second.size() >= 10)
            { // 10+ different ports in window
                scanners.push_back("Port scan detected from: " + pair.first +
                                   " (" + std::to_string(pair.second.size()) + " ports)");
            }
        }

        return scanners;
    }

    void getNetworkStatistics(std::string &json_output)
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        json_output = "{\n  \"connections\": [\n";

        bool first = true;
        for (const auto &pair : connection_stats)
        {
            if (!first)
                json_output += ",\n";
            first = false;

            const auto &stats = pair.second;
            json_output += "    {\n";
            json_output += "      \"src_ip\": \"" + stats.src_ip + "\",\n";
            json_output += "      \"dst_ip\": \"" + stats.dst_ip + "\",\n";
            json_output += "      \"src_port\": " + std::to_string(stats.src_port) + ",\n";
            json_output += "      \"dst_port\": " + std::to_string(stats.dst_port) + ",\n";
            json_output += "      \"protocol\": \"" + stats.protocol + "\",\n";
            json_output += "      \"packet_count\": " + std::to_string(stats.packet_count) + ",\n";
            json_output += "      \"bytes\": " + std::to_string(stats.bytes_transferred) + ",\n";
            json_output += "      \"suspicious\": " + (stats.is_suspicious ? "true" : "false") + "\n";
            json_output += "    }";
        }

        json_output += "\n  ]\n}";
    }

private:
    void capturePackets()
    {
        char buffer[65536];

        while (is_running)
        {
            int bytes_received = recv(raw_socket, buffer, sizeof(buffer), 0);
            if (bytes_received > 0)
            {
                processPacket(buffer, bytes_received);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    void processPacket(char *buffer, int size)
    {
        if (size < sizeof(IPHeader))
            return;

        IPHeader *ip_header = (IPHeader *)buffer;

        // Convert addresses to strings
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = ip_header->iph_srcaddr;
        dst_addr.s_addr = ip_header->iph_destaddr;

        std::string src_ip = inet_ntoa(src_addr);
        std::string dst_ip = inet_ntoa(dst_addr);

        int src_port = 0, dst_port = 0;
        std::string protocol;

        // Parse TCP packets
        if (ip_header->iph_protocol == IPPROTO_TCP)
        {
            protocol = "TCP";
            if (size >= sizeof(IPHeader) + sizeof(TCPHeader))
            {
                TCPHeader *tcp_header = (TCPHeader *)(buffer + sizeof(IPHeader));
                src_port = ntohs(tcp_header->tcp_srcport);
                dst_port = ntohs(tcp_header->tcp_destport);

                // Track for port scan detection
                trackPortAccess(src_ip, dst_port);
            }
        }
        else if (ip_header->iph_protocol == IPPROTO_UDP)
        {
            protocol = "UDP";
            // UDP header parsing would go here
        }
        else
        {
            protocol = "OTHER";
        }

        // Update connection statistics
        updateConnectionStats(src_ip, dst_ip, src_port, dst_port, protocol, size);
    }

    void trackPortAccess(const std::string &src_ip, int port)
    {
        std::lock_guard<std::mutex> lock(scan_mutex);
        port_scan_tracker[src_ip].push_back(port);

        // Remove duplicates and keep recent entries
        auto &ports = port_scan_tracker[src_ip];
        std::sort(ports.begin(), ports.end());
        ports.erase(std::unique(ports.begin(), ports.end()), ports.end());

        // Keep only recent activity (simplified - should use timestamps)
        if (ports.size() > 50)
        {
            ports.erase(ports.begin(), ports.begin() + 25);
        }
    }

    void updateConnectionStats(const std::string &src_ip, const std::string &dst_ip,
                               int src_port, int dst_port, const std::string &protocol,
                               size_t packet_size)
    {
        std::lock_guard<std::mutex> lock(stats_mutex);

        std::string connection_key = src_ip + ":" + std::to_string(src_port) +
                                     "->" + dst_ip + ":" + std::to_string(dst_port) +
                                     "(" + protocol + ")";

        auto &stats = connection_stats[connection_key];
        if (stats.src_ip.empty())
        {
            // New connection
            stats.src_ip = src_ip;
            stats.dst_ip = dst_ip;
            stats.src_port = src_port;
            stats.dst_port = dst_port;
            stats.protocol = protocol;
            stats.packet_count = 0;
            stats.bytes_transferred = 0;
            stats.first_seen = std::chrono::system_clock::now();
            stats.is_suspicious = false;
        }

        stats.packet_count++;
        stats.bytes_transferred += packet_size;
        stats.last_seen = std::chrono::system_clock::now();

        // Check for suspicious activity
        checkSuspiciousActivity(stats);
    }

    void checkSuspiciousActivity(NetworkStats &stats)
    {
        // Check for suspicious patterns
        for (const auto &pattern : suspicious_patterns)
        {
            if (stats.src_ip.find(pattern) != std::string::npos ||
                stats.dst_ip.find(pattern) != std::string::npos)
            {
                stats.is_suspicious = true;
                break;
            }
        }

        // Check for unusual port activity
        if (stats.dst_port == 22 || stats.dst_port == 23 || stats.dst_port == 3389)
        {
            stats.is_suspicious = true; // SSH, Telnet, RDP attempts
        }

        // Check for high packet count (potential DDoS)
        if (stats.packet_count > 1000)
        {
            stats.is_suspicious = true;
        }
    }

    void analyzeTraffic()
    {
        while (is_running)
        {
            // Periodic analysis and cleanup
            cleanupOldConnections();
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    }

    void cleanupOldConnections()
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        auto now = std::chrono::system_clock::now();

        for (auto it = connection_stats.begin(); it != connection_stats.end();)
        {
            auto duration = std::chrono::duration_cast<std::chrono::minutes>(
                now - it->second.last_seen);

            if (duration.count() > 30)
            { // Remove connections older than 30 minutes
                it = connection_stats.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
};

// C-style wrapper functions for Python integration
extern "C"
{
    static NetworkPacketAnalyzer *analyzer = nullptr;

    __declspec(dllexport) bool start_packet_analyzer()
    {
        if (analyzer == nullptr)
        {
            analyzer = new NetworkPacketAnalyzer();
        }
        analyzer->start();
        return true;
    }

    __declspec(dllexport) void stop_packet_analyzer()
    {
        if (analyzer != nullptr)
        {
            analyzer->stop();
            delete analyzer;
            analyzer = nullptr;
        }
    }

    __declspec(dllexport) void get_network_stats(char *output, int max_length)
    {
        if (analyzer != nullptr)
        {
            std::string stats;
            analyzer->getNetworkStatistics(stats);
            strncpy_s(output, max_length, stats.c_str(), _TRUNCATE);
        }
    }

    __declspec(dllexport) int get_suspicious_count()
    {
        if (analyzer != nullptr)
        {
            return static_cast<int>(analyzer->getSuspiciousConnections().size());
        }
        return 0;
    }
}