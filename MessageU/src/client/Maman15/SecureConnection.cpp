#include "SecureConnection.h"
#include <iostream>
#include <algorithm>

SecureConnection::SecureConnection()
    : m_socket(m_io), m_port(0) {}

SecureConnection::~SecureConnection() {
    close();
}

void SecureConnection::configure(const std::string& host, unsigned short port) {
    m_host = host;
    m_port = port;
}

// Open the conection
bool SecureConnection::open(const std::string& host, unsigned short port) {
    configure(host, port);
    try {
        boost::asio::ip::tcp::resolver resolver(m_io);
        auto endpoints = resolver.resolve(m_host, std::to_string(m_port));
        boost::asio::connect(m_socket, endpoints);
        std::cout << "[conn] connected to " << m_host << ":" << m_port << "\n";
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[conn] open failed: " << e.what() << "\n";
        return false;
    }
}

// Close conection
void SecureConnection::close() {
    if (m_socket.is_open()) {
        boost::system::error_code ec;
        m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        m_socket.close(ec);
        std::cout << "[conn] closed\n";
    }
}

bool SecureConnection::isOpen() const noexcept {
    return m_socket.is_open();
}

// Write data
bool SecureConnection::write(const std::vector<uint8_t>& data) {
    if (!isOpen()) {
        std::cerr << "[conn] write failed: not open\n";
        return false;
    }
    try {
        boost::asio::write(m_socket, boost::asio::buffer(data));
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[conn] write error: " << e.what() << "\n";
        return false;
    }
}

// Read data
bool SecureConnection::read(std::vector<uint8_t>& out) {
    if (!isOpen()) {
        std::cerr << "[conn] read failed: not open\n";
        return false;
    }
    try {
        std::vector<uint8_t> header(9);
        boost::asio::read(m_socket, boost::asio::buffer(header));

        uint16_t payloadSize = parseLengthField(header);
        out.resize(header.size() + payloadSize);
        std::copy(header.begin(), header.end(), out.begin());

        if (payloadSize > 0) {
            boost::asio::read(m_socket, boost::asio::buffer(out.data() + header.size(), payloadSize));
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[conn] read error: " << e.what() << "\n";
        return false;
    }
}

uint16_t SecureConnection::parseLengthField(const std::vector<uint8_t>& header) const {
    return static_cast<uint16_t>(header[3]) |
           (static_cast<uint16_t>(header[4]) << 8);
}