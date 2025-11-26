#ifndef SECURE_CONNECTION_HPP
#define SECURE_CONNECTION_HPP

#include <string>
#include <vector>
#include <boost/asio.hpp>

class SecureConnection {
public:
    SecureConnection();
    ~SecureConnection();

    // Connection methods
    bool open(const std::string& host, unsigned short port);
    void close();
    bool isOpen() const noexcept;

    // Input and output
    bool write(const std::vector<uint8_t>& data);
    bool read(std::vector<uint8_t>& out);

    // Server info
    void configure(const std::string& host, unsigned short port);

private:
    uint16_t parseLengthField(const std::vector<uint8_t>& header) const;

    boost::asio::io_context m_io;
    boost::asio::ip::tcp::socket m_socket;
    std::string m_host;
    unsigned short m_port;
};

#endif