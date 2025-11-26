#ifndef BINARY_PROTOCOL_HPP
#define BINARY_PROTOCOL_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <tuple>
#include <utility>

namespace ProtoCode {
    constexpr uint16_t REG          = 1000;
    constexpr uint16_t REG_OK       = 1001;
    constexpr uint16_t REG_ERR      = 1002;
    constexpr uint16_t AUTH         = 2000;
    constexpr uint16_t AUTH_OK      = 2001;
    constexpr uint16_t AUTH_ERR     = 2002;
    constexpr uint16_t MSG_SEND     = 3000;
    constexpr uint16_t MSG_SEND_OK  = 3001;
    constexpr uint16_t MSG_SEND_ERR = 3002;
    constexpr uint16_t MSG_GET      = 4000;
    constexpr uint16_t MSG_LIST     = 4001;
    constexpr uint16_t USER_GET     = 5000;
    constexpr uint16_t USER_LIST    = 5001;
    constexpr uint16_t KEY_GET      = 5002;
    constexpr uint16_t KEY_RETURN   = 5003;
    constexpr uint16_t SYM_KEY      = 5004;
    constexpr uint16_t SYM_KEY_OK   = 5005;
    constexpr uint16_t DISC         = 6000;
    constexpr uint16_t DISC_OK      = 6001;
}

namespace ProtoSize {
    constexpr uint16_t USERNAME  = 255;
    constexpr uint16_t PUBKEY    = 1024;
    constexpr uint16_t CLIENT_ID = 16;
    constexpr uint16_t HEADER    = 9;
}

class BinaryProtocol {
public:
    BinaryProtocol();
    ~BinaryProtocol();

    // Response parsing
    bool parse(const std::vector<uint8_t>& raw);
    bool regOk() const;
    bool loginOk() const;
    bool msgAck() const;
    bool usersOk() const;
    bool pubKeyOk() const;
    bool msgsOk() const;
    bool sendOk() const;
    bool symKeyOk() const;

    // Extractors
    std::string errorText() const;
    std::vector<std::string> users() const;
    std::pair<std::string,std::string> pubKey() const;
    std::vector<std::tuple<std::string,uint32_t,uint8_t,std::string,std::string>> messages() const;
    std::pair<std::string,std::vector<uint8_t>> symKey() const;

    // Builders
    std::vector<uint8_t> makeReg(const std::string& name,const std::string& pub);
    std::vector<uint8_t> makeLogin(const std::string& name);
    std::vector<uint8_t> makeUserReq();
    std::vector<uint8_t> makePubKeyReq(const std::string& ident);
    std::vector<uint8_t> makeSendMsg(const std::string& from,const std::string& to,const std::vector<uint8_t>& body);
    std::vector<uint8_t> makeSymKey(const std::string& from,const std::string& to,const std::vector<uint8_t>& enc);
    std::vector<uint8_t> makeMsgReq(const std::string& cid);
    std::vector<uint8_t> makeLogout();

private:
    std::vector<uint8_t> m_in;
    uint16_t m_lastCode{0};

    // Utilities
    std::vector<uint8_t> pad(const std::string& s,size_t len) const;
    std::string extract(const std::vector<uint8_t>& buf,size_t off,size_t len) const;
    uint32_t checksum(const std::vector<uint8_t>& buf) const;
    std::vector<uint8_t> header(uint16_t code,const std::vector<uint8_t>& payload) const;
};

#endif