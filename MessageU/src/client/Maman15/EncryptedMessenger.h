#ifndef SECURE_MESSAGING_CLIENT_HPP
#define SECURE_MESSAGING_CLIENT_HPP

#include <string>
#include <vector>
#include "SecureConnection.h"
#include "CryptographicEngine.h"
#include "BinaryProtocol.h"

class EncryptedMessenger {
private:
    SecureConnection      net_;
    CryptographicEngine   crypto_;
    BinaryProtocol        proto_;

    std::string           host_;
    unsigned short        port_;
    std::string           username_;
    std::string           clientId_;
    std::string           privatePem_;
    std::string           publicPem_;

    bool                  registered_;
    bool                  connected_;

    // Configuration
    bool loadServerConfig();
    bool loadClientConfig();
    void showMenu();
    void handleMenuSelection(int choice);

    // Operations
    void doRegistration();
    void queryUserList();
    void queryPublicKey();
    void pollInbox();
    void sendMessage();
    void queryRecipientKey();
    void transmitSymKey();
    void shutdownApp();

    // Key exchange
    bool getPublicKeyFor(const std::string& target);
    bool exchangeSymmetricKey(const std::string& target);
    bool onSymmetricKeyMessage(const std::string& senderId, const std::vector<uint8_t>& encryptedKey);

public:
    EncryptedMessenger();
    ~EncryptedMessenger();

    // Main functions
    bool init();
    void run();
    void close();
};

#endif
