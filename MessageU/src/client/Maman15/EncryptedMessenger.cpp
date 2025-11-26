#include "EncryptedMessenger.h"
#include <iostream>
#include <limits>
#include <sstream>
#include <fstream>

EncryptedMessenger::EncryptedMessenger()
    : port_(0),
      registered_(false),
      connected_(false) {
}

EncryptedMessenger::~EncryptedMessenger() {}

bool EncryptedMessenger::init()
{
    std::cout << "[app] initializing..." << std::endl;

    if (!loadServerConfig()) {
        std::cerr << "[app] server config error" << std::endl;
        return false;
    }

    loadClientConfig(); // Load the client configuration 

    std::cout << "[app] ready" << std::endl;
    return true;
}

void EncryptedMessenger::run()
{
    std::cout << "[app] interactive mode" << std::endl;

    for (;;) {
        showMenu();

        int choice = 0;
        std::cout << "select> ";

        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "please enter a number" << std::endl;
            continue;
        }

        if (choice == 0) {
            shutdownApp();
            break;
        }

        handleMenuSelection(choice);
    }
}

void EncryptedMessenger::close()
{
    std::cout << "[app] shutting down..." << std::endl;
}

void EncryptedMessenger::shutdownApp()
{
    std::cout << "bye" << std::endl;
}

bool EncryptedMessenger::loadServerConfig()
{
    std::ifstream in("server.info");
    if (!in.is_open()) {
        std::cerr << "server.info missing" << std::endl;
        return false;
    }

    std::string line;
    if (!std::getline(in, line)) {
        std::cerr << "server.info is empty" << std::endl;
        return false;
    }

    const auto pos = line.find(':');
    if (pos == std::string::npos) {
        std::cerr << "server.info bad format (expected ip:port)" << std::endl;
        return false;
    }

    host_ = line.substr(0, pos);
    const std::string portStr = line.substr(pos + 1);

    try {
        port_ = static_cast<unsigned short>(std::stoi(portStr));
    }
    catch (...) {
        std::cerr << "server.info invalid port" << std::endl;
        return false;
    }

    std::cout << "[app] server " << host_ << ":" << port_ << std::endl;
    return true;
}

bool EncryptedMessenger::loadClientConfig()
{
    std::ifstream in("me.info");
    if (!in.is_open()) {
        std::cout << "no me.info found; registration required" << std::endl;
        registered_ = false;
        return false;
    }

    auto readLine = [&](std::string& s) -> bool {
        return static_cast<bool>(std::getline(in, s));
    };

    // Read a PEM chunk from the file opened
    auto readPemBlock = [&](const std::string& beginMarker, const std::string& endMarker) -> std::string {
        std::ostringstream pem;
        std::string line;
        bool inBlock = false;

        while (std::getline(in, line)) {
            if (line.find(beginMarker) != std::string::npos) {
                pem << line << '\n';
                inBlock = true;
                break;
            }
        }

        if (!inBlock) return std::string();

        while (std::getline(in, line)) {
            pem << line << '\n';
            if (line.find(endMarker) != std::string::npos) break;
        }

        return pem.str();
    };

    std::string name, id;

    if (!readLine(name) || name.empty()) {
        std::cout << "me.info incomplete; please register" << std::endl;
        registered_ = false;
        return false;
    }
    if (!readLine(id) || id.empty()) {
        std::cout << "me.info incomplete; please register" << std::endl;
        registered_ = false;
        return false;
    }

    // Get public key
    const std::string pubPem = readPemBlock("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
    if (pubPem.empty()) {
        std::cout << "me.info missing public key; please register" << std::endl;
        registered_ = false;
        return false;
    }

    // Get private key
    const std::string privPem = readPemBlock("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
    if (privPem.empty()) {
        in.clear();
        std::cout << "me.info missing private key; please register" << std::endl;
        registered_ = false;
        return false;
    }

    username_   = name;
    clientId_   = id;
    publicPem_  = pubPem;
    registered_ = true;

    std::cout << "[app] identity: " << username_ << " [" << clientId_ << "]" << std::endl;

    if (crypto_.importPrivateKey(privPem)) {
        std::cout << "[app] private key loaded" << std::endl;
    } else {
        std::cout << "[app] private key load failed" << std::endl;
    }

    return true;
}

void EncryptedMessenger::showMenu()
{
    std::cout
        << "\n=== Menu ===" << std::endl
        << "110) Register" << std::endl
        << "120) Request clients list" << std::endl
        << "130) Request public key" << std::endl
        << "140) Request waiting messages" << std::endl
        << "150) Send text message" << std::endl
        << "151) Request symmetric key" << std::endl
        << "152) Send your symmetric key" << std::endl
        << "0) Exit" << std::endl
        << "===========" << std::endl;
}

void EncryptedMessenger::handleMenuSelection(int choice)
{
    switch (choice) {
    case 110: doRegistration();     break;
    case 120: queryUserList();      break;
    case 130: queryPublicKey();     break;
    case 140: pollInbox();          break;
    case 150: sendMessage();        break;
    case 151: queryRecipientKey();  break;
    case 152: transmitSymKey();     break;
    case 0:   shutdownApp();        break;
    default:  std::cout << "unknown option" << std::endl; break;
    }
}

void EncryptedMessenger::doRegistration()
{
    if (registered_) {
        std::cout << "already registered" << std::endl;
        return;
    }

    std::cout << "[register]" << std::endl;

    std::string name;
    std::cout << "name> ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, name);

    if (name.empty()) {
        std::cout << "username cannot be empty" << std::endl;
        return;
    }

    if (!crypto_.initKeys()) {
        std::cout << "key generation failed" << std::endl;
        return;
    }

    // Get public key
    const std::string pubPem = crypto_.exportPublicPEM();
    if (pubPem.empty()) {
        std::cout << "could not obtain public key" << std::endl;
        return;
    }

    std::cout << "[register] keys ready for " << name << std::endl;

    const std::vector<uint8_t> reqPayload = proto_.makeReg(name, pubPem);

    if (!net_.open(host_, port_)) {
        std::cout << "server connect failed" << std::endl;
        return;
    }

    std::cout << "[register] sending..." << std::endl;

    if (!net_.write(reqPayload)) {
        std::cout << "send failed" << std::endl;
        net_.close();
        return;
    }

    std::vector<uint8_t> respPayload;
    if (!net_.read(respPayload)) {
        std::cout << "receive failed" << std::endl;
        net_.close();
        return;
    }

    if (!proto_.parse(respPayload)) {
        std::cout << "bad response" << std::endl;
        net_.close();
        return;
    }

    // Makr sure that the registration was successful
    if (proto_.regOk()) {
        if (respPayload.size() >= 25) {
            std::string newId;
            for (size_t i = 9; i < 25 && i < respPayload.size(); ++i) {
                if (respPayload[i] != 0) newId += static_cast<char>(respPayload[i]);
            }

            std::ofstream out("me.info", std::ios::trunc);
            if (out.is_open()) {
                out << name << '\n';
                out << newId << '\n';
                out << pubPem << '\n';
                out << crypto_.exportPrivatePEM() << '\n';
                out.close();

                username_   = name;
                clientId_   = newId;
                publicPem_  = pubPem;
                registered_ = true;

                std::cout << "[register] ok; id=" << newId << std::endl;
                std::cout << "[register] saved to me.info" << std::endl;
            } else {
                std::cout << "failed writing me.info" << std::endl;
            }
        } else {
            std::cout << "malformed registration reply" << std::endl;
        }
    } else {
        const std::string err = proto_.errorText();
        std::cout << "registration failed: " << (err.empty() ? "unknown error" : err) << std::endl;
    }

    net_.close();
}

void EncryptedMessenger::queryUserList()
{
    if (!registered_) {
        std::cout << "please register first" << std::endl;
        return;
    }

    std::cout << "[users] requesting..." << std::endl;

    const std::vector<uint8_t> reqPayload = proto_.makeUserReq();

    if (!net_.open(host_, port_)) {
        std::cout << "server connect failed" << std::endl;
        return;
    }

    if (!net_.write(reqPayload)) {
        std::cout << "send failed" << std::endl;
        net_.close();
        return;
    }

    std::vector<uint8_t> respPayload;
    if (!net_.read(respPayload)) {
        std::cout << "receive failed" << std::endl;
        net_.close();
        return;
    }

    if (!proto_.parse(respPayload)) {
        std::cout << "bad response" << std::endl;
        net_.close();
        return;
    }

    // Confirm that the user list was received successfully
    if (proto_.usersOk()) {
        const auto users = proto_.users();
        if (!users.empty()) {
            std::cout << "\n-- clients --" << std::endl;
            for (const auto& u : users) std::cout << u << std::endl;
            std::cout << "-------------" << std::endl;
        } else {
            std::cout << "no clients" << std::endl;
        }
    } else {
        const std::string err = proto_.errorText();
        std::cout << "list failed: " << (err.empty() ? "unknown error" : err) << std::endl;
    }

    net_.close();
}

void EncryptedMessenger::queryPublicKey()
{
    if (!registered_) {
        std::cout << "please register first" << std::endl;
        return;
    }

    std::cout << "[pubkey]" << std::endl;
    std::string target;
    std::cout << "id or nickname> ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, target);

    if (target.empty()) {
        std::cout << "empty identifier" << std::endl;
        return;
    }

    if (getPublicKeyFor(target)) {
        const auto keyPair = proto_.pubKey();
        if (!keyPair.first.empty() && !keyPair.second.empty()) {
            std::cout << "[id] " << keyPair.first << std::endl;
            std::cout << "[key]\n" << keyPair.second << std::endl;
        }
    } else {
        std::cout << "public key request failed" << std::endl;
    }
}

void EncryptedMessenger::pollInbox()
{
    if (!registered_) {
        std::cout << "please register first" << std::endl;
        return;
    }

    std::cout << "[messages] fetching..." << std::endl;
    const auto reqPayload = proto_.makeMsgReq(clientId_);

    if (!net_.open(host_, port_)) {
        std::cout << "server connect failed" << std::endl;
        return;
    }

    if (!net_.write(reqPayload)) {
        std::cout << "send failed" << std::endl;
        net_.close();
        return;
    }

    std::vector<uint8_t> respPayload;
    if (!net_.read(respPayload)) {
        std::cout << "receive failed" << std::endl;
        net_.close();
        return;
    }

    if (!proto_.parse(respPayload)) {
        std::cout << "bad response" << std::endl;
        net_.close();
        return;
    }

    // Fetch all messages
    if (proto_.msgsOk()) {
        const auto messages = proto_.messages();

        if (messages.empty()) {
            std::cout << "no waiting messages" << std::endl;
        } else {
            std::cout << "\n-- waiting messages --" << std::endl;

            // Handle any symmetric key messages
            for (const auto& msg : messages) {
                const std::string& senderId = std::get<0>(msg);
                const uint8_t type          = std::get<2>(msg);
                const std::string& content  = std::get<3>(msg);

                if (type == 2) {
                    std::cout << "[key] from " << senderId << std::endl;
                    std::vector<uint8_t> decodedKey;
                    try {
                        decodedKey = crypto_.decodeB64(content);
                    } catch (...) {
                        decodedKey.assign(content.begin(), content.end());
                    }

                    if (onSymmetricKeyMessage(senderId, decodedKey))
                        std::cout << "[key] processed" << std::endl;
                    else
                        std::cout << "[key] processing failed" << std::endl;
                }
            }

            // Display text messages
            for (const auto& msg : messages) {
                const std::string& senderId   = std::get<0>(msg);
                const uint8_t type            = std::get<2>(msg);
                const std::string& content    = std::get<3>(msg);
                const std::string& senderName = std::get<4>(msg);

                if (type == 1) {
                    std::vector<uint8_t> encrypted;
                    try {
                        encrypted = crypto_.decodeB64(content);
                    } catch (...) {
                        encrypted.assign(content.begin(), content.end());
                    }

                    std::string plainText;
                    if (crypto_.containsSymKey(senderId)) {
                        const auto symKey = crypto_.fetchSymKey(senderId);
                        const auto decrypted = crypto_.aesDecrypt(encrypted, symKey);
                        plainText = decrypted.empty() ? "[decrypt failed]"
                                                      : std::string(decrypted.begin(), decrypted.end());
                    } else {
                        plainText = "[no key available]";
                    }

                    std::cout << "\nfrom: " << senderName << std::endl;
                    std::cout << plainText << std::endl;
                    std::cout << "-- end --\n" << std::endl;
                }
            }
        }
    } else {
        const std::string err = proto_.errorText();
        std::cout << "messages failed: " 
                  << (err.empty() ? "unknown error" : err) << std::endl;
    }

    net_.close();
}

void EncryptedMessenger::sendMessage()
{
    if (!registered_) {
        std::cout << "please register first" << std::endl;
        return;
    }

    std::cout << "[send]" << std::endl;
    std::string recipient;
    std::cout << "to (id/nick)> ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, recipient);

    if (recipient.empty()) {
        std::cout << "recipient required" << std::endl;
        return;
    }

    if (!crypto_.containsSymKey(recipient)) {
        std::cout << "[send] no key; exchanging..." << std::endl;
        if (!exchangeSymmetricKey(recipient)) {
            std::cout << "key exchange failed; aborting" << std::endl;
            return;
        }
        std::cout << "[send] key exchange done" << std::endl;
    }

    std::string text;
    std::cout << "message> ";
    std::getline(std::cin, text);
    if (text.empty()) {
        std::cout << "message cannot be empty" << std::endl;
        return;
    }

    const std::vector<uint8_t> plainBytes(text.begin(), text.end());
    const auto symKey = crypto_.fetchSymKey(recipient);
    if (symKey.empty()) {
        std::cout << "no key available for encryption" << std::endl;
        return;
    }

    const auto encrypted = crypto_.aesEncrypt(plainBytes, symKey);
    if (encrypted.empty()) {
        std::cout << "encryption failed" << std::endl;
        return;
    }

    std::cout << "[send] encrypted" << std::endl;
    const auto reqPayload = proto_.makeSendMsg(clientId_, recipient, encrypted);

    if (!net_.open(host_, port_)) {
        std::cout << "server connect failed" << std::endl;
        return;
    }

    if (!net_.write(reqPayload)) {
        std::cout << "send failed" << std::endl;
        net_.close();
        return;
    }

    std::vector<uint8_t> respPayload;
    if (!net_.read(respPayload)) {
        std::cout << "receive failed" << std::endl;
        net_.close();
        return;
    }

    if (!proto_.parse(respPayload)) {
        std::cout << "bad response" << std::endl;
        net_.close();
        return;
    }

    // Confirm if the message was sent succesfuly
    if (proto_.sendOk()) {
        const std::string status = proto_.errorText();
        if (!status.empty())
            std::cout << "[send] " << status << std::endl;
        else
            std::cout << "[send] ok" << std::endl;
    } else {
        const std::string err = proto_.errorText();
        std::cout << "send failed: " 
                  << (err.empty() ? "unknown error" : err) << std::endl;
    }

    net_.close();
}

void EncryptedMessenger::queryRecipientKey()
{
    if (!registered_) {
        std::cout << "please register first" << std::endl;
        return;
    }

    std::cout << "[sym-key]" << std::endl;
    std::string recipient;
    std::cout << "id or nickname> ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, recipient);

    if (recipient.empty()) {
        std::cout << "recipient required" << std::endl;
        return;
    }

    if (exchangeSymmetricKey(recipient)) {
        std::cout << "[sym-key] symmetric key sent to " << recipient << std::endl;
    } else {
        std::cout << "[sym-key] exchange failed" << std::endl;
    }
}

void EncryptedMessenger::transmitSymKey()
{
    if (!registered_) {
        std::cout << "please register first" << std::endl;
        return;
    }

    std::cout << "[send-key]" << std::endl;
    std::string recipient;
    std::cout << "to (id/nick)> ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, recipient);

    if (recipient.empty()) {
        std::cout << "recipient required" << std::endl;
        return;
    }

    if (exchangeSymmetricKey(recipient)) {
        std::cout << "symmetric key sent to " << recipient << std::endl;
    } else {
        std::cout << "failed sending key to " << recipient << std::endl;
    }
}

bool EncryptedMessenger::getPublicKeyFor(const std::string& target)
{
    const auto reqPayload = proto_.makePubKeyReq(target);

    if (!net_.open(host_, port_)) {
        std::cout << "server connect failed" << std::endl;
        return false;
    }

    if (!net_.write(reqPayload)) {
        std::cout << "send failed" << std::endl;
        net_.close();
        return false;
    }

    std::vector<uint8_t> respPayload;
    if (!net_.read(respPayload)) {
        std::cout << "receive failed" << std::endl;
        net_.close();
        return false;
    }

    if (!proto_.parse(respPayload)) {
        std::cout << "bad response" << std::endl;
        net_.close();
        return false;
    }

    if (proto_.pubKeyOk()) {
        const auto keyPair = proto_.pubKey();
        if (!keyPair.first.empty() && !keyPair.second.empty()) {
            std::cout << "[pubkey] received for " << keyPair.first << std::endl;
            net_.close();
            return true;
        } else {
            std::cout << "malformed public key reply" << std::endl;
        }
    } else {
        std::cout << "public key failed: " << proto_.errorText() << std::endl;
    }

    net_.close();
    return false;
}

bool EncryptedMessenger::exchangeSymmetricKey(const std::string& target)
{
    if (!getPublicKeyFor(target)) {
        std::cout << "couldn't fetch recipient public key" << std::endl;
        return false;
    }

    const auto keyPair = proto_.pubKey();
    const std::string& pubKey = keyPair.second;
    if (pubKey.empty()) {
        std::cout << "missing recipient public key" << std::endl;
        return false;
    }

    const auto encryptedKey = crypto_.buildKeyExchange(target, pubKey);
    if (encryptedKey.empty()) {
        std::cout << "key exchange build failed" << std::endl;
        return false;
    }

    const auto reqPayload = proto_.makeSymKey(clientId_, target, encryptedKey);

    if (!net_.open(host_, port_)) {
        std::cout << "server connect failed" << std::endl;
        return false;
    }

    if (!net_.write(reqPayload)) {
        std::cout << "send failed" << std::endl;
        net_.close();
        return false;
    }

    std::vector<uint8_t> respPayload;
    if (!net_.read(respPayload)) {
        std::cout << "receive failed" << std::endl;
        net_.close();
        return false;
    }

    if (!proto_.parse(respPayload)) {
        std::cout << "bad response" << std::endl;
        net_.close();
        return false;
    }

    if (proto_.symKeyOk()) {
        std::cout << "[send-key] ok" << std::endl;
        net_.close();
        return true;
    } else {
        std::cout << "key send failed: " << proto_.errorText() << std::endl;
    }

    net_.close();
    return false;
}

bool EncryptedMessenger::onSymmetricKeyMessage(const std::string& senderId,
                                               const std::vector<uint8_t>& encryptedKey)
{
    return crypto_.handleKeyExchange(senderId, encryptedKey);
}
