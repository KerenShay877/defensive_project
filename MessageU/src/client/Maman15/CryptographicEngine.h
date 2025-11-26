#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <string>
#include <vector>
#include <map>

#include <rsa.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <base64.h>

class CryptographicEngine {
public:
    CryptographicEngine();
    ~CryptographicEngine();

    // RSA key management
    bool initKeys();
    bool importPrivateKey(const std::string& pem);
    bool readKeys(const std::string& file);
    bool writeKeys(const std::string& file);
    bool importServerPub(const std::string& file);
    std::string exportPublicPEM();
    std::string exportPrivatePEM();

    // AES operations
    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& plain, const std::vector<uint8_t>& key);
    std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& key);

    // Symmetric key management
    std::vector<uint8_t> newSymmetricKey();
    bool saveSymKey(const std::string& peer, const std::vector<uint8_t>& key);
    std::vector<uint8_t> fetchSymKey(const std::string& peer);
    bool containsSymKey(const std::string& peer);

    // RSA operations
    std::vector<uint8_t> rsaEncrypt(const std::vector<uint8_t>& data, const std::string& pubPem);
    std::vector<uint8_t> rsaDecrypt(const std::vector<uint8_t>& data);

    // Utility functions
    std::vector<uint8_t> decodeB64(const std::string& text);
    std::string encodeB64(const std::vector<uint8_t>& data);
    std::vector<uint8_t> randomBlock(size_t len);
    std::vector<uint8_t> randomVector(size_t len);
    std::string toB64(const std::vector<uint8_t>& data);

    // Helpers
    std::vector<uint8_t> wrapMessage(const std::vector<uint8_t>& msg);
    std::vector<uint8_t> unwrapMessage(const std::vector<uint8_t>& msg);
    std::vector<uint8_t> signData(const std::vector<uint8_t>& data);
    bool checkSignature(const std::vector<uint8_t>& data,
                        const std::vector<uint8_t>& sig,
                        const CryptoPP::RSA::PublicKey& pub);
    std::vector<uint8_t> newSessionKey();
    std::vector<uint8_t> wrapSessionKey(const std::vector<uint8_t>& key);

    // Key exchange
    std::vector<uint8_t> buildKeyExchange(const std::string& peer, const std::string& pubPem);
    bool handleKeyExchange(const std::string& peer, const std::vector<uint8_t>& blob);

private:
    CryptoPP::AutoSeededRandomPool rng_;
    CryptoPP::RSA::PrivateKey privKey_;
    CryptoPP::RSA::PublicKey  pubKey_;
    std::map<std::string, std::vector<uint8_t>> symKeyStore_;
};

#endif