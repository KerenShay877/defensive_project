#include "CryptographicEngine.h"
#include <iostream>
#include <fstream>
#include <sstream>

#include <filters.h>
#include <base64.h>
#include <aes.h>
#include <modes.h>
#include <rsa.h>
#include <osrng.h>

using byte = CryptoPP::byte;

CryptographicEngine::CryptographicEngine() {}
CryptographicEngine::~CryptographicEngine() {}

// RSA key management
bool CryptographicEngine::initKeys() {
    try {
        privKey_.GenerateRandomWithKeySize(rng_, 2048); // Create a RSA key
        pubKey_.AssignFrom(privKey_);
        return true;
    } catch (...) {
        return false;
    }
}

bool CryptographicEngine::importPrivateKey(const std::string& pem) {
    try {
        std::string body;
        std::istringstream iss(pem);
        std::string line;
        bool inBody = false;
        while (std::getline(iss, line)) {
            if (line.find("-----BEGIN") != std::string::npos) { inBody = true; continue; }
            if (line.find("-----END")   != std::string::npos) break;
            if (inBody) body += line;
        }
        CryptoPP::Base64Decoder dec; // Decode RSA key
        dec.Put(reinterpret_cast<const byte*>(body.data()), body.size());
        dec.MessageEnd();
        privKey_.Load(dec); // Load RSA key
        pubKey_.AssignFrom(privKey_); // Assign a public key
        return true;
    } catch (...) {
        return false;
    }
}

bool CryptographicEngine::readKeys(const std::string& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return false;
    std::ostringstream oss;
    oss << in.rdbuf();
    return importPrivateKey(oss.str()); // Import the private key
}

bool CryptographicEngine::writeKeys(const std::string& file) {
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << exportPrivatePEM(); // Export the private key
    return true;
}

bool CryptographicEngine::importServerPub(const std::string&) {
    return true;
}

std::string CryptographicEngine::exportPublicPEM() {
    std::string buf;
    CryptoPP::Base64Encoder enc(new CryptoPP::StringSink(buf), false);
    pubKey_.Save(enc);
    enc.MessageEnd();
    return "-----BEGIN PUBLIC KEY-----\n" + buf + "\n-----END PUBLIC KEY-----"; // Exporl the public key in PEM format
}

std::string CryptographicEngine::exportPrivatePEM() {
    std::string buf;
    CryptoPP::Base64Encoder enc(new CryptoPP::StringSink(buf), false);
    privKey_.Save(enc);
    enc.MessageEnd();
    return "-----BEGIN PRIVATE KEY-----\n" + buf + "\n-----END PRIVATE KEY-----"; // Exporl the private koy in PEM format
}

// AES operations
std::vector<uint8_t> CryptographicEngine::aesEncrypt(const std::vector<uint8_t>& plain,
                                                     const std::vector<uint8_t>& key) {
    try {
        if (key.size() != 16) return {};
        std::vector<uint8_t> iv(16, 0);
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data());
        std::vector<uint8_t> out;
        CryptoPP::ArraySource(plain.data(), plain.size(), true, // Encrypt and return data
            new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(out)));
        return out;
    } catch (...) {
        return {};
    }
}

std::vector<uint8_t> CryptographicEngine::aesDecrypt(const std::vector<uint8_t>& cipher,
                                                     const std::vector<uint8_t>& key) {
    try {
        if (key.size() != 16) return {};
        std::vector<uint8_t> iv(16, 0);
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data());
        std::vector<uint8_t> out;
        CryptoPP::ArraySource(cipher.data(), cipher.size(), true,
            new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(out)));
        return out;
    } catch (...) {
        return {};
    }
}

// Symmetric key management
std::vector<uint8_t> CryptographicEngine::newSymmetricKey() {
    return randomBlock(16);
}

bool CryptographicEngine::saveSymKey(const std::string& peer, const std::vector<uint8_t>& key) {
    symKeyStore_[peer] = key;
    return true;
}

std::vector<uint8_t> CryptographicEngine::fetchSymKey(const std::string& peer) {
    auto it = symKeyStore_.find(peer);
    return it != symKeyStore_.end() ? it->second : std::vector<uint8_t>{};
}

bool CryptographicEngine::containsSymKey(const std::string& peer) {
    return symKeyStore_.count(peer) > 0;
}

// RSA operations
std::vector<uint8_t> CryptographicEngine::rsaEncrypt(const std::vector<uint8_t>& data,
                                                     const std::string&) {
    return data;
}

std::vector<uint8_t> CryptographicEngine::rsaDecrypt(const std::vector<uint8_t>& data) {
    return data;
}

// Utility
std::vector<uint8_t> CryptographicEngine::decodeB64(const std::string& text) {
    std::vector<uint8_t> out;
    CryptoPP::Base64Decoder dec(new CryptoPP::VectorSink(out));
    CryptoPP::StringSource(text, true, new CryptoPP::Redirector(dec));
    return out;
}

std::string CryptographicEngine::encodeB64(const std::vector<uint8_t>& data) {
    std::string out;
    CryptoPP::Base64Encoder enc(new CryptoPP::StringSink(out), false);
    CryptoPP::ArraySource(data.data(), data.size(), true, new CryptoPP::Redirector(enc));
    return out;
}

std::vector<uint8_t> CryptographicEngine::randomBlock(size_t len) {
    std::vector<uint8_t> buf(len);
    rng_.GenerateBlock(buf.data(), buf.size());
    return buf;
}

std::vector<uint8_t> CryptographicEngine::randomVector(size_t len) {
    return randomBlock(len);
}

std::string CryptographicEngine::toB64(const std::vector<uint8_t>& data) {
    return encodeB64(data);
}

// Helpers
std::vector<uint8_t> CryptographicEngine::wrapMessage(const std::vector<uint8_t>& msg) {
    return msg;
}

std::vector<uint8_t> CryptographicEngine::unwrapMessage(const std::vector<uint8_t>& msg) {
    return msg;
}

std::vector<uint8_t> CryptographicEngine::signData(const std::vector<uint8_t>& ) {
    return {};
}

bool CryptographicEngine::checkSignature(const std::vector<uint8_t>& ,
                                         const std::vector<uint8_t>& ,
                                         const CryptoPP::RSA::PublicKey&) {
    return true;
}

std::vector<uint8_t> CryptographicEngine::newSessionKey() {
    return {};
}

std::vector<uint8_t> CryptographicEngine::wrapSessionKey(const std::vector<uint8_t>&) {
    return {};
}

// Key exchange
std::vector<uint8_t> CryptographicEngine::buildKeyExchange(const std::string& peer,
                                                           const std::string& pubPem) {
    auto key = containsSymKey(peer) ? fetchSymKey(peer) : newSymmetricKey();
    if (!containsSymKey(peer)) saveSymKey(peer, key);
    return rsaEncrypt(key, pubPem);
}

bool CryptographicEngine::handleKeyExchange(const std::string& peer,
                                            const std::vector<uint8_t>& blob) {
    auto key = rsaDecrypt(blob);
    if (key.size() != 16) key.resize(16, 0);
    saveSymKey(peer, key);
    return true;
}
