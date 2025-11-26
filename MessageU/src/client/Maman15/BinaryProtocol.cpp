#include "BinaryProtocol.h"
#include <cstring>
#include <iostream>

BinaryProtocol::BinaryProtocol() {}
BinaryProtocol::~BinaryProtocol() {}

// Utilities
std::vector<uint8_t> BinaryProtocol::pad(const std::string& s,size_t len) const {
    std::vector<uint8_t> buf(len,0);
    auto n = std::min(s.size(),len);
    std::memcpy(buf.data(),s.data(),n);
    return buf;
}

std::string BinaryProtocol::extract(const std::vector<uint8_t>& buf,size_t off,size_t len) const {
    if(off+len>buf.size()) return {};
    std::string s(reinterpret_cast<const char*>(buf.data()+off),len);
    auto pos=s.find('\0');
    if(pos!=std::string::npos) s.resize(pos);
    return s;
}

uint32_t BinaryProtocol::checksum(const std::vector<uint8_t>& buf) const {
    uint64_t sum=0;
    for(auto b:buf) sum+=b;
    return static_cast<uint32_t>(sum&0xFFFFFFFF);
}

std::vector<uint8_t> BinaryProtocol::header(uint16_t code,const std::vector<uint8_t>& payload) const {
    std::vector<uint8_t> out;
    out.push_back(1); 
    out.push_back(code&0xFF);
    out.push_back((code>>8)&0xFF);
    uint16_t len=static_cast<uint16_t>(payload.size());
    out.push_back(len&0xFF);
    out.push_back((len>>8)&0xFF);
    uint32_t chk=checksum(payload);
    out.push_back(chk&0xFF);
    out.push_back((chk>>8)&0xFF);
    out.push_back((chk>>16)&0xFF);
    out.push_back((chk>>24)&0xFF);
    out.insert(out.end(),payload.begin(),payload.end());
    return out;
}

// Response parsing
bool BinaryProtocol::parse(const std::vector<uint8_t>& raw){
    if(raw.size()<ProtoSize::HEADER) return false;
    m_in=raw;
    m_lastCode=static_cast<uint16_t>(raw[1])|(static_cast<uint16_t>(raw[2])<<8);
    return true;
}

bool BinaryProtocol::regOk() const {return m_lastCode==ProtoCode::REG_OK;}
bool BinaryProtocol::loginOk() const {return m_lastCode==ProtoCode::AUTH_OK;}
bool BinaryProtocol::msgAck() const {return m_lastCode==ProtoCode::MSG_LIST;}
bool BinaryProtocol::usersOk() const {return m_lastCode==ProtoCode::USER_LIST;}
bool BinaryProtocol::pubKeyOk() const {return m_lastCode==ProtoCode::KEY_RETURN;}
bool BinaryProtocol::msgsOk() const {return m_lastCode==ProtoCode::MSG_LIST;}
bool BinaryProtocol::sendOk() const {return m_lastCode==ProtoCode::MSG_SEND_OK;}
bool BinaryProtocol::symKeyOk() const {return m_lastCode==ProtoCode::SYM_KEY_OK;}

// Extractors
std::string BinaryProtocol::errorText() const {
    if(m_in.size()<ProtoSize::HEADER) return {};
    uint16_t len=static_cast<uint16_t>(m_in[3])|(static_cast<uint16_t>(m_in[4])<<8);
    if(m_in.size()<ProtoSize::HEADER+len) return {};
    return std::string(m_in.begin()+ProtoSize::HEADER,m_in.begin()+ProtoSize::HEADER+len);
}

std::vector<std::string> BinaryProtocol::users() const {
    std::vector<std::string> out;
    if(m_in.size()<13) return out;
    uint32_t count=m_in[9]|(m_in[10]<<8)|(m_in[11]<<16)|(m_in[12]<<24);
    size_t pos=13;
    for(uint32_t i=0;i<count;i++){
        if(pos+ProtoSize::CLIENT_ID+ProtoSize::USERNAME>m_in.size()) break;
        std::string cid=extract(m_in,pos,ProtoSize::CLIENT_ID); pos+=ProtoSize::CLIENT_ID;
        std::string name=extract(m_in,pos,ProtoSize::USERNAME); pos+=ProtoSize::USERNAME;
        out.push_back(name+" (ID: "+cid+")");
    }
    return out;
}

std::pair<std::string,std::string> BinaryProtocol::pubKey() const {
    if(m_in.size()<ProtoSize::HEADER+ProtoSize::CLIENT_ID+ProtoSize::PUBKEY) return {"",""};
    std::string cid=extract(m_in,ProtoSize::HEADER,ProtoSize::CLIENT_ID);
    std::string key=extract(m_in,ProtoSize::HEADER+ProtoSize::CLIENT_ID,ProtoSize::PUBKEY);
    return {cid,key};
}

std::vector<std::tuple<std::string,uint32_t,uint8_t,std::string,std::string>> BinaryProtocol::messages() const {
    std::vector<std::tuple<std::string,uint32_t,uint8_t,std::string,std::string>> out;
    if (m_in.size() < 13) return out;

    uint32_t count = m_in[9] | (m_in[10] << 8) | (m_in[11] << 16) | (m_in[12] << 24);
    size_t pos = 13;

    for (uint32_t i = 0; i < count; i++) {
        if (pos + ProtoSize::CLIENT_ID + 4 + 1 + 4 > m_in.size()) break;

        // sender id
        std::string fromId = extract(m_in, pos, ProtoSize::CLIENT_ID);
        pos += ProtoSize::CLIENT_ID;

        // message id
        uint32_t msgId = m_in[pos] | (m_in[pos+1] << 8) | (m_in[pos+2] << 16) | (m_in[pos+3] << 24);
        pos += 4;

        // message type
        uint8_t msgType = m_in[pos];
        pos += 1;

        // content length
        uint32_t contentLen = m_in[pos] | (m_in[pos+1] << 8) | (m_in[pos+2] << 16) | (m_in[pos+3] << 24);
        pos += 4;

        if (pos + contentLen > m_in.size()) break;
        std::string content(reinterpret_cast<const char*>(&m_in[pos]), contentLen);
        pos += contentLen;

        if (pos + ProtoSize::USERNAME > m_in.size()) break;
        std::string senderName = extract(m_in, pos, ProtoSize::USERNAME);
        pos += ProtoSize::USERNAME;

        out.emplace_back(fromId, msgId, msgType, content, senderName);
    }

    return out;
}

std::pair<std::string,std::vector<uint8_t>> BinaryProtocol::symKey() const {
    if (m_in.size() < ProtoSize::HEADER + ProtoSize::CLIENT_ID + 4) return {"",{}};

    std::string sender = extract(m_in, ProtoSize::HEADER, ProtoSize::CLIENT_ID);
    size_t pos = ProtoSize::HEADER + ProtoSize::CLIENT_ID;

    uint32_t keyLen = m_in[pos] | (m_in[pos+1]<<8) | (m_in[pos+2]<<16) | (m_in[pos+3]<<24);
    pos += 4;
    if (pos + keyLen > m_in.size()) return {sender,{}};

    std::vector<uint8_t> key(m_in.begin()+pos, m_in.begin()+pos+keyLen);
    return {sender,key};
}

// Builders
std::vector<uint8_t> BinaryProtocol::makeReg(const std::string& name,const std::string& pub) {
    std::vector<uint8_t> payload;
    auto n = pad(name,ProtoSize::USERNAME);
    auto k = pad(pub,ProtoSize::PUBKEY);
    payload.insert(payload.end(),n.begin(),n.end());
    payload.insert(payload.end(),k.begin(),k.end());
    return header(ProtoCode::REG,payload);
}

std::vector<uint8_t> BinaryProtocol::makeLogin(const std::string& name) {
    auto n = pad(name,ProtoSize::USERNAME);
    return header(ProtoCode::AUTH,n);
}

std::vector<uint8_t> BinaryProtocol::makeUserReq() {
    std::vector<uint8_t> empty;
    return header(ProtoCode::USER_GET,empty);
}

std::vector<uint8_t> BinaryProtocol::makePubKeyReq(const std::string& ident) {
    auto id = pad(ident,ProtoSize::USERNAME);
    return header(ProtoCode::KEY_GET,id);
}

std::vector<uint8_t> BinaryProtocol::makeSendMsg(const std::string& from,const std::string& to,const std::vector<uint8_t>& body) {
    std::vector<uint8_t> payload;
    auto f = pad(from,ProtoSize::CLIENT_ID);
    auto t = pad(to,ProtoSize::USERNAME);
    payload.insert(payload.end(),f.begin(),f.end());
    payload.insert(payload.end(),t.begin(),t.end());
    uint32_t len = static_cast<uint32_t>(body.size());
    payload.push_back(len&0xFF);
    payload.push_back((len>>8)&0xFF);
    payload.push_back((len>>16)&0xFF);
    payload.push_back((len>>24)&0xFF);
    payload.insert(payload.end(),body.begin(),body.end());
    return header(ProtoCode::MSG_SEND,payload);
}

std::vector<uint8_t> BinaryProtocol::makeSymKey(const std::string& from,const std::string& to,const std::vector<uint8_t>& enc) {
    std::vector<uint8_t> payload;
    auto f = pad(from,ProtoSize::CLIENT_ID);
    auto t = pad(to,ProtoSize::USERNAME);
    payload.insert(payload.end(),f.begin(),f.end());
    payload.insert(payload.end(),t.begin(),t.end());
    uint32_t len = static_cast<uint32_t>(enc.size());
    payload.push_back(len&0xFF);
    payload.push_back((len>>8)&0xFF);
    payload.push_back((len>>16)&0xFF);
    payload.push_back((len>>24)&0xFF);
    payload.insert(payload.end(),enc.begin(),enc.end());
    return header(ProtoCode::SYM_KEY,payload);
}

std::vector<uint8_t> BinaryProtocol::makeMsgReq(const std::string& cid) {
    auto c = pad(cid,ProtoSize::CLIENT_ID);
    return header(ProtoCode::MSG_GET,c);
}

std::vector<uint8_t> BinaryProtocol::makeLogout() {
    std::vector<uint8_t> empty;
    return header(ProtoCode::DISC,empty);
}