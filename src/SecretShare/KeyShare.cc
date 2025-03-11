#include <iostream>
#include <BigNumbers/BigNumbers.h>
#include <SecretShare/KeyShare.h>


KeyShare::KeyShare (const KeyShare& obj) 
    : m_k (obj.m_k)
    , m_n (obj.m_n)
    , m_publicID (obj.m_publicID)
    , m_Index (obj.m_Index)
    , m_Share (obj.m_Share)
 { return ; }
         
 KeyShare& KeyShare::operator= (const KeyShare& obj){
    if (this != &obj){
        m_k = obj.m_k;
        m_n = obj.m_n;
        m_publicID = obj.m_publicID;
        m_Index = obj.m_Index;
        m_Share = obj.m_Share;
    }
    return *this ; 
 }

toml::value to_toml(const KeyShare& ks){
    return toml::value{
        toml::table{ 
            {"k", ks.k()},
            {"n", ks.n()},
            {"publicID", ks.publicID()},
            {"Index", ks.Index().ToHex()},
            {"Share", ks.Share().ToHex()}
        }
    };
}
KeyShare from_toml(const toml::value& v){
    KeyShare ks; 
    ks.k() = toml::find<int>(v,"k");
    ks.n() = toml::find<int>(v, "n");
    ks.publicID() = toml::find<std::string>(v, "publicID");
    ks.Index().FromHex(toml::find<std::string>(v, "Index"));
    ks.Share().FromHex(toml::find<std::string>(v, "Share"));
    return ks; 
}
#if 0 
std::string keyshare_to_json (const KeyShare& obj) {
    nlohmann::json j;
    j["threshold"] = obj.k();
    j["sharecount"] = obj.n(); 
    j["pubid"] = obj.publicID();
    j["index"] = obj.Index().ToHex(); 
    j["share"] = obj.Share().ToHex(); 
    return j.dump();
}

KeyShare keyshare_from_json (const std::string& keyshareJson){

    KeyShare share; 
    nlohmann::json j;
    j = nlohmann::json::parse(keyshareJson); 

    share.k() = j.at("threshold").get<int>(); 
    share.n() = j.at("sharecount").get<int>();
    share.publicID() = j.at("pubid").get<std::string>();
    share.Index().FromHex(j.at("index").get<std::string>());
    share.Share().FromHex(j.at("share").get<std::string>());
 
    return share; 
}
#endif