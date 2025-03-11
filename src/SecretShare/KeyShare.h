#ifndef __KEY_SHARE_H__
#define __KEY_SHARE_H__

#include <string>
#include <include/toml.hpp>

class BigNumber;

class KeyShare{
    public:
        KeyShare () = default;
        ~KeyShare () = default ;
        
        KeyShare (const KeyShare& );
         
         KeyShare& operator= (const KeyShare&);
         
        //moveable
        KeyShare(KeyShare&& obj) noexcept = default;
        KeyShare& operator=(KeyShare&& obj) noexcept = default;
        
        
        int& k () { return m_k ;}
        const int& k() const { return m_k; }
        
        int& n () { return m_n ;}
        const int& n() const { return m_n;}
        
        std::string& publicID() { return m_publicID; }
        const std::string& publicID () const { return m_publicID; }
        
        BigNumber& Index () { return m_Index; }
        const BigNumber& Index () const { return m_Index; }
        
        BigNumber& Share () { return m_Share; }
        const BigNumber& Share () const { return m_Share; }
        
    
    private:
        int m_k;
        int m_n;
        
        std::string m_publicID;
        BigNumber m_Index;
        BigNumber m_Share; 
};

toml::value to_toml(const KeyShare&);
KeyShare from_toml(const toml::value&);

#endif //#ifndef __KEY_SHARE_H__