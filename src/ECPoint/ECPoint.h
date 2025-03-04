#ifndef _EC_POINT__H__
#define _EC_POINT__H__

#include <memory>
#include <vector>
#include <string>
#include <utility>
#include <tuple>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <BigNumbers/BigNumbers.h>


using EC_GROUP_ptr = std::unique_ptr< EC_GROUP, decltype(&EC_GROUP_free) >;
using EC_POINT_ptr = std::unique_ptr< EC_POINT, decltype(&EC_POINT_free) >;
//typedef EC_builtin_curve* EC_builtin_curve_ptr;

using CurveList = std::vector<std::tuple<int, std::string, std::string>>;
using CTX_ptr = std::unique_ptr<BN_CTX, decltype(&::BN_CTX_free)>;

class ECPoint
{
    friend ECPoint operator+ (const ECPoint&, const ECPoint&);
    friend bool operator == (const ECPoint&, const ECPoint&);
    friend bool operator != (const ECPoint&, const ECPoint&);
    friend ECPoint operator* (const ECPoint&, const BigNumber&); 

    friend bool ComparePoints(const ECPoint&, const ECPoint&);

    public:
        ECPoint();
	    ECPoint(const BigNumber& x, const BigNumber& y, const int& nid = 714);
        ~ECPoint();
        ECPoint(const int& nid);
        ECPoint(const std::string& NIDstring);
        ECPoint(const EC_GROUP_ptr&, const EC_POINT_ptr&, const int&); 

        //moveable
        ECPoint(ECPoint&& obj) noexcept;
        ECPoint& operator=(ECPoint&& obj) noexcept;

        //copyable
        ECPoint(const ECPoint& obj);
        ECPoint& operator=(const ECPoint& obj);

        ECPoint Double() const;


        void SetRandom() ; 
        void Invert();
        bool CheckInfinity();
        bool CheckOnCurve();

        std::string ToHex(const bool& compressed = true) const ;
        std::string ToDec(const bool& compressed = true) const ;

        int GroupNid()const;

        bool FromHex(const std::string& hexStr, int nid=-1) ;
        bool FromDec(const std::string& decStr, int nid=-1) ;

        std::pair<BigNumber, BigNumber> GetAffineCoords () const ;
        void SetAffineCoords(const std::pair<BigNumber, BigNumber>&); 

        BigNumber getECGroupOrder() const;
        int getECGroupDegree() const;
        ECPoint getGenerator() const;

        const EC_POINT_ptr& ec_ptr() const { return m_ec; }

    private:
        // don't change this order as the std::unique_ptrs are initialised
        // in the constructor list
        EC_GROUP_ptr m_gp; 
        EC_POINT_ptr m_ec; 
        int m_nid = 0;
};


std::vector<std::tuple<int, std::string, std::string>> getCurveList();
int getNidForString(const std::string& NIDstr);

ECPoint MultiplyByGeneratorPt(const BigNumber&, int curveID=714);
//std::string GroupOrder(const std::string&);
BigNumber GroupOrder(const int&);

ECPoint Multiply(const ECPoint& ec_pt, const BigNumber& m,const BigNumber& n);
#endif //ifndef _EC_POINT__H__
