#include <ECPoint/ECPoint.h>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <BigNumbers/BigNumbers.h>
#include <cassert>

ECPoint::ECPoint() 
    : m_gp(EC_GROUP_new_by_curve_name(NID_secp256k1), &EC_GROUP_free)
    , m_ec(EC_POINT_new(m_gp.get()), &EC_POINT_free)
    , m_nid(NID_secp256k1){
    return; 
}


ECPoint::ECPoint(const int& nid)
    : m_gp(EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free)
    , m_ec(EC_POINT_new(m_gp.get()), &EC_POINT_free)
    , m_nid(nid){
    return; 
}

ECPoint::ECPoint(const std::string& NIDstring) : 
    m_gp(nullptr, &EC_GROUP_free)
    , m_ec(nullptr, &EC_POINT_free){
    int nid = getNidForString(NIDstring);
    if (nid == -1)
        throw std::runtime_error("Invalid NID string provided");
    //if (!EC_GROUP_copy(m_gp.get(), gp.get()))
    //        throw std::runtime_error("ECPoint::ECPoint failed to copy EC_GROUP"); 
    //if (!EC_POINT_copy(m_ec.get(), ec.get()))
    //        throw std::runtime_error("ECPoint::ECPoint failed to copy EC_POINT"); 
    //    return;

    EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free);
    if (!EC_GROUP_copy(m_gp.get(), gp.get()))
            throw std::runtime_error("ECPoint::ECPoint failed to copy EC_GROUP"); 
    if (!EC_POINT_copy(m_ec.get(), EC_POINT_new(m_gp.get())))
            throw std::runtime_error("ECPoint::ECPoint failed to copy EC_POINT");
    m_nid = nid; 
}

ECPoint::ECPoint(const EC_GROUP_ptr& gp, const EC_POINT_ptr& ec, const int& nid)
    : m_gp(EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free)
    , m_ec(EC_POINT_new(m_gp.get()), &EC_POINT_free) 
    , m_nid(nid){
        if (!EC_GROUP_copy(m_gp.get(), gp.get()))
            throw std::runtime_error("ECPoint::ECPoint failed to copy EC_GROUP"); 
        if (!EC_POINT_copy(m_ec.get(), ec.get()))
            throw std::runtime_error("ECPoint::ECPoint failed to copy EC_POINT"); 
        return;
}

 ECPoint::ECPoint(const BigNumber& x, const BigNumber& y, const int& nid)
    : m_gp(EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free)
    , m_ec(EC_POINT_new(m_gp.get()), &EC_POINT_free) 
    , m_nid(nid){
        std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
        if(!EC_POINT_set_affine_coordinates(m_gp.get(), m_ec.get(), x.bn_ptr().get(), y.bn_ptr().get(), ctxptr.get()))
            throw std::runtime_error("Failed to set coordinates.");
    }

ECPoint::~ECPoint()=default;

ECPoint::ECPoint(ECPoint&& obj) noexcept = default;

ECPoint& ECPoint::operator=(ECPoint&& obj) noexcept = default;

ECPoint::ECPoint(const ECPoint& obj)
    : m_gp(EC_GROUP_new_by_curve_name(obj.m_nid), &EC_GROUP_free)
    , m_ec(EC_POINT_new(m_gp.get()), &EC_POINT_free) {
    EC_POINT_copy (m_ec.get(), obj.m_ec.get());
    m_nid = obj.m_nid;
}


//ECPoint::ECPoint(const BigNumber& x, const BigNumber& y, const int& nid) : m_pImpl(new ECPointImpl(x, y, nid)) {}


ECPoint& ECPoint::operator=(const ECPoint& obj){
    if (this != &obj){
        EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(obj.m_nid), &EC_GROUP_free);  
        if (!EC_GROUP_copy(m_gp.get(), gp.get()))
            throw std::runtime_error("operator= failed EC_GROUP_copy");


        EC_POINT_ptr m_ec(EC_POINT_new(m_gp.get()), &EC_POINT_free); 
        if (!EC_POINT_copy(m_ec.get(), obj.m_ec.get()))
            throw std::runtime_error("operator= failed EC_POINT_copy");

        m_nid = obj.m_nid; 
    }
    return *this;
}


ECPoint operator+ (const ECPoint& obj1, const ECPoint& obj2){
    if (obj1.GroupNid() != obj2.GroupNid()){
        throw std::runtime_error("error : methods mismatched in the given objects");
    }
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(obj1.GroupNid()), &EC_GROUP_free);
    EC_POINT_ptr ec(EC_POINT_new(obj1.m_gp.get()), &EC_POINT_free); 
    if (! EC_POINT_add(gp.get(), ec.get(), obj1.m_ec.get(), obj2.m_ec.get(), ctxptr.get()))
        throw std::runtime_error("error : Failed to add EC POINTs");

    ECPoint res(gp,ec,obj1.GroupNid()); 
    return res; 
}



bool operator == (const ECPoint& obj1, const ECPoint& obj2){
    return ComparePoints(obj1, obj2); 
}

bool operator != (const ECPoint& obj1, const ECPoint& obj2){
    return !ComparePoints(obj1, obj2); 
}


ECPoint ECPoint::Double() const{
    // Allocate for CTX 
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(m_nid), &EC_GROUP_free);
    EC_POINT_ptr ec(EC_POINT_new(gp.get()), &EC_POINT_free); 
    // allocate & get result group and EC struct


    if (! EC_POINT_dbl(gp.get(), ec.get(), m_ec.get(), ctxptr.get()))
        throw std::runtime_error("error : Failed to double EC POINT");

    ECPoint res_ec(gp, ec, m_nid); 
    return res_ec;
}

void ECPoint::SetRandom(){
 /* I believe this is correct but a real scientist might have to tell me the truth
        1) Initial a EC_POINT P as generator.
        2) Find a random bignum k such that 0 < k < order (of the group).
        3) Do scalar multiplication to get random point R = kP
    */

    BN_ptr k ( BN_new(), ::BN_free );
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );

    if ( !EC_GROUP_get_order(m_gp.get(),k.get(),ctxptr.get())){
        throw std::runtime_error ("Invalid group order on set random" );
    }

    if (!BN_rand(k.get(), BN_num_bits(k.get()), 0, 0)){
        throw std::runtime_error ("Unable to generate a random number" );
    }

    if (!EC_POINT_mul(m_gp.get(),m_ec.get(),k.get(),NULL,NULL,ctxptr.get())){
        throw std::runtime_error ("Unable to generate a random number" );
    }
    return ;
}

void ECPoint::Invert(){
    // Allocate for CTX 
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );

    int res = EC_POINT_invert(m_gp.get(), m_ec.get(), ctxptr.get());
    
    if (!res)
        throw std::runtime_error("error : Failed to invert EC POINT");
}

bool ECPoint::CheckInfinity(){
    if (!EC_POINT_is_at_infinity(m_gp.get(), m_ec.get()))
        return false;

    return true;
}

bool ECPoint::CheckOnCurve()
{
    // Allocate for CTX 
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    int res = EC_POINT_is_on_curve(m_gp.get(), m_ec.get(), ctxptr.get());

    if (res == -1)
        throw std::runtime_error("error : Failed to check if the EC POINT is on the curve");

    return res == 0 ? false : true;
}

std::pair<BigNumber, BigNumber> ECPoint::GetAffineCoords () const{

    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    if (!EC_POINT_is_on_curve(m_gp.get(),m_ec.get(), ctxptr.get()))
        throw std::runtime_error("error: Point not on curve for GetAffineCoords");

    BigNumber x_cord; 
    BigNumber y_cord; 
    if (!EC_POINT_get_affine_coordinates(m_gp.get(), m_ec.get(), x_cord.bn_ptr().get(), y_cord.bn_ptr().get(), ctxptr.get()))
        throw std::runtime_error("error: Unale to execute GetAddineCoords");

    return std::make_pair(x_cord, y_cord);
}

void ECPoint::SetAffineCoords(const std::pair<BigNumber, BigNumber>& pts){

    auto& [x, y] = pts; // structured binding. C++17 feature
    EC_POINT_set_affine_coordinates(m_gp.get(), m_ec.get(), x.bn_ptr().get(), y.bn_ptr().get(), NULL);
    if(!this->CheckOnCurve())
        throw std::runtime_error("error: Point not on curve for SetAffineCoords");
    return; 
}

/*
An EC Point is a point (X, Y)
Its serialization is 04+X+Y as uncompressed, and (02+X as compressed if Y is even), and (03+X as compressed if Y is odd). X and Y are here the corresponding 64-character hexadecimal string
*/
std::string ECPoint::ToHex(const bool& compressed) const{
    char *ecChar = nullptr; 
    
    // Allocate for CTX 
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    if(compressed)
        ecChar  = EC_POINT_point2hex(m_gp.get(), m_ec.get(), POINT_CONVERSION_COMPRESSED, ctxptr.get());
    else
        ecChar  = EC_POINT_point2hex(m_gp.get(), m_ec.get(), POINT_CONVERSION_UNCOMPRESSED, ctxptr.get());

    if ( ecChar == nullptr)
	    std::runtime_error("Failed to convert EC Point to Hex");

    std::string ecStr(ecChar) ;

    // free 
    OPENSSL_free(ecChar);
    return ecStr;
}


std::string ECPoint::ToDec(const bool& compressed) const
{
    char *ecChar = nullptr; 
    unsigned char * internal_buf = nullptr; 
    size_t internal_buf_len = 0;  
    // Allocate for CTX 
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    //BN_ptr bn_obj_n_uptr {BN_new(), ::BN_free};
    if(compressed){
        internal_buf_len = EC_POINT_point2buf(m_gp.get(), m_ec.get(), POINT_CONVERSION_COMPRESSED, &internal_buf,ctxptr.get());
        if (internal_buf_len == 0)
            std::runtime_error("Failed to create intneral buffer for ECPoint converstion to decimal bignumber");
    }else{
        internal_buf_len = EC_POINT_point2buf(m_gp.get(), m_ec.get(), POINT_CONVERSION_UNCOMPRESSED, &internal_buf,ctxptr.get());
        if (internal_buf_len == 0)
            std::runtime_error("Failed to create intneral buffer for ECPoint converstion to decimal bignumber");
    }
    // Convert buffer to BIGNUM
    BN_ptr bn_obj_n_uptr{BN_bin2bn(internal_buf, internal_buf_len, NULL), ::BN_free};
    ecChar = BN_bn2dec(bn_obj_n_uptr.get());
    if ( ecChar == nullptr)
	    std::runtime_error("Failed to convert EC Point to Hex");
    std::string ecStr(ecChar) ;
    // free 
    OPENSSL_free(ecChar);
    OPENSSL_free(internal_buf);
    return ecStr;
}

int ECPoint::GroupNid() const
{
    return  m_nid; 
}

bool ECPoint::FromHex(const std::string& hexStr, int nid) {
    if(nid != -1){
        m_nid = nid;
        EC_GROUP_ptr gp (EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free);
        EC_POINT_ptr ec (EC_POINT_new(m_gp.get()), &EC_POINT_free); 
        m_gp.reset(gp.get()); 
        m_ec.reset(ec.get()); 
    }
      
    
    // Allocate for CTX
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );

    EC_POINT_hex2point(m_gp.get(), hexStr.c_str(), m_ec.get(), ctxptr.get());
    if (m_ec.get() == nullptr){
        return false;
    }
    return true;
}

bool ECPoint::FromDec(const std::string& decStr, int nid){
    if(nid != -1){
        m_nid = nid;
        EC_GROUP_ptr gp (EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free);
        EC_POINT_ptr ec (EC_POINT_new(m_gp.get()), &EC_POINT_free); 
        m_gp.reset(gp.get()); 
        m_ec.reset(ec.get()); 
    }
      
    // Allocate for CTX
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );

    BIGNUM * bnptr = BN_new();
    BN_dec2bn(&bnptr, decStr.c_str());
    // export to a buffer
    // Convert BIGNUM to binary buffer
    int buf_len = BN_num_bytes(bnptr);
    unsigned char *buf = (unsigned char *) OPENSSL_malloc(buf_len);
    BN_bn2bin(bnptr, buf);

    if(!EC_POINT_oct2point(m_gp.get(), m_ec.get(), buf, buf_len, ctxptr.get())){
        OPENSSL_free(buf);
        BN_free(bnptr);
        return false;
    }
    OPENSSL_free(buf);
    BN_free(bnptr);
    return true;
}

BigNumber ECPoint::getECGroupOrder() const {
    BigNumber bnVal;

    // Allocate for CTX
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );

    if(!EC_GROUP_get_order(m_gp.get(), bnVal.bn_ptr().get(), ctxptr.get()))
        throw std::runtime_error("failed to getECGroupOrder");

    return bnVal; 
}

int ECPoint::getECGroupDegree() const {
     return EC_GROUP_get_degree(m_gp.get());
}

ECPoint ECPoint::getGenerator() const {
    // Allocate for CTX
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    EC_GROUP_ptr gp (EC_GROUP_new_by_curve_name(m_nid), &EC_GROUP_free);

    const EC_POINT * tmp_pt = EC_GROUP_get0_generator(m_gp.get()); 
    EC_POINT_ptr ec(EC_POINT_new(m_gp.get()), &EC_POINT_free);
    if(!EC_POINT_copy(ec.get(),tmp_pt))
        throw std::runtime_error("failed tp getECGroup generator point");

    ECPoint res(gp, ec, m_nid); 
    //ECPoint res; 
    return res;
}



//------------------------------------------------------------
//  Free Functions
//------------------------------------------------------------

std::vector<std::tuple<int, std::string, std::string>> getCurveList(){
    /* Get a list of all internal curves */
    auto crvLen = EC_get_builtin_curves(NULL, 0);

    EC_builtin_curve *curves = (EC_builtin_curve *) OPENSSL_malloc(sizeof(EC_builtin_curve) * crvLen);

    if (curves == nullptr){
        throw std::runtime_error("error : Failed to allocate memory for internal curves");
    }

    if (!EC_get_builtin_curves(curves, crvLen)) {
        throw std::runtime_error("error : Failed to EC_get_builtin_curves to get internal curve list");
    }

    CurveList _curveList;
    for (int i = 0; i < crvLen; i++)
    {
        const char *sname = nullptr;

        sname =  OBJ_nid2sn(curves[i].nid);
        if (sname== nullptr)
            sname = "";
        _curveList.push_back(std::make_tuple(curves[i].nid, sname, curves[i].comment)); 
    }
  
    /* NOTE : curves has an internal pointer, comment, which shouldn't freed as its just a pointer to a constant curve_list->comment*/
    if (curves)
        ::OPENSSL_free(curves);

    return _curveList;

}


int getNidForString(const std::string& NIDstr){
    // get the curve vec list
    std::vector<std::tuple<int, std::string, std::string>> nidVec = getCurveList();
    // iterate over the vec list and look for the matched one
    for(auto& nidTuple : nidVec)
    {
        if (std::get<1>(nidTuple) == NIDstr)
        {
            return std::get<0>(nidTuple);
        }
    }
    return -1;
}

ECPoint MultiplyByGeneratorPt(const BigNumber& value, int curveID){
   // create new EC point defaulted to NID_secp256k1
    ECPoint point( curveID ) ;

    // get the generator point
    ECPoint GEN = point.getGenerator( ) ; 

    // multiply the value (as Hex string) by the generator 
    // please fix this.  We could possibily multiply by a BigNumber! 
    ECPoint result = GEN * value; 
    return result;
}



BigNumber GroupOrder(const int& nid){
     BigNumber bnVal;

    // Allocate for CTX
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free);
    if(!EC_GROUP_get_order(gp.get(), bnVal.bn_ptr().get(), ctxptr.get()))
        throw std::runtime_error("failed to getECGroupOrder");

    return bnVal; 
}

bool ComparePoints(const ECPoint& obj1, const ECPoint& obj2){
    // check if the given ECPoints are not null

    if ( obj1.GroupNid() != obj2.GroupNid()){
        return false;
    }
    // Allocate for CTX 
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    // allocate & get result group and EC struct

    int res = EC_POINT_cmp(obj1.m_gp.get(), obj1.m_ec.get(), obj2.m_ec.get(), ctxptr.get()); 
    if(res == -1){
        throw std::runtime_error("failed to compare ECPoints");
    }

    if (res != 0)
    {
        return false;
    }

    return true;
}


// G * n + q * m where G -> Group Generator, n -> BigNumber and can be null, q -> ECPoint, m -> BigNum
ECPoint Multiply(const ECPoint& ec_pt, const BigNumber& m,const BigNumber& n) {

    // Allocate for CTX 
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );

    // allocate & get result group and EC struct
    EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(ec_pt.GroupNid()), &EC_GROUP_free);
    EC_POINT_ptr ec(EC_POINT_new(gp.get()), &EC_POINT_free); 

    int res = EC_POINT_mul(gp.get(), 
                           ec.get(), 
                           n.bn_ptr().get(),
                           ec_pt.ec_ptr().get(),
                           m.bn_ptr().get(),
                           ctxptr.get());

    if (!res)
        throw std::runtime_error("error : Failed to multiply EC POINT with the BIGNUM");
   
    ECPoint res_ec(gp, ec,  ec_pt.GroupNid()); 
    return res_ec; 
}


ECPoint operator* (const ECPoint& ec_pt, const BigNumber& bn){
    // Allocate for CTX 
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    EC_GROUP_ptr gp(EC_GROUP_new_by_curve_name(ec_pt.GroupNid()), &EC_GROUP_free);
    

    EC_POINT * tmp_pt = EC_POINT_new(gp.get()); 
    EC_POINT * tmp_ec_input = ec_pt.m_ec.get();
    EC_POINT_ptr ec(EC_POINT_new(gp.get()), &EC_POINT_free); 
    // Ensure ec is initialized
    EC_POINT_set_to_infinity(gp.get(), ec.get());
    std::cout << "Input EC -> "
        << EC_POINT_point2hex(gp.get(), tmp_ec_input, POINT_CONVERSION_COMPRESSED, ctxptr.get())
        << "\nInput BN -> "  
        << BN_bn2hex(bn.bn_ptr().get())
        << "\nResult before multplying " 
        << EC_POINT_point2hex(gp.get(), ec.get(), POINT_CONVERSION_COMPRESSED, ctxptr.get())
        << std::endl; 
        
    //int mul_res = EC_POINT_mul(gp.get(),tmp_pt,NULL,ec_pt.m_ec.get(),bn.bn_ptr().get(), ctxptr.get());
    int mul_res = EC_POINT_mul(gp.get(),tmp_pt,NULL,tmp_ec_input, bn.bn_ptr().get(), ctxptr.get());
    
    if(!mul_res)
        throw std::runtime_error("failed to multiply EC Point with BIGNUM"); 

    if(!EC_POINT_copy(ec.get(),tmp_pt))
        throw std::runtime_error("failed tp getECGroup generator point");
    std::cout << "Return value from EC_POINT_mul -> " << mul_res << std::endl;
    std::cout << EC_POINT_point2hex(gp.get(), ec.get(), POINT_CONVERSION_COMPRESSED, ctxptr.get()) << std::endl; 
    ECPoint res(gp, ec, ec_pt.GroupNid()); 
    return res; 
}

ECPoint GenerateECFromHex(const std::string& hexval, const int curveID){
    ECPoint point(curveID);
    point.FromHex(hexval);
    return point; 
}

