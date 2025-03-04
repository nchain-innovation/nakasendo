#include <bignum_helper.h>
#include <pybind11/pytypes.h> 


BigNumber PyIntToBigNumber(pybind11::int_ val){
    BigNumber bn; 
    
    pybind11::bytes pyBytes = val.attr("to_bytes")(val.attr("__sizeof__")(), "big");
    std::string bytesStr = pyBytes; 

    bn.FromBin (reinterpret_cast<unsigned char*>(bytesStr.data()), (int)bytesStr.size()); 

    //BN_bin2bn(reinterpret_cast<const unsigned char*>(bytesStr.data()), bytesStr.size(), bn);
    //return BigNumber(bn);
    return bn;
}