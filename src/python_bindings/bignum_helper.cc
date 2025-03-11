#include <bignum_helper.h>
#include <pybind11/pytypes.h> 


BigNumber PyIntToBigNumber(pybind11::int_ val){
    BigNumber bn; 
    
    pybind11::bytes pyBytes = val.attr("to_bytes")(val.attr("__sizeof__")(), "big");
    std::string bytesStr = pyBytes; 

    bn.FromBin (reinterpret_cast<unsigned char*>(bytesStr.data()), (int)bytesStr.size()); 
    return bn;
}