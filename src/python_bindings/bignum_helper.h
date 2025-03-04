#ifndef __BIG_NUM_HELPER__
#define __BIG_NUM_HELPER__
#include <pybind11/pybind11.h>
#include <pybind11/operators.h> 
#include <BigNumbers/BigNumbers.h>


BigNumber PyIntToBigNumber(pybind11::int_);
#endif //ifndef __BIG_NUM_HELPER__