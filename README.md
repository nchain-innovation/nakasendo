# Nakasendo core library
This library provides a python and c/c++ implementation of the core features of NChains Nakasendo. 

# Submodules. 
This project has a github submodule included. Please execute below after cloning the repo.

```bash
git submodule update --init --recursive
```
# To build the c/c++
```bash
mkdir build
cd build
cmake ../ -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON
make 
make test
```

# To build the python wheel
* Install a pyton virtual environment and source it
* pip3 wheel -w build . --verbose
* pip3 install --force-reinstall build/pynakasendo-0.0.1-cp313-cp313-macosx_15_0_arm64.whl

## Python tests
```bash
cd src/python
./tests.sh
```

