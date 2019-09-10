# my-sgx
[![license](https://img.shields.io/badge/license-GPL3-brightgreen.svg)](https://github.com/qygh/my-sgx/blob/master/LICENSE)

This is a simple implementation of the [PAPEETE (Private, Authorised, fast PErsonal gEnomic TEsting)](http://discovery.ucl.ac.uk/10049432/) protocol using [Intel SGX](https://software.intel.com/en-us/sgx) for Linux.


## Pre-requisites
  - Ensure SGX is enabled in the BIOS.

  - Ensure Intel SGX Linux [driver](https://github.com/intel/linux-sgx-driver) is installed.

  - Ensure [SDK **2.3**](https://download.01.org/intel-sgx/linux-2.3) and [PSW](https://github.com/intel/linux-sgx#install-the-intelr-sgx-psw) are installed.


## Build
Build **my-sgx** as follows:

  - Source the Intel SGX SDK as described [here](https://github.com/intel/linux-sgx#install-the-intelr-sgx-sdk-1); if your SDK installation path is `/opt/intel/sgxsdk/`, run:
```
$ source /opt/intel/sgxsdk/environment
```

  - To build in **Simulation Mode** (non-SGX version):
```
$ git clone git clone https://github.com/qygh/my-sgx
$ cd my-sgx
$ make
```

  - To build in **Hardware Mode** (SGX version):
```
$ git clone git clone https://github.com/qygh/my-sgx
$ cd my-sgx
$ make SGX_MODE=HW SGX_PRERELEASE=1
```


## Usage
  - Remember to source the SGX SDK before running non-SGX version of the application:
```
$ source /opt/intel/sgxsdk/environment
```

**my-sgx** comes with a simple command-line interface that can be run with the following options:
  - Show help:
```
$ ./my-sgx
```

  - Run self-test:
```
$ ./my-sgx -m test
``` 

  - Decode result into human-readable format from raw result file `result.data`:
```
$ ./my-sgx -m decode_result -s result result.data
``` 

  - Run as Testing Facility in offline phase with weights file `ws.data` containing `n` weights and Certification Authority `ca_hostname` on port `ca_port`:
```
$ ./my-sgx -m offline_t -h ca_hostname -p ca_port -n n -w ws.data
``` 

  - Run as Certification Authority in offline phase with listening port `ca_port` and `n` weights:
```
$ ./my-sgx -m offline_ca -b ca_port -n n
``` 

  - Run as User in online phase with Certification Authority `ca_hostname` on port `ca_port`, Testing Facility `t_hostname` on port `t_port` and SNPs file `snps.data` containing `n` SNPs:
```
$ ./my-sgx -m online_u -h ca_hostname -p ca_port -i t_hostname -q t_port -n n -s snps.data
``` 

  - Run as Testing Facility in online phase with listening port `t_port`, the key file `x.data` and encrypted and authorised weights file `cts.data` containing `n` weights:
```
$ ./my-sgx -m online_t -b t_port -n n -x x.data -c cts.data
``` 

  - Run as Certification Authority in online phase with listening port `ca_port`, the key file `d.data` and `n` SNPs/weights:
```
$ ./my-sgx -m online_ca -b ca_port -n n -d d.data
``` 


## Format for weights and SNPs file
  - Each weight is represented as a 32-bit unsigned integer with **little-endian** byte order. The hexadecimal values of a file containing the 5 weights `1, 2, 5, 32, 256` should be:
```
0x01 0x00 0x00 0x00 0x02 0x00 0x00 0x00 0x05 0x00 0x00 0x00 0x20 0x00 0x00 0x00 0x00 0x01 0x00 0x00
```

  - Each SNP can have value 0, 1 or 2 and is represented as a single byte. The hexadecimal values of a file containing the 5 SNPs `0, 1, 2, 0, 2` should be:
```
0x00 0x01 0x02 0x00 0x02
```


## Contribute
Any help is welcome through PRs!


## License
[The GPLv3 license](https://www.gnu.org/licenses/gpl-3.0.en.html)


