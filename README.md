# sgx-wallet
[![license](https://img.shields.io/badge/license-GPL3-brightgreen.svg)](https://github.com/asonnino/sgx-wallet/blob/master/LICENSE)

This is a simple password wallet application based on Intel SGX on linux. 


## Pre-requisites
Ensure to have installed the Intel SGX Linux [drivers](https://github.com/intel/linux-sgx-driver) and [SDK](https://github.com/intel/linux-sgx).


## Install
*sgx-wallet* can be installed as follows:

  - Source the Intel SGX SDK as described [here](https://github.com/intel/linux-sgx#install-the-intelr-sgx-sdk-1):
```
$ source ${sgx-sdk-install-path}/environment
```
where `${sgx-sdk-install-path}` is your SDK installation path. 

  - Clone and build the source code:
```
$ git clone https://github.com/asonnino/sgx-wallet.git
$ cd sgx-wallet
$ make
```


## Usage
The current cli can be run with the following options:
  - Show help:
```
sgx-wallet -h
```

  - Show version:
```
sgx-wallet -v
```

  - Run tests:
```
sgx-wallet -t
``` 

  - create a new wallet with master-password `<master-passowrd>`:
```
sgx-wallet -n master-password
``` 

  - Change current master-password to `<new-master-password>`:
```
sgx-wallet -p master-password -c new-master-password
``` 

  - Add a new item to the wallet with title `<items_title>`, username `<items_username>`, and password `<items_password>`:
```
sgx-wallet -p master-password -a -x items_title -y items_username -z toitems_password
``` 

  - Remove item at index `<items_index>` from the wallet:
```
sgx-wallet -p master-password -r items_index
``` 


## Contribute
Any help is welcome through PRs!


## License
[The GPLv3 license](https://www.gnu.org/licenses/gpl-3.0.en.html)


