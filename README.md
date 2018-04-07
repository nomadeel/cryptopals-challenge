# cryptopals-challenge

This repository holds my solutions to the challenges located at https://cryptopals.com/. This is my 'Something Awesome' project
as part of COMP6841 at UNSW.

The solutions requires the following:
* **cmake**: The cmake build system, https://cmake.org/.
* **cryptopp**: A free C++ library of cryptographic schemes, https://github.com/weidai11/cryptopp.

In the root of the repository directory, there is a bash script called **setup.sh** which when executed will clone the
**crytopp** library and build the files. Additionally, it will setup the **cmake** build system which will generate the
Makefiles for each solution subdirectory.
