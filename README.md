# Cryptopals
Matasano crypto challenges (http://cryptopals.com/) implemented mostly in C.

## Introduction ##

This is a serie of 56 technical challenges around software programming and cryptography made by some people at Matasano. Every solution can be built either on Windows or on Linux (Mint and Arch tested). 

The tools folder contains implementations of several standard cryptographic protocols and utilities : do not use them in production.

## Requirements ##

* You need to have access to the `gcc` toochain and basic shell commands (`make`, `cd`, `sed`, `awk`, etc.). On Windows, every challenge has been tested against the `mingw32` compiler.
* Some challenges use pythons scripts : everything has been written for Python 3xx. Older versions may or may not work.
* `pip` requirements :
  * On Linux, install `pip3` : `sudo (apt-get install | yum install |  pacman -S)  python3-pip` to prevent name clashing with the system-wide pip binary.
  * `bottle` web framework  for challenges 31 & 32
  * `tkinter` for challenge 20
* `libcurl` : challenge 31 & 32 use libcurl to make requests to a remote webpage.
  * Libcurl isn't installed by default on Windows, so you will need to download the static library compatible with your compiler (or build it yourself) and placing it in the corresponding's lib folder. Download page : http://curl.haxx.se/download.html
  * On Unix systems, you can either use libcurl statically of dynamically (modify the `Makefile` to your needs). Don't forget to add the installed lib folder (something like `/usr/lib/x86_64-linux-gnu` ) in the `LDFLAGS`.
  

## Usage ##

The `Makefile` located in the root folder contains every useful commands, while `global.mk` has every project-wide variables.

Ex :

* `make 01 all`  will build all the targets in first challenge.
* `make tools`   will build all the necessary libraries and bins in the tools folder.
* `make exos clean`  will run `make clean` on every challenges.
* `make exos compile`  will run `make compile` on every challenges, building the binary.
* `make exos solve`  will run `make solve` on every challenges, building the binary and running it.
* `make 01 07 09 solve`  will run `make solve` on challenge 01, 07 and 09.


Caveat : challenge `#31 & #32` can't be called from the top-level Makefile since you need to fire up a websever. To test the challenge , you need to type :

  - cd `"[$ex]_..."`
  - `make webserver` on one terminal
  - `make solve` on an another terminal

---

## Set 1

  - [X] [Convert hex to base64](http://cryptopals.com/sets/1/challenges/1/)
  - [X] [Fixed XOR](http://cryptopals.com/sets/1/challenges/2/)
  - [X] [Single-byte XOR cipher](http://cryptopals.com/sets/1/challenges/3/)
  - [X] [Detect single-character XOR](http://cryptopals.com/sets/1/challenges/4/)
  - [X] [Implement repeating-key XOR](http://cryptopals.com/sets/1/challenges/5/)
  - [X] [Break repeating-key XOR](http://cryptopals.com/sets/1/challenges/6/)
  - [X] [AES in ECB mode](http://cryptopals.com/sets/1/challenges/7/)
  - [X] [Detect AES in ECB mode](http://cryptopals.com/sets/1/challenges/8/)

## Set 2

  - [X] [Implement PKCS#7 padding](http://cryptopals.com/sets/2/challenges/9/)
  - [X] [Implement CBC mode](http://cryptopals.com/sets/2/challenges/10/)
  - [X] [An ECB/CBC detection oracle](http://cryptopals.com/sets/2/challenges/11/)
  - [X] [Byte-at-a-time ECB decryption (Simple)](http://cryptopals.com/sets/2/challenges/12/)
  - [X] [ECB cut-and-paste](http://cryptopals.com/sets/2/challenges/13/)
  - [X] [Byte-at-a-time ECB decryption (Harder)](http://cryptopals.com/sets/2/challenges/14/)
  - [X] [PKCS#7 padding validation](http://cryptopals.com/sets/2/challenges/15/)
  - [X] [CBC bitflipping attacks](http://cryptopals.com/sets/2/challenges/16/)

## Set 3

  - [X] [The CBC padding oracle](http://cryptopals.com/sets/3/challenges/17/)
  - [X] [Implement CTR, the stream cipher mode](http://cryptopals.com/sets/3/challenges/18/)
  - [X] [Break fixed-nonce CTR mode using substitions](http://cryptopals.com/sets/3/challenges/19/)
  - [X] [Break fixed-nonce CTR statistically](http://cryptopals.com/sets/3/challenges/20/)
  - [X] [Implement the MT19937 Mersenne Twister RNG](http://cryptopals.com/sets/3/challenges/21/)
  - [X] [Crack an MT19937 seed](http://cryptopals.com/sets/3/challenges/22/)
  - [X] [Clone an MT19937 RNG from its output](http://cryptopals.com/sets/3/challenges/23/)
  - [X] [Create the MT19937 stream cipher and break it](http://cryptopals.com/sets/3/challenges/24/)

## Set 4

  - [X] [Break "random access read/write" AES CTR](http://cryptopals.com/sets/4/challenges/25/)
  - [X] [CTR bitflipping](http://cryptopals.com/sets/4/challenges/26/)
  - [X] [Recover the key from CBC with IV=Key](http://cryptopals.com/sets/4/challenges/27/)
  - [X] [Implement a SHA-1 keyed MAC](http://cryptopals.com/sets/4/challenges/28/)
  - [X] [Break a SHA-1 keyed MAC using length extension](http://cryptopals.com/sets/4/challenges/29/)
  - [X] [Break an MD4 keyed MAC using length extension](http://cryptopals.com/sets/4/challenges/30/)
  - [X] [Implement and break HMAC-SHA1 with an artificial timing leak](http://cryptopals.com/sets/4/challenges/31/)
  - [X] [Break HMAC-SHA1 with a slightly less artificial timing leak](http://cryptopals.com/sets/4/challenges/32/)
    ↳ This challenge works only on Linux (Arch Linux & Mint tested).

## Set 5

  - [X] [Implement Diffie-Hellman](http://cryptopals.com/sets/5/challenges/33)
  - [X] [Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](http://cryptopals.com/sets/5/challenges/34)
  - [X] [Implement DH with negotiated groups, and break with malicious "g" parameters](http://cryptopals.com/sets/5/challenges/35)
  - [X] [Implement Secure Remote Password (SRP)](http://cryptopals.com/sets/5/challenges/36)
  - [X] [Break SRP with a zero key](http://cryptopals.com/sets/5/challenges/37)
  - [ ] [Offline dictionary attack on simplified SRP](http://cryptopals.com/sets/5/challenges/38)
  - [x] [Implement RSA](http://cryptopals.com/sets/5/challenges/39)
  - [X] [Implement an E=3 RSA Broadcast attack](http://cryptopals.com/sets/5/challenges/40)

## Set 6

  - [ ] [Implement unpadded message recovery oracle](http://cryptopals.com/sets/6/challenges/41)
  - [ ] [Bleichenbacher's e=3 RSA Attack](http://cryptopals.com/sets/6/challenges/42)
  - [ ] [DSA key recovery from nonce](http://cryptopals.com/sets/6/challenges/43)
  - [ ] [DSA nonce recovery from repeated nonce](http://cryptopals.com/sets/6/challenges/44)
  - [ ] [DSA parameter tampering](http://cryptopals.com/sets/6/challenges/45)
  - [ ] [RSA parity oracle](http://cryptopals.com/sets/6/challenges/46)
  - [ ] [Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)](http://cryptopals.com/sets/6/challenges/47)
  - [ ] [Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)](http://cryptopals.com/sets/6/challenges/48)

## Set 7
  
  - [ ] [CBC-MAC Message Forgery](http://cryptopals.com/sets/7/challenges/49)
  - [ ] [Hashing with CBC-MAC](http://cryptopals.com/sets/7/challenges/50)
  - [ ] [Compression Ratio Side-Channel Attacks](http://cryptopals.com/sets/7/challenges/51)
  - [ ] [Iterated Hash Function Multicollisions](http://cryptopals.com/sets/7/challenges/52)
  - [ ] [Kelsey and Schneier's Expandable Messages](http://cryptopals.com/sets/7/challenges/53)
  - [ ] [Kelsey and Kohno's Nostradamus Attack](http://cryptopals.com/sets/7/challenges/54)
  - [ ] [MD4 Collisions](http://cryptopals.com/sets/7/challenges/55)
  - [ ] [RC4 Single-Byte Biases](http://cryptopals.com/sets/7/challenges/56)

---


## Licensing

My own code is free to use (attribution is nice, but not mandatory). Other licenses :

* curl : libcurl has a fairy complicated license mix. Since I only link against the lib, my work is not derivative and is not subject to libcurl's licenses.
* mini-gmp is doubly licensed GPL and LGPL. 
* sha1 is copied from polarSSL/mbed is GPL also.
* sha256 is copied from Brad conte crypto-algorithms and is copyleft.
* rsa prime generation is adapted from SSH 1.2.0, found in MIT Athena's project (Copyright 1995 SSH Communications Security).