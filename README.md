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

  - [X] [Convert hex to base64]([01]_base64/)
  - [X] [Fixed XOR]([02]_fixed_xor/)
  - [X] [Single-byte XOR cipher]([03]_single_byte_xor_cipher/)
  - [X] [Detect single-character XOR]([04]_detect_single_character_xor/)
  - [X] [Implement repeating-key XOR]([05]_repeating_key_xor_cipher/)
  - [X] [Break repeating-key XOR]([06]_break_repeat_key_cipher/)
  - [X] [AES in ECB mode]([07]_AES_in_ECB_mode/)
  - [X] [Detect AES in ECB mode]([08]_detect_AES_in_ECB_mode/)

## Set 2

  - [X] [Implement PKCS#7 padding]([09]_PCKS_#7_padding/)
  - [X] [Implement CBC mode]([10]_AES_in_CBC_mode/)
  - [X] [An ECB/CBC detection oracle]([11]_AES_ECB_detection_oracle/)
  - [X] [Byte-at-a-time ECB decryption (Simple)]([12]_Byte-at-a-time_ECB_decryption_(Simple)/)
  - [X] [ECB cut-and-paste]([13]_ECB_cut_and_paste/)
  - [X] [Byte-at-a-time ECB decryption (Harder)]([14]_Byte-at-a-time_ECB_decryption_(Harder)/)
  - [X] [PKCS#7 padding validation]([15]_PKCS_#7_padding_validation/)
  - [X] [CBC bitflipping attacks]([16]_CBC_bitflipping_attacks/)

## Set 3

  - [X] [The CBC padding oracle]([17]_CBC_padding_oracle/)
  - [X] [Implement CTR, the stream cipher mode]([18]_AES_in_CTR_mode/)
  - [X] [Break fixed-nonce CTR mode using substitions]([19]_break_AES_in_CTR_mode_manually/)
  - [X] [Break fixed-nonce CTR statistically]([20]_break_AES_in_CTR_mode_statistically/)
  - [X] [Implement the MT19937 Mersenne Twister RNG]([21]_Implement_the_MT19937_Mersenne_Twister_RNG/)
  - [X] [Crack an MT19937 seed]([22]_Crack_an_MT19937_seed/)
  - [X] [Clone an MT19937 RNG from its output]([23]_Clone_an_MT19937_RNG/)
  - [X] [Create the MT19937 stream cipher and break it]([24]_Create_the_MT19937_stream_cipher_and_break_it/)

## Set 4

  - [X] [Break "random access read/write" AES CTR]([25]_Break_RARW_AES_CTR/)
  - [X] [CTR bitflipping]([26]_CTR_bitflipping_attack/)
  - [X] [Recover the key from CBC with IV=Key]([27]_Recover_the_key_from_CBC_with_IV_eq_Key/)
  - [X] [Implement a SHA-1 keyed MAC]([28]_Implement_a_SHA-1_keyed_MAC/)
  - [X] [Break a SHA-1 keyed MAC using length extension]([29]_Break_SHA-1_keyed_MAC_using_length_extension/)
  - [X] [Break an MD4 keyed MAC using length extension]([30]_Break_a_MD4_keyed_MAC_using_length_extension/)
  - [X] [Implement and break HMAC-SHA1 with an artificial timing leak]([31]_Implement_and_break_HMAC_SHA1_with_an_artificial_timing_leak/)
  - [X] [Break HMAC-SHA1 with a slightly less artificial timing leak]([32]_Break_HMAC_SHA1_with_a_slightly_less_artificial_timing_leak/) 
    - This challenge works only on Linux (Arch Linux & Mint tested).

## Set 5

  - [X] [Implement Diffie-Hellman]([33]_Implement_Diffie_Hellman/)
  - [X] [Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection]([34]_MITM_attack_on_Diffie-Hellman_with_parameter_injection/)
  - [X] [Implement DH with negotiated groups, and break with malicious "g" parameters]([35]_Implement_DH_with_negotiated_groups_and_break_with_malicious_g_parameters/)
    - Done on paper only
  - [X] [Implement Secure Remote Password (SRP)]([36]_Implement_Secure_Remote_Password_SRP/)
  - [X] [Break SRP with a zero key]([37]_Break_SRP_with_a_zero_key/)
  - [X] [Offline dictionary attack on simplified SRP]([38]_Offline_dictionary_attack_on_simplified_SRP/)
  - [x] [Implement RSA]([39]_Implement_RSA/)
  - [X] [Implement an E=3 RSA Broadcast attack]([40]_Implement_an_E3_Broadcast_attack/)

## Set 6

  - [X] [Implement unpadded message recovery oracle]([41]_Implement_unpadded_message_recovery_oracle/)
  - [x] [Bleichenbacher's e=3 RSA Attack]([42]_Bleichenbacher_s_e3_RSA_Attack/)
  - [ ] [DSA key recovery from nonce](http://cryptopals.com/sets/6/challenges/43)
  - [ ] [DSA nonce recovery from repeated nonce](http://cryptopals.com/sets/6/challenges/44)
  - [ ] [DSA parameter tampering](http://cryptopals.com/sets/6/challenges/45)
  - [x] [RSA parity oracle]([46]_RSA_parity_oracle/)
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