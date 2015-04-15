# Cryptopals
Matasano crypto challenges (http://cryptopals.com/) implemented mostly in C.

Every challenge compile either on Windows (using mingw32 toolchain) or on Linux (Mint and Arch tested).
Some challenges also use Python3.xxx. 

## Set 1

  - [X] [Convert hex to base64](http://cryptopals.com/sets/1/challenges/1/)
  - [X] [Fixed XOR](http://cryptopals.com/sets/1/challenges/2/)
  - [X] [Single-byte XOR cipher](http://cryptopals.com/sets/1/challenges/3/)
  - [X] [Detect single-character XOR](http://cryptopals.com/sets/1/challenges/4/)
  - [X] [Implement repeating-key XOR](http://cryptopals.com/sets/1/challenges/5/)
  - [ ] [Break repeating-key XOR](http://cryptopals.com/sets/1/challenges/6/)
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
  - [ ] [Implement and break HMAC-SHA1 with an artificial timing leak](http://cryptopals.com/sets/4/challenges/31/)
  - [ ] [Break HMAC-SHA1 with a slightly less artificial timing leak](http://cryptopals.com/sets/4/challenges/32/)

## Set 5

  - [ ] [Implement Diffie-Hellman](http://cryptopals.com/sets/5/challenges/33)
  - [ ] [Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](http://cryptopals.com/sets/5/challenges/34)
  - [ ] [Implement DH with negotiated groups, and break with malicious "g" parameters](http://cryptopals.com/sets/5/challenges/35)
  - [ ] [Implement Secure Remote Password (SRP)](http://cryptopals.com/sets/5/challenges/36)
  - [ ] [Break SRP with a zero key](http://cryptopals.com/sets/5/challenges/37)
  - [ ] [Offline dictionary attack on simplified SRP](http://cryptopals.com/sets/5/challenges/38)
  - [ ] [Implement RSA](http://cryptopals.com/sets/5/challenges/39)
  - [ ] [Implement an E=3 RSA Broadcast attack](http://cryptopals.com/sets/5/challenges/40)

## Set 6

  - [ ] [Implement unpadded message recovery oracle](http://cryptopals.com/sets/6/challenges/41)
  - [ ] [Bleichenbacher's e=3 RSA Attack](http://cryptopals.com/sets/6/challenges/42)
  - [ ] [DSA key recovery from nonce](http://cryptopals.com/sets/6/challenges/43)
  - [ ] [DSA nonce recovery from repeated nonce](http://cryptopals.com/sets/6/challenges/44)
  - [ ] [DSA parameter tampering](http://cryptopals.com/sets/6/challenges/45)
  - [ ] [RSA parity oracle](http://cryptopals.com/sets/6/challenges/46)
  - [ ] [Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)](http://cryptopals.com/sets/6/challenges/47)
  - [ ] [Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)](http://cryptopals.com/sets/6/challenges/48)
