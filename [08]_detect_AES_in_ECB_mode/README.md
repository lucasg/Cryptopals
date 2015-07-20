## Detect AES in ECB mode

[Source](http://cryptopals.com/sets/1/challenges/8/)

[In this file](http://cryptopals.com/static/challenge-data/8.txt) are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
r a reason. You'll need it a lot later on, and not just for attacking ECB. 


