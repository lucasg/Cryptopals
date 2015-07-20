## Implement a SHA-1 keyed MAC

[Source](http://cryptopals.com/sets/4/challenges/28/)

Find a SHA-1 implementation in the language you code in. 

Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:

    SHA1(key || message)

Verify that you cannot tamper with the message without breaking the MAC you've produced, and that you can't produce a new MAC without knowing the secret key. 



### Don't cheat. It won't work.

Do not use the SHA-1 implementation your language already provides (for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).
