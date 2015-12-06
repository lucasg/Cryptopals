## DSA nonce recovery from repeated nonce
[Source](http://cryptopals.com/sets/6/challenges/44/)


[In this file](http://cryptopals.com/static/challenge-data/44.txt) find a collection of DSA-signed messages. (NB: each msg has a trailing space.)

These were signed under the following pubkey:

y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07
    13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
    5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
    f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
    f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
    2971c3de5084cce04a2e147821

(using the same domain parameters as the previous exercise)

It should not be hard to find the messages for which we have accidentally used a repeated "k". Given a pair of such messages, you can discover the "k" we used with the following formula:

         (m1 - m2)
     k = --------- mod q
         (s1 - s2)

What's my private key? Its SHA-1 (from hex) is:

   ca8f6f7c66fa362d40760d135b763eb8527d3d52

# 9th Grade Math: Study It!

If you want to demystify this, work out that equation from the original DSA equations.

# Basic cyclic group math operations want to screw you

Remember all this math is mod q; s2 may be larger than s1, for instance, which isn't a problem if you're doing the subtraction mod q. If you're like me, you'll definitely lose an hour to forgetting a paren or a mod q. (And don't forget that modular inverse function!)

# Cryptanalytic MVP award.

This attack (in an elliptic curve group) broke the PS3. It is a great, great attack.