## Break an MD4 keyed MAC using length extension

[Source](http://cryptopals.com/sets/4/challenges/30/)

Second verse, same as the first, but use MD4 instead of SHA-1. Having done this attack once against SHA-1, the MD4 variant should take much less time; mostly just the time you'll spend Googling for an implementation of MD4. 


### You're thinking, why did we bother with this?

Blame Stripe. In their second CTF game, the second-to-last challenge involved breaking an H(k, m) MAC with SHA1. Which meant that SHA1 code was floating all over the Internet. MD4 code, not so much. 