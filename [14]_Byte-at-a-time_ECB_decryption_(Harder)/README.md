## Byte-at-a-time ECB decryption (Harder)

[Source](http://cryptopals.com/sets/2/challenges/14/)

Take your oracle function [from #12](http://cryptopals.com/sets/2/challenges/12/). Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing: 

    AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.

### Stop and think for a second.

What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think `STIMULUS` and `RESPONSE`.
