## Bleichenbacher's PKCS 1.5 Padding Oracle (Complete  Case)

[Source](http://cryptopals.com/sets/6/challenges/48/)

This is a continuation of challenge #47; it implements the complete BB'98 attack.

Set yourself up the way you did in #47, but this time generate a `768` bit modulus.

To make the attack work with a realistic RSA keypair, you need to reproduce `step 2b` from the paper, and your implementation of `Step 3` needs to handle multiple ranges.

The full Bleichenbacher attack works basically like this: 

* Starting from the smallest 's' that could possibly produce a plaintext bigger than 2B, iteratively search for an 's' that produces a conformant plaintext.
* For our known `s1` and `n`, solve `m1=m0s1-rn` (again: just a definition of modular multiplication) for `r`, the number of times we've wrapped the modulus.
* `m0` and `m1` are unknowns, but we know both are conformant `PKCS#1v1.5` plaintexts, and so are between `[2B,3B]`.
* We substitute the known bounds for both, leaving only `r` free, and solve for a range of possible `r` values. This range should be small!
* Solve `m1=m0s1-rn` again but this time for `m0`, plugging in each value of `r` we generated in the last step. This gives us new intervals to work with. Rule out any interval that is outside `[2B,3B]`.
* Repeat the process for successively higher values of `s`. Eventually, this process will get us down to just one interval, whereupon we're back to exercise #47.

What happens when we get down to one interval is, we stop blindly incrementing `s`; instead, we start rapidly growing `r` and backing it out to `s` values by solving `m1=m0s1-rn` for `s` instead of `r` or `m0`. So much algebra! Make your teenage son do it for you! *Note: does not work well in practice* 

### Cryptanalytic MVP award

This is an extraordinarily useful attack. PKCS#1v15 padding, despite being totally insecure, is the default padding used by RSA implementations. The OAEP standard that replaces it is not widely implemented. This attack routinely breaks SSL/TLS. 