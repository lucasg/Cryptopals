## Offline dictionary attack on simplified SRP

[Source](http://cryptopals.com/sets/5/challenges/38/)


**S**

    x = SHA256(salt|password)
    v = g**x % n

**C->S**

    I, A = g**a % n

**S->C**

    salt, B = g**b % n, u = 128 bit random number

**C**

    x = SHA256(salt|password)
    S = B**(a + ux) % n
    K = SHA256(S)

**S**

    S = (A * v ** u)**b % n
    K = SHA256(S)

**C->S**
    Send `HMAC-SHA256(K, salt)`
**S->C**
    Send "OK" if `HMAC-SHA256(K, salt)` validates

Note that in this protocol, the server's "B" parameter doesn't depend on the password (it's just a Diffie Hellman public key).

Make sure the protocol works given a valid password.

Now, run the protocol as a MITM attacker: pose as the server and use arbitrary values for `b`, `B`, `u`, and `salt`.

Crack the password from A's `HMAC-SHA256(K, salt)`.
