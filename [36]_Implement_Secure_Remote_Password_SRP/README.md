## Implement Secure Remote Password (SRP)

[Source](http://cryptopals.com/sets/5/challenges/36/)

To understand SRP, look at how you generate an AES key from DH; now, just observe you can do the "opposite" operation an generate a numeric parameter from a hash. Then:

Replace A and B with C and S (client & server)

**C & S**

    Agree on N=[NIST Prime], `g=2`, `k=3`, I (email), P (password)
    
**S**

 1. Generate salt as random integer
 2. Generate string `xH=SHA256(salt|password)`
 3. Convert `xH` to integer `x` somehow (put `0x` on hexdigest)
 4. Generate `v=g**x % N`
 5. Save everything but `x`, `xH`

**C->S**

    Send I, `A=g**a % N`(a la Diffie Hellman)
    
**S->C**

    Send salt, `B=kv + g**b % N`.
    
**S, C**

    Compute string `uH = SHA256(A|B)`, `u = integer of uH`
    
**C**

 1. Generate string `xH=SHA256(salt|password)`
 2. Convert `xH` to integer `x` somehow (put `0x` on hexdigest)
 3. Generate `S = (B - k * g**x)**(a + u * x) % N`
 4. Generate `K = SHA256(S)`

**S**

 1. Generate `S = (A * v**u) ** b % N`
 2. Generate `K = SHA256(S)`

**C->S**

    Send `HMAC-SHA256(K, salt)`
    
**S->C**

    Send "OK" if `HMAC-SHA256(K, salt)` validates

You're going to want to do this at a REPL of some sort; it may take a couple tries.

It doesn't matter how you go from integer to string or string to integer (where things are going in or out of SHA256) as long as you do it consistently. I tested by using the ASCII decimal representation of integers as input to SHA256, and by converting the hexdigest to an integer when processing its output.

This is basically Diffie Hellman with a tweak of mixing the password into the public keys. The server also takes an extra step to avoid storing an easily crackable password-equivalent. 
