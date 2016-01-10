## DSA parameter tampering
[Source](http://cryptopals.com/sets/6/challenges/45/)

Take your DSA code from the previous exercise. Imagine it as part of an algorithm in which the client was allowed to propose domain parameters (the p and q moduli, and the g generator).

This would be bad, because attackers could trick victims into accepting bad parameters. Vaudenay gave two examples of bad generator parameters: generators that were 0 mod p, and generators that were 1 mod p.

Use the parameters from the previous exercise, but substitute 0 for "g". Generate a signature. You will notice something bad. Verify the signature. Now verify any other signature, for any other string.

Now, try (p+1) as "g". With this "g", you can generate a magic signature s, r for any DSA public key that will validate against any string. For arbitrary z:

  r = ((y**z) % p) % q

        r
  s =  --- % q
        z

Sign "Hello, world". And "Goodbye, world". 