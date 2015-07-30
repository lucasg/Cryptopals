## Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

[Source](http://cryptopals.com/sets/6/challenges/47/)

Read the Bleichenbacher paper from CRYPTO '98 . It describes a padding oracle attack on PKCS#1v1.5. The attack is similar in spirit to the CBC padding oracle you built earlier; it's an "adaptive chosen ciphertext attack", which means you start with a valid ciphertext and repeatedly corrupt it, bouncing the adulterated ciphertexts off the target to learn things about the original.

This is a common flaw even in modern cryptosystems that use RSA.

It's also the most fun you can have building a crypto attack. It involves 9th grade math, but also has you implementing an algorithm that is complex on par with finding a minimum cost spanning tree.

The setup:

 * Build an oracle function, just like you did in the last exercise, but have it check for `plaintext[0] == 0` and `plaintext[1] == 2`.  
 * Generate a 256 bit keypair (that is, p and q will each be 128 bit primes), `[n, e, d]`.
 * Plug `d` and `n` into your oracle function.
 * PKCS1.5-pad a short message, like `"kick it, CC"`, and call it `"m"`. Encrypt to to get `"c"`.
 * Decrypt `"c"` using your padding oracle.

For this challenge, we've used an untenably small RSA modulus (you could factor this keypair instantly). That's because this exercise targets a specific step in the Bleichenbacher paper --- Step 2c, which implements a fast, nearly `O(log n)` search for the plaintext.

Things you want to keep in mind as you read the paper:

 * RSA ciphertexts are just numbers.
 * RSA is "homomorphic" with respect to multiplication, which means you can multiply `c * RSA(2)` to get a `c'` that will decrypt to `plaintext * 2`. This is mindbending but easy to see if you play with it in code --- try multiplying ciphertexts with the RSA encryptions of numbers so you know you grok it.
 * What you need to grok for this challenge is that Bleichenbacher uses multiplication on ciphertexts the way the CBC oracle uses XORs of random blocks.
 * A PKCS#1v1.5 conformant plaintext, one that starts with `00:02`, must be a number between `02:00:00...00` and `02:FF:FF..FF` --- in other words, `2B` and `3B-1`, where `B` is the bit size of the modulus minus the first 16 bits. When you see `2B` and `3B`, that's the idea the paper is playing with.

To decrypt `"c"`, you'll need Step 2a from the paper (the search for the first `"s"` that, when encrypted and multiplied with the ciphertext, produces a conformant plaintext), Step 2c, the fast `O(log n)` search, and Step 3.

Your Step 3 code is probably not going to need to handle multiple ranges.

We recommend you just use the raw math from paper (check, check, double check your translation to code) and not spend too much time trying to grok how the math works.

### Degree of difficulty: moderate