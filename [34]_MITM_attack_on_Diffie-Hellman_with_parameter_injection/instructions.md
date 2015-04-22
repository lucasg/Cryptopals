#Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

Use the code you just worked out to build a protocol and an "echo" bot. You don't actually have to do the network part of this if you don't want; just simulate that. The protocol is:

1. A->B : Send "p", "g", "A"
2. B->A : Send "B"
3. A->B : Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
4. B->A : Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv

(In other words, derive an AES key from DH with SHA1, use it in both directions, and do CBC with random IVs appended or prepended to the message).

Now implement the following MITM attack:

1. A->M : Send "p", "g", "A"
2. M->B : Send "p", "g", "p"
3. B->M : Send "B"
4. M->A : Send "p"
5. A->M : Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
6. M->B : Relay that to B
7. B->M : Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
8. M->A : Relay that to A

M should be able to decrypt the messages. "A" and "B" in the protocol --- the public keys, over the wire --- have been swapped out with "p". Do the DH math on this quickly to see what that does to the predictability of the key.

Decrypt the messages from M's vantage point as they go by.

Note that you don't actually have to inject bogus parameters to make this attack work; you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack. But do the parameter injection attack; it's going to come up again.
