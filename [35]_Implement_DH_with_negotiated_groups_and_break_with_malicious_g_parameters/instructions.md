# Implement DH with negotiated groups, and break with malicious "g" parameters #

A->B
    Send "p", "g"
B->A
    Send ACK
A->B
    Send "A"
B->A
    Send "B"
A->B
    Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A
    Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv

Do the MITM attack again, but play with "g". What happens with:

    `g = 1`
    `g = p`
    `g = p - 1`

Write attacks for each.

## When does this ever happen? ##
Honestly, not that often in real-world systems. If you can mess with "g", chances are you can mess with something worse. Most systems pre-agree on a static DH group. But the same construction exists in Elliptic Curve Diffie-Hellman, and this becomes more relevant there.


## Attacks ##

	1. `g = 1` : When `g` equals to `1`, every public key equals to `1`.
	2. `g = p` : When `g` equals to `p`, every public key equals to `0`.
	3. `g = p - 1` : When `g` equals to `p - 1`, every public key is equal either to 1 or (p - 1) : `A = (p-1)^a [p] = (p-1)*(a % 2) + 1*(a-1 % 2) [p]`.

