## Break fixed-nonce CTR mode using substitions

[Source](http://cryptopals.com/sets/3/challenges/19/)

Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.

In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts: 

    SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
    Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
    RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
    RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
    SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
    T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
    T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
    UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
    QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
    T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
    VG8gcGxlYXNlIGEgY29tcGFuaW9u
    QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
    QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
    QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
    QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
    QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
    VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
    SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
    SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
    VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
    V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
    V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
    U2hlIHJvZGUgdG8gaGFycmllcnM/
    VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
    QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
    VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
    V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
    SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
    U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
    U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
    VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
    QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
    SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
    VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
    WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
    SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
    SW4gdGhlIGNhc3VhbCBjb21lZHk7
    SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
    VHJhbnNmb3JtZWQgdXR0ZXJseTo=
    QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=

(This should produce 40 short CTR-encrypted ciphertexts).

Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. This is very bad.

Understanding that, like most stream ciphers (including RC4, and obviously any block cipher run in CTR mode), the actual "encryption" of a byte of data boils down to a single XOR operation, it should be plain that:

    CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE

And since the keystream is the same for every ciphertext:

    CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
    say!")

Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses, catch common English trigrams, and so on.

### Don't overthink it.
Points for automating this, but part of the reason I'm having you do this is that I think this approach is suboptimal.

 

