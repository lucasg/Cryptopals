## CTR bitflipping

[Source](http://cryptopals.com/sets/4/challenges/26/)

There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is susceptible.

Re-implement [the CBC bitflipping exercise from earlier](http://cryptopals.com/sets/2/challenges/16) to use CTR mode instead of CBC mode. Inject an "admin=true" token.