# Break SRP with a zero key 

Get your SRP working in an actual client-server setting. "Log in" with a valid password using the protocol.

Now log in without your password by having the client send 0 as its "A" value. What does this to the "S" value that both sides compute?

Now log in without your password by having the client send N, N*2, &c.


## Cryptanalytic MVP award
Trevor Perrin and Nate Lawson taught us this attack 7 years ago. It is excellent. Attacks on DH are tricky to "operationalize". But this attack uses the same concepts, and results in auth bypass. Almost every implementation of SRP we've ever seen has this flaw; if you see a new one, go look for this bug.


## Attacks
  - A = 0 => S = 0 => K = SHA256("0")
  - A = N => S = 0 => K = SHA256("0")
  - A = N**2 => S = 0 => K = SHA256("0")