
####How to Hash a key securely?
H(x) -> y and in cookies 'x|H(x)' is as a pair stored in cookies. So we can not modify x without modify y. But if we know the hash algorithm we use (i.e. md5()), we can calculate the hash value of x very easily. To solve this problem, we could add a secret string to x, so that H(x + secret) -> y. As long as the secret string remains secret, attacer will not be able to forge the hash value of x.

Hash-based Message Authentication Code (HMAC)

import hmac
hmac.new(secret, key,hashmode) = [HASH]

the same result of previous methd


Rainbow table 
rainbow table is inverse map of HASH(x) -> x, so given H(x), attacker could guess the correct x.
We can solve the problem by giving a secret message to x. 
But if we always use the same secret massage, it is also possible for attacker to crack the passsword. 

