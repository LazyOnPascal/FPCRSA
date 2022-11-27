## FPCRSA
Implementing the RSA Algorithm in Lazarus

## The Original Code is TurboPower LockBox
Visit https://sourceforge.net/projects/tplockbox/

## How to use
```
Uses ..., LbRSA, LbAsym, LbRandom;
...
var LbRSA1: TLbRSA;
...
LbRSA1 := TLbRSA.Create(nil, 'RSA key name', aks2048); //create a key object with a length of 2048 bits
LbRSA1.GenerateKeyPair; 
sEncoded := aKey.EncryptString('my secret string');
sDecoded := LbRSA1.DecryptString(sEncoded);
```
