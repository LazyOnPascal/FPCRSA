## FPCRSA
Implementing the RSA Algorithm in Lazarus

## The Original Code is TurboPower LockBox
Visit https://sourceforge.net/projects/tplockbox/

## How to use
```
Add package FPCRSA/lib/fpcrsalib.lpk in you project (read https://wiki.freepascal.org/Lazarus_Packages#Use_your_package_in_your_project)
or add FPCRSA/source/ as source directory

Uses ..., LbRSA, LbAsym, LbRandom;
...
var LbRSA1: TLbRSA;
sEncoded, sDecoded: string;
...
LbRSA1 := TLbRSA.Create(nil, 'RSA key name', aks2048); //create a key object with a length of 2048 bits
LbRSA1.GenerateKeyPair; 
//Now we have unique keys, private and public part
sEncoded := LbRSA1.EncryptString('my secret string');
// sEncoded is now encoded using the public key from LbRSA1
sDecoded := LbRSA1.DecryptString(sEncoded);
// sDecoded is now decoded using a private key and is again equal to 'my secret string'
```
