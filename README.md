## FPCRSA
Implementing the RSA Algorithm in Lazarus

## The Original Code is TurboPower LockBox
Visit https://sourceforge.net/projects/tplockbox/

## How to use
```
In the test project (FPCRSA/test/fpcrsatest.lpr) for Lazarus you will find an example of use.
Add package FPCRSA/lib/fpcrsalib.lpk in you project
    (read https://wiki.freepascal.org/Lazarus_Packages#Use_your_package_in_your_project)
Or add FPCRSA/source/ as source directory

Uses ..., LbRSA, LbAsym, LbRandom;
...
var LbRSA1: TLbRSA;
sEncoded, sDecoded: string;
...
LbRSA1 := TLbRSA.Create(nil, 'RSA key name', aks2048); //create a key object with a length of 2048 bits
//You can use aks128, aks256, aks512, aks768, aks1024, aks2048, aks3072.
LbRSA1.GenerateKeyPair; //Now we have unique keys, private and public part

//You can use the constructor TLbRSA.LoadFromStream(aStream: TStream) to fill in an already stored key pair
//To save the keys, use PackToStream(aStream: TStream) procedure

sEncoded := LbRSA1.EncryptString('my secret string');
// sEncoded is now encoded using the public key from LbRSA1
sDecoded := LbRSA1.DecryptString(sEncoded);
// sDecoded is now decoded using a private key and is again equal to 'my secret string'

//The exponent and the Module of both keys can be obtained as a string, for example
ModOfPrivatekey := LbRSA1.PrivateKey.ModulusAsString;
```

