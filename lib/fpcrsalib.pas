{ This file was automatically created by Lazarus. Do not edit!
  This source is only used to compile and install the package.
 }

unit fpcrsalib;

{$warn 5023 off : no warning about unused units}
interface

uses
  RSAFunc, LbUtils, LbString, LbRSA, LbRandom, LbProc, LbConst, LbClass, 
  LbCipher, LbBigInt, LbAsym, LazarusPackageIntf;

implementation

procedure Register;
begin
end;

initialization
  RegisterPackage('fpcrsalib', @Register);
end.
