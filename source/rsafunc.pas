unit RSAFunc;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, LbRSA, LbAsym;

{ new public procedures }
function GetRSALengthAsString(aKeySize: TLbAsymKeySize): string;
function GetRSAHash(aRSA: TLbRSA): string;
function GetRSAFullName(aRSA: TLbRSA): string;
function GetRSAShortHashWithBits(aRSA: TLbRSA): string;


implementation

uses
  DCPsha256;

function GetRSAShortHashWithBits(aRSA: TLbRSA): string;
var
  tempString: string;
begin
  tempString := GetRSAHash(aRSA);
  Result := copy(tempString, 0, 4) + ' ' + copy(tempString, 5, 4) +
    ' (' + GetRSALengthAsString(aRSA.KeySize) + ' bits)';
end;

function GetRSALengthAsString(aKeySize: TLbAsymKeySize): string;
begin

  case aKeySize of
    aks128:
    begin
      Result := '128';
    end;
    aks256:
    begin
      Result := '256';
    end;
    aks512:
    begin
      Result := '512';
    end;
    aks768:
    begin
      Result := '768';
    end;
    aks1024:
    begin
      Result := '1024';
    end;
    aks2048:
    begin
      Result := '2048';
    end;
    aks3072:
    begin
      Result := '3072';
    end;
    else
    begin
      Result := '?????';
    end;
  end;

end;

function GetRSAFullName(aRSA: TLbRSA): string;
begin
  Result := GetRSAShortHashWithBits(aRSA) + ' - ' + aRSA.Name;
end;

function GetRSAHash(aRSA: TLbRSA): string;
var
  hash: TDCP_sha256;
  buf: array of byte;
  hashString: string;
  i: integer;
begin
  hashString := '';//avoid warnings
  buf := nil;

  hash := TDCP_sha256.Create(nil);
  SetLength(buf,hash.GetHashSize div 8);

  hash.Init;
  Randomize;
  hashString := aRSA.PrivateKey.ExponentAsString +
    aRSA.PrivateKey.ModulusAsString +
    aRSA.PublicKey.ExponentAsString +
    aRSA.PublicKey.ModulusAsString;

  hash.UpdateStr(hashString);
  hash.Final(buf[0]);
  Result := '';
  for i := 0 to 31 do
  begin
    Result += HexStr(buf[i], 2);
  end;

  hash.Free;
end;

end.

