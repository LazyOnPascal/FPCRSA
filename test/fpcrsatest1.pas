unit fpcrsatest1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fpcunit, testregistry, LbRSA, LbAsym;

type

  { TTestCaseRSA }

  TTestCaseRSA = class(TTestCase)
  private
    procedure TestEncodeDecode(aKey: TLbRSA; aStringLength: integer);
    procedure TestStringsEncodeDecode(aKey: TLbRSA);
    procedure TestCreateKey(aKeySize: TLbAsymKeySize);
  published
    procedure TestKey128;
    procedure TestKey256;
    procedure TestKey512;
    procedure TestKey768;
    procedure TestKey1024;
    procedure TestKey2048;
    procedure TestKey3072;

  end;

implementation

uses
   LbRandom, RSAFunc;

procedure TTestCaseRSA.TestKey128;
begin
  //Writeln('Start at : ', FormatDateTime('c', Now));
  self.TestCreateKey(aks128);
end;

procedure TTestCaseRSA.TestKey256;
begin
  self.TestCreateKey(aks256);
end;

procedure TTestCaseRSA.TestKey512;
begin
  self.TestCreateKey(aks512);
end;

procedure TTestCaseRSA.TestKey768;
begin
  self.TestCreateKey(aks768);
end;

procedure TTestCaseRSA.TestKey1024;
begin
  self.TestCreateKey(aks1024);
end;

procedure TTestCaseRSA.TestKey2048;
begin
  self.TestCreateKey(aks2048);
end;

procedure TTestCaseRSA.TestKey3072;
begin
  self.TestCreateKey(aks3072);
end;

procedure TTestCaseRSA.TestEncodeDecode(aKey: TLbRSA; aStringLength: integer);
var
  sRand, sEncoded, sDecoded: string;
  startTime: TDateTime;
begin
  sRand := RandomString(aStringLength);

  startTime := Now;
  sEncoded := aKey.EncryptString(sRand);
  Writeln('String(' + sRand +') encrypted by ' +
    GetRSALengthAsString(aKey.KeySize) + 'bit key in ',
    FormatDateTime('nn:ss:zzzz', (Now - startTime)), ' sec');

  startTime := Now;
  sDecoded := aKey.DecryptString(sEncoded);
  AssertEquals(sRand, sDecoded);
  Writeln('Decrypted  in ',
    FormatDateTime('nn:ss:zzzz', (Now - startTime)), ' sec');
  Writeln('-------------');
end;

procedure TTestCaseRSA.TestStringsEncodeDecode(aKey: TLbRSA);
begin
  self.TestEncodeDecode(aKey, 8);
  //self.TestEncodeDecode(aKey, 32);
  //self.TestEncodeDecode(aKey, 128);
  //self.TestEncodeDecode(aKey, 256);
  //self.TestEncodeDecode(aKey, 1024);
  //self.TestEncodeDecode(aKey, 2048);
end;

procedure TTestCaseRSA.TestCreateKey(aKeySize: TLbAsymKeySize);
var
  LbRSA1: TLbRSA;
  startTime: TDateTime;
begin
  //Writeln('Start at : ', FormatDateTime('c', Now));
  Writeln('Start generate '+GetRSALengthAsString(aKeySize)+
                 ' bits key....' );
  startTime := Now;

  LbRSA1 := TLbRSA.Create(nil, 'key '+GetRSALengthAsString(aKeySize)+' bits', aKeySize);
  LbRSA1.GenerateKeyPair;

  Writeln('Done for  ',
    FormatDateTime('nn:ss:zzzz', (Now - startTime)));
  self.TestStringsEncodeDecode(LbRSA1);

  LbRSA1.Free;
end;



initialization

  RegisterTest(TTestCaseRSA);


end.

