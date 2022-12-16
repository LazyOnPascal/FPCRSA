unit KeyList;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, LbRSA, LbAsym, DCPsha256, DCPrijndael;

const
  DATABASEVERSION = 1;

type

  { TConnectionList }

  { TKeysList }

  TKeysList = class(TFPList)
  private
    function Get(Index: integer): TLbRSA;
  public
    constructor Create();
    destructor Destroy; override;

    function Add(aRSA: TLbRSA): integer;
    function CreateKey(aName: string; aKeySize: TLbAsymKeySize): integer;
    procedure DeleteAndFree(Index: integer);

    function SaveAllKeysToStream(aDest: TStream; aEncription: boolean;
      aPassword: string; aIncludePrivatePart: boolean): boolean;
    function LoadAllKeysFromStream(aSource: TStream; aEncription: boolean;
      aPassword: string): boolean;
    function SaveAllKeysToFile(aPath: string; aEncription: boolean;
      aPassword: string; aIncludePrivatePart: boolean): boolean;
    function LoadAllKeysFromFile(aPath: string; aEncription: boolean;
      aPassword: string): boolean;

    property Items[Index: integer]: TLbRSA read Get; default;
  end;

implementation

uses
  RSAFunc;



{ TKeysList }

function TKeysList.Get(Index: integer): TLbRSA;
begin
  Result := TLbRSA(inherited get(Index));
end;

constructor TKeysList.Create();
begin
  Randomize;
end;

destructor TKeysList.Destroy;
var
  i: integer;
begin
  for i := 0 to Self.Count - 1 do
  begin
    Items[i].Free;
  end;
  inherited Destroy;
end;

function TKeysList.Add(aRSA: TLbRSA): integer;
begin
  Result := inherited Add(aRSA);
end;

function TKeysList.CreateKey(aName: string; aKeySize: TLbAsymKeySize): integer;
var
  LbRSA1: TLbRSA;
begin
  LbRSA1 := TLbRSA.Create(nil, aName, TLbAsymKeySize(aKeySize));
  LbRSA1.GenerateKeyPair;
  Exit(inherited Add(LbRSA1));
end;

procedure TKeysList.DeleteAndFree(Index: integer);
begin
  Items[Index].Free;
  inherited Delete(Index);
end;

function TKeysList.SaveAllKeysToStream(aDest: TStream; aEncription: boolean;
  aPassword: string; aIncludePrivatePart: boolean): boolean;
var
  Cipher: TDCP_rijndael;
  Source: TMemoryStream;
  i: integer;
  tempRSA: TLbRSA;
begin
  //wtite in stream version not encripted
  aDest.WriteByte(DATABASEVERSION);
  if aEncription then aDest.WriteByte(1)
  else
    aDest.WriteByte(0);

  Source := TMemoryStream.Create;
  //write the number of keys
  Source.WriteDWord(self.Count);
  //write each key
  for i := 0 to Self.Count - 1 do
  begin
    tempRSA := Items[i];
    Source.WriteByte(Ord(tempRSA.KeySize));
    Source.WriteAnsiString(tempRSA.Name);
    Source.WriteAnsiString(tempRSA.PublicKey.ModulusAsString);
    Source.WriteAnsiString(tempRSA.PublicKey.ExponentAsString);
    if aIncludePrivatePart then
      Source.WriteAnsiString(tempRSA.PrivateKey.ExponentAsString)
    else
      Source.WriteAnsiString('');
  end;
  Source.Position := 0;

  if aEncription then  //if need - encript
  begin
    try
      try
        Cipher := TDCP_rijndael.Create(nil);
        Cipher.InitStr(aPassword, TDCP_sha256);
        Cipher.EncryptStream(Source, aDest, Source.Size);
        Cipher.Burn;
      finally
        Cipher.Free;
      end;
      Result := True;
    except
      Source.Free;
      exit(False);
    end;
  end
  else
  begin //or just copy
    aDest.CopyFrom(Source, Source.Size);
    Result := True;
  end;
  Source.Free;
end;

function TKeysList.LoadAllKeysFromStream(aSource: TStream; aEncription: boolean;
  aPassword: string): boolean;
var
  Cipher: TDCP_rijndael;
  Dest: TMemoryStream;
  KeysInFile, i: cardinal;
  newRSA: TLbRSA;
begin
  //check the version of base
  if not (aSource.ReadByte = DATABASEVERSION) then
  begin
    exit(False);
  end;
  if aEncription then
  begin
    if not (aSource.ReadByte = 1) then //base encripted, but no pass
    begin
      exit(False);
    end;
    //decrypt stream
    try
      try
        Dest := TMemoryStream.Create;
        Cipher := TDCP_rijndael.Create(nil);
        Cipher.InitStr(aPassword, TDCP_sha256);
        Cipher.DecryptStream(aSource, Dest, aSource.Size);
        Cipher.Burn;
      finally
        Cipher.Free;
      end;
    except
      Dest.Free;
      exit(False);
    end;
  end
  else
  begin
    //or just copy
    if not (aSource.ReadByte = 0) then //base not ecripted, but pass set
    begin
      exit(False);
    end;
    Dest.CopyFrom(aSource, aSource.Size);
  end;

  Dest.Position := 0;
  KeysInFile := Dest.ReadDWord;
  for i := 1 to KeysInFile do
  begin
    newRSA := TLbRSA.Create(nil, '0', aks128);
    newRSA.KeySize := TLbAsymKeySize(Dest.ReadByte);
    newRSA.Name := Dest.ReadAnsiString;
    newRSA.PublicKey.ModulusAsString := Dest.ReadAnsiString;
    newRSA.PublicKey.ExponentAsString := Dest.ReadAnsiString;
    newRSA.PrivateKey.ExponentAsString := Dest.ReadAnsiString;

    if not (newRSA.PrivateKey.ExponentAsString = '') then
      newRSA.PrivateKey.ModulusAsString := newRSA.PublicKey.ModulusAsString;

    self.Add(newRSA);
  end;
  Dest.Free;

  Result := True;
end;

function TKeysList.SaveAllKeysToFile(aPath: string; aEncription: boolean;
  aPassword: string; aIncludePrivatePart: boolean): boolean;
var
  Dest: TFileStream;
begin
  try
    try
      Dest := TFileStream.Create(aPath, fmCreate);
      Result := SaveAllKeysToStream(Dest, aEncription, aPassword,
        aIncludePrivatePart);
    finally
      Dest.Free;
    end;
  except
    Result := False;
  end;
end;

function TKeysList.LoadAllKeysFromFile(aPath: string; aEncription: boolean;
  aPassword: string): boolean;
var
  Source: TFileStream;
begin
  try
    try
      Source := TFileStream.Create(aPath, fmOpenRead);
      Result := LoadAllKeysFromStream(Source, aEncription, aPassword);
    finally
      Source.Free;
    end;
  except
    Result := False;
  end;
end;


end.
