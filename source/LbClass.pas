(* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is TurboPower LockBox
 *
 * The Initial Developer of the Original Code is
 * TurboPower Software
 *
 * Portions created by the Initial Developer are Copyright (C) 1997-2002
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * ***** END LICENSE BLOCK ***** *)
{*********************************************************}
{*                   LBCLASS.PAS 2.07                    *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}

{$H+}  {turn on huge strings}

unit LbClass;

{$MODE Delphi}

  {-LockBox components and classes }

interface

uses
{$IFDEF MSWINDOWS}
  Windows,
{$ENDIF}
  Classes,
  SysUtils,
  LbCipher;



{ TLbBaseComponent }
type
  TLBBaseComponent = class(TLBBase)
  protected {private}
    function GetVersion : string;
    procedure SetVersion(const Value : string);
  published {properties}
    property Version : string
      read GetVersion write SetVersion stored False;
  end;


{ TLbCipher }
type
  TLbCipherMode = (cmECB, cmCBC);

  TLbCipher = class(TLbBaseComponent)
  public {methods}
    constructor Create(AOwner : TComponent); override;
    destructor Destroy; override;

    function DecryptBuffer(const InBuf; InBufSize : Cardinal; var OutBuf) : Cardinal;
    function EncryptBuffer(const InBuf; InBufSize : Cardinal; var OutBuf) : Cardinal;

    procedure DecryptFile(const InFile, OutFile : string); virtual; abstract;
    procedure DecryptStream(InStream , OutStream : TStream); virtual; abstract;
    function  DecryptString(const InString : string) : string; virtual; abstract;

    procedure EncryptFile(const InFile, OutFile : string); virtual; abstract;
    procedure EncryptStream(InStream, OutStream : TStream); virtual; abstract;
    function  EncryptString(const InString : string) : string; virtual; abstract;

    function OutBufSizeNeeded(InBufSize : Cardinal) : Cardinal; virtual; abstract;
  end;


{ TLbSymmetricCipher }
type
  TLbSymmetricCipher = class(TLbCipher)
  protected {private}
    FCipherMode : TLbCipherMode;
  public {methods}
    constructor Create(AOwner : TComponent); override;
    destructor Destroy; override;

    procedure GenerateKey(const Passphrase : string); virtual; abstract;
    procedure GenerateRandomKey; virtual; abstract;
  public {properties}
    property CipherMode : TLbCipherMode
               read FCipherMode write FCipherMode;
  end;




{ TLbHash }
type
  TLbHash = class(TLbBaseComponent)
    protected {private}
      FBuf : array[0..1023] of Byte;
    public {methods}
      constructor Create(AOwner : TComponent); override;
      destructor Destroy; override;
      procedure HashBuffer(const Buf; BufSize : Cardinal); virtual; abstract;
      procedure HashFile(const AFileName : string); virtual; abstract;
      procedure HashStream(AStream: TStream); virtual; abstract;
      procedure HashString(const AStr : string); virtual; abstract;
    end;





implementation

uses
  LbProc, LbString, LbConst;



{ == TLbBaseComponent ====================================================== }
function TLBBaseComponent.GetVersion : string;
begin
  Result := sLbVersion;
end;
{ -------------------------------------------------------------------------- }
procedure TLBBaseComponent.SetVersion(const Value : string);
begin
  { nop }
end;


{ == TLbCipher ============================================================= }
constructor TLbCipher.Create(AOwner : TComponent);
begin
  inherited Create(AOwner);
end;
{ -------------------------------------------------------------------------- }
destructor TLbCipher.Destroy;
begin
  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
function TLbCipher.DecryptBuffer(const InBuf; InBufSize : Cardinal; var OutBuf) : Cardinal;
var
  InS, OutS : TMemoryStream;
begin
  InS := TMemoryStream.Create;
  OutS := TMemoryStream.Create;
  try
    InS.SetSize(InBufSize);
    InS.Write(InBuf, InBufSize);
    InS.Position := 0;
    DecryptStream(InS, OutS);
    OutS.Position := 0;
    OutS.Read(OutBuf, OutS.Size);
    Result := OutS.Size;
  finally
    InS.Free;
    OutS.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
function TLbCipher.EncryptBuffer(const InBuf; InBufSize : Cardinal; var OutBuf) : Cardinal;
var
  InS, OutS : TMemoryStream;
begin
  InS := TMemoryStream.Create;
  OutS := TMemoryStream.Create;
  try
    InS.SetSize(InBufSize);
    InS.Write(InBuf, InBufSize);
    InS.Position := 0;
    EncryptStream(InS, OutS);
    OutS.Position := 0;
    OutS.Read(OutBuf, OutS.Size);
    Result := OutS.Size;
  finally
    InS.Free;
    OutS.Free;
  end;
end;


{ == TLbSymmetricCipher ==================================================== }
constructor TLbSymmetricCipher.Create(AOwner : TComponent);
begin
  inherited Create(AOwner);
end;
{ -------------------------------------------------------------------------- }
destructor TLbSymmetricCipher.Destroy;
begin
  inherited Destroy;
end;


{ == TLbHash =============================================================== }
constructor TLbHash.Create(AOwner : TComponent);
begin
  inherited Create(AOwner);
end;
{ -------------------------------------------------------------------------- }
destructor TLbHash.Destroy;
begin
  inherited Destroy;
end;

end.
