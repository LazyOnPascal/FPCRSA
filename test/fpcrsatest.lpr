program fpcrsatest;

{$mode objfpc}{$H+}

uses
  Interfaces, Forms, GuiTestRunner, fpcrsatest1;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

