unit utils;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

procedure log(msg:string;level:byte=0);

var
  debug:boolean=false;

implementation

procedure log(msg:string;level:byte=0);
begin
if (level=0) and (debug=false) then exit;
writeln(msg);
end;

end.

