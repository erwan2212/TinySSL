unit utils;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

procedure log(msg:string;level:byte=0);

function HexaStringToByte2(hash:string):tbytes;

var
  debug:boolean=false;

implementation

procedure log(msg:string;level:byte=0);
begin
if (level=0) and (debug=false) then exit;
writeln(msg);
end;

function HexaStringToByte2(hash:string):tbytes;
var
  i:dword;
  tmp:string;
  b:longint;
begin
log('**** HexaStringToByte2 ****');
log('length:'+inttostr(length(hash)));
try
i:=1;
//log('hash:'+hash);
//log('length(hash) div 2:'+inttostr(length(hash) div 2));
setlength(result,length(hash) div 2);
  while I<length(hash) do
      begin
      tmp:=copy(hash,i,2);
      if TryStrToInt ('$'+tmp,b) then result[i div 2]:=b;
      //result[i div 2]:=strtoint('$'+tmp);
      inc(i,2);
      //write('.');
      end;
except
on e:exception do log('HexaStringToByte2:'+e.Message );
end;
end;

end.

