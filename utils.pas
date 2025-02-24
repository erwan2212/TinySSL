unit utils;

{$mode objfpc}{$H+}

interface

uses
  windows,Classes, SysUtils;

procedure log(msg:string;level:byte=0);

function HexaStringToByte2(hash:string):tbytes;
function AnsiStringtoByte(input:string;unicode:boolean=false):tbytes;

function ByteToHexaString(hash:pbyte;len:dword):string;overload;
function ByteToHexaString(hash:array of byte):string;

var
  debug:boolean=false;

implementation

procedure log(msg:string;level:byte=0);
begin
if (level=0) and (debug=false) then exit;
writeln(msg);
end;

function ByteToHexaString(hash:pbyte;len:dword):string;overload;
var
  tmp:tbytes;
begin
SetLength(tmp,len);
ZeroMemory(@tmp[0],len);
CopyMemory(@tmp[0],hash,len) ;
result:=ByteToHexaString(tmp);
end;

//function HashByteToString(hash:tbyte16):string;
function ByteToHexaString(hash:array of byte):string;
var
  i:dword;
  dummy:string{$ifdef fpc}=''{$endif fpc};
begin
log('**** ByteToHexaString ****');
log('sizeof:'+inttostr(sizeof(hash)));
//setlength(dummy,sizeof(hash)*2);
try
//writeln('sizeof(hash):'+inttostr(sizeof(hash)));
//writeln('length(hash):'+inttostr(length(hash)));
  for i:=0 to sizeof(hash)-1 do  dummy:=dummy+inttohex(hash[i],2);
  result:=dummy;
except
on e:exception do log('ByteToHexaString:'+e.Message );
end;
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

function AnsiStringtoByte(input:string;unicode:boolean=false):tbytes;
var
  i:dword;
  ws:widestring;
begin
log('**** AnsiStringtoByte ****');
//input:=stringreplace(input,'\0',#0,[]);
//log('input:->'+input+'<-');
log('length:'+inttostr(length(input)));
try
if unicode=false then
begin
setlength(result,length(input));
//log('AnsiStringtoByte len:'+inttostr(length(input)));
//for i:=1 to length(input) do result[i-1]:=ord(input[i]);
//or quicker?
copymemory(@result[0],@input[1],length(input));
end;

if unicode=true then
begin
setlength(result,length(input)*2);
//log('AnsiStringtoByte len:'+inttostr(length(input)));
//for i:=1 to length(input)  do result[(i-1)*2]:=ord(input[i]);
//or quicker?
ws:=widestring(input);
copymemory(@result[0],@ws[1],length(result));
end;

//for i:=0 to length(result)-1 do write(inttohex(result[i],2));
//writeln;

except
on e:exception do log('AnsiStringtoByte:'+e.Message );
end;
end;

end.

