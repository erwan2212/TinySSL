program tinySSL;

//openssl here https://indy.fulgan.com/SSL/

{$mode objfpc}{$H+}
{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  windows,sysutils,classes,
  libeay32,
  rcmdline in '..\rcmdline-master\rcmdline.pas',
  opensslutils,
  utils;

//https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc
type
  BLOBHEADER=record
    bType:BYTE;
    bVersion:BYTE;
    Reserved:WORD;
    aiKeyAlg:DWORD;
end;

//https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey
RSAPUBKEY=record
    magic:DWORD;
    bitlen:DWORD;
    pubexp:DWORD;
end;
PRSAPUBKEY=^RSAPUBKEY;
{
BYTE            modulus[rsapubkey.bitlen/8];
BYTE            prime1[rsapubkey.bitlen/16];
BYTE            prime2[rsapubkey.bitlen/16];
BYTE            exponent1[rsapubkey.bitlen/16];
BYTE            exponent2[rsapubkey.bitlen/16];
BYTE            coefficient[rsapubkey.bitlen/16];
BYTE            privateExponent[rsapubkey.bitlen/8];
}

var
  cmd: TCommandLineReader;
  filename,encrypted,password,privatekey,publickey,cert,cn,alt:string;
  ca:boolean=false;
  hfile_:thandle=thandle(-1);
  mem_:array[0..8192-1] of char;
  size_:dword=0;

//load a decrypted rsa key, no header
procedure loadrsa(filename:string);
var
    buffer:array[0..8192-1] of byte;
    temp:array of byte;
    pos,size,c:word;
begin
    hfile_ := CreateFile(pchar(filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
    if hfile_=thandle(-1) then begin log('invalid handle',1);exit;end;
    ReadFile (hfile_,buffer[0],sizeof(buffer),size_,nil);
    if size_>0 then
       begin
       writeln(inttohex(PRSAPUBKEY(@buffer[0])^.magic ,8));
       writeln(PRSAPUBKEY(@buffer[0])^.bitlen  );
       writeln(PRSAPUBKEY(@buffer[0])^.pubexp   );
       //modulus
       pos:=sizeof(RSAPUBKEY);
       size:=PRSAPUBKEY(@buffer[0])^.bitlen div 8;
       SetLength(temp,size);
       copymemory(@temp[0],@buffer[pos],size);
       for c:=0 to size -1 do write(inttohex(temp[c],2));
       writeln;
       //prime1
       pos:=pos+size;
       size:=PRSAPUBKEY(@buffer[0])^.bitlen div 16;
       SetLength(temp,size);
       copymemory(@temp[0],@buffer[pos],size);
       for c:=0 to size -1 do write(inttohex(temp[c],2));
       writeln;
       //prime2
       pos:=pos+size;
       size:=PRSAPUBKEY(@buffer[0])^.bitlen div 16;
       SetLength(temp,size);
       copymemory(@temp[0],@buffer[pos],size);
       for c:=0 to size -1 do write(inttohex(temp[c],2));
       writeln;
       //
       end;
    closehandle(hfile_);
end;

begin
  //loadrsa('decoded.bin');
  //exit;
  debug:=true;

  if paramcount=0 then
  begin
    writeln('Usage: tinySSL --help');
    exit;
  end;

  cmd := TCommandLineReader.create;
  //cmd.declareString('username', 'mandatory');
  cmd.declareString('cn', 'cn');
  cmd.declareString('alt', 'alternate name');
  cmd.declareString('ca', 'true|false','false');
  cmd.declareString('password', 'password');
  cmd.declareString('privatekey', 'path to a privatekey file');
  cmd.declareString('publickey', 'path to a publickey file, not needed if you have the privatekey');
  cmd.declareString('cert', 'path to a certificate');
  cmd.declareString('debug', 'true|false','false');

  cmd.declareString('filename', 'local filename');

  //
  cmd.declareflag('print_cert', 'print cert details');
  cmd.declareflag('print_private', 'print cert details');

  cmd.declareflag('genkey', 'generate rsa keys public.pem and private.pem');

  cmd.declareflag('encrypt', 'encrypt a file using public.pem, read from filename');
  cmd.declareflag('decrypt', 'decrypt a file using private.pem, read from filename');

  cmd.declareflag('mkcert', 'make a self sign root cert, read from privatekey (option) & write to filename.crt and filename.key');
  cmd.declareflag('mkreq', 'make a certificate service request, read from privatekey & write to filename.csr filename.key (if privatekey not specified)');
  cmd.declareflag('signreq', 'make a certificate from a csr, read from filename and cert, write to filename.crt');
  //cmd.declareflag('selfsign', 'make a self sign cert, write to cert.crt cert.key');

  cmd.declareflag('dertopem', 'convert a binary/der private key or cert to base 64 pem format, read from cert or privatekey, write to cert.crt or privatekey.key ');
  cmd.declareflag('p12topem', 'convert a pfx to pem, read from filename, write to filename.crt and filename.key');
  cmd.declareflag('pemtop12', 'convert a pem to pfx, read from cert and privatekey, write to filename');
  //
  cmd.parse(cmdline);

  debug:= cmd.readString('debug')='true';

  if cmd.existsProperty('encrypt')=true then
  begin
    LoadSSL;
    filename:=cmd.readString('filename');
    hfile_ := CreateFile(pchar(filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
    if hfile_=thandle(-1) then begin log('invalid handle',1);exit;end;
    ReadFile (hfile_,mem_[0],sizeof(mem_),size_,nil);
    if size_>0 then EncryptPub (strpas(@mem_[0]),encrypted);
    writeln(encrypted);
    closehandle(hfile_);
    freessl;
    exit;
  end;

  if cmd.existsProperty('decrypt')=true then
  begin
    LoadSSL;
    filename:=cmd.readString('filename');
    hfile_ := CreateFile(pchar(filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
    if hfile_=thandle(-1) then begin log('invalid handle',1);exit;end;
    ReadFile (hfile_,mem_[0],sizeof(mem_),size_,nil);
    if size_>0 then DecryptPriv(strpas(@mem_[0]));
    closehandle(hfile_);
    freessl;
    exit;
  end;

  if cmd.existsProperty('genkey')=true then
    begin
    try
    LoadSSL;
    if generate_rsa_key=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('p12topem')=true then
    begin
    try
    LoadSSL;
    //in
    filename:=cmd.readString('filename');
    if filename='' then filename:='cert.pfx';
    //
    if PFX2PEM (filename,cmd.readString('password'))=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('dertopem')=true then
    begin
    try
    LoadSSL;
    //in
    cert:=cmd.readString('cert');
    privatekey:=cmd.readString('privatekey') ;
    //
    if privatekey <>'' then
       if PVTDER2PEM (privatekey)=true then writeln('ok') else writeln('not ok');
    if cert <>'' then
       if X509DER2PEM (cert)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('pemtop12')=true then
    begin
    try
    LoadSSL;
    //out
    filename:=cmd.readString('filename');
    if filename='' then filename:='cert.pfx';
    //in
    cert:=cmd.readString('cert') ;
    if cert='' then cert:='cert.crt';
    privatekey:=cmd.readString('privatekey') ;
    if privatekey='' then privatekey:=changefileext(cert,'.key');
    //
    if PEM2PFX (filename,cmd.readString('password'),privatekey,cert)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('mkcert')=true then
    begin
    try
    LoadSSL;
    //out
    filename:=cmd.readString('filename');
    if filename='' then filename:='ca.crt';
    //in
    privatekey:=cmd.readString('privatekey') ;
    password:=cmd.readString('password') ;
    cn:=cmd.readString('cn') ;
    if cn='' then cn:='_Root Authority_';
    ca:=cmd.readString('ca')='true';
    //
    if mkcert(filename,cn,privatekey,password,'',ca)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('mkreq')=true then
    begin
    try
    LoadSSL;
    cn:=cmd.readString('cn') ;
    if cn='' then cn:='localhost';
    filename:=cmd.readString('filename');
    if filename='' then filename:='request.csr';
    privatekey:=cmd.readString('privatekey') ;
    //if privatekey='' then privatekey:='request.key';
    if mkreq(cn,privatekey,filename)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('signreq')=true then
    begin
    try
    LoadSSL;
    //in
    cert:=cmd.readString('cert');
    if cert='' then cert:='ca.crt';
    filename:=cmd.readString('filename');
    if filename='' then filename:='request.csr';
    password:=cmd.readString('password') ;
    alt:=cmd.readString('alt') ;
    ca:=cmd.readString('ca')='true';
    if signreq(filename,cert,password,alt,ca)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  {
    if cmd.existsProperty('selfsign')=true then
    begin
    try
    LoadSSL;
    filename:=cmd.readString('filename');
    if filename='' then filename:='signed.crt';
    cn:=cmd.readString('cn') ;
    if cn='' then cn:='localhost';
    if selfsign(filename,cn)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;
    }

    if cmd.existsProperty('print_cert')=true then
    begin
    try
    LoadSSL;
    filename:=cmd.readString('filename');
    if filename='' then exit;
    if print_cert(filename)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

    if cmd.existsProperty('print_private')=true then
    begin
    try
    LoadSSL;
    filename:=cmd.readString('filename');
    if filename='' then exit;
    password:=cmd.readString('password') ;
    if print_private(filename,password)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;



end.


