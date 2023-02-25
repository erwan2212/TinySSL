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

var
  cmd: TCommandLineReader;
  filename,encrypted,password,privatekey,publickey,cert,cn,alt:string;
  hfile_:thandle=thandle(-1);
  mem_:array[0..8192-1] of char;
  size_:dword=0;

begin
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
  cmd.declareString('password', 'password');
  cmd.declareString('privatekey', 'path to a privatekey file');
  cmd.declareString('publickey', 'path to a publickey file, not needed if you have the privatekey');
  cmd.declareString('cert', 'path to a certificate');
  cmd.declareString('debug', 'true|false','false');

  cmd.declareString('filename', 'local filename');

  //
  cmd.declareflag('genkey', 'generate rsa keys public.pem and private.pem');

  cmd.declareflag('encrypt', 'encrypt a file using public.pem');
  cmd.declareflag('decrypt', 'decrypt a file using private.pem');

  cmd.declareflag('mkcert', 'make a self sign root cert, read from privatekey (option) & write to ca.crt and ca.key');
  cmd.declareflag('mkreq', 'make a certificate service request, read from request.key (if exist) & write to request.csr request.key');
  cmd.declareflag('signreq', 'make a certificate from a csr, read from a csr filename ca.crt ca.key');
  cmd.declareflag('selfsign', 'make a self sign cert, write to cert.crt cert.key');

  cmd.declareflag('p12topem', 'convert a pfx to pem, write to cert.crt and cert.key');
  cmd.declareflag('pemtop12', 'convert a pem to pfx, read from cert.crt and cert.key');
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
    if Convert2PEM (filename,cmd.readString('password'))=true then writeln('ok') else writeln('not ok');
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
    privatekey:=cmd.readString('privatekey') ;
    if privatekey='' then privatekey:='cert.key';
    cert:=cmd.readString('cert') ;
    if cert='' then cert:='cert.crt';
    //
    if Convert2PKCS12 (filename,cmd.readString('password'),privatekey,cert)=true then writeln('ok') else writeln('not ok');
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
    //
    if mkCAcert(filename,cn,privatekey,password)=true then writeln('ok') else writeln('not ok');
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
    if privatekey='' then privatekey:='request.key';
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
    if signreq(filename,cert,password,alt)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

    if cmd.existsProperty('selfsign')=true then
    begin
    try
    LoadSSL;
    //filename:=cmd.readString('filename');
    //if filename='' then filename:='signed.crt';
    cn:=cmd.readString('cn') ;
    if selfsign(cn)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;


end.


