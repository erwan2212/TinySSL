program tinySSL;

//openssl here https://indy.fulgan.com/SSL/
//format here : https://cppsecrets.com/users/38911097109971109810497110115971081051149710611010510864103109971051084699111109/OpenSSL-Converting-Certificate-Formats.php

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
  filename,encrypted,key,algo,password,privatekey,cert,cn,alt:string;
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
    writeln('https://github.com/erwan2212');
    writeln('Usage: tinySSL --help');
    exit;
  end;

  cmd := TCommandLineReader.create;
  cmd.declareString('cn', 'cn');
  cmd.declareString('alt', 'alternate name');
  cmd.declareString('ca', 'true|false','false');
  cmd.declareString('password', 'password');
  cmd.declareString('privatekey', 'path to a privatekey file');
  //cmd.declareString('publickey', 'path to a publickey file, not needed if you have the privatekey');
  cmd.declareString('cert', 'path to a certificate');
  //cmd.declareString('input', 'something to be hashed');
  cmd.declareString('algo', 'md4 md5 sha sha1 sha224 sha256 sha284 sha512 ripemd160 / des_ecb des_cbc des_ede3_ecb des_ede3_cbc rc2_ecb rc4 aes_128_ecb aes_192_ecb aes_256_ecb');
  cmd.declareString('key', 'optional, used by crypt/encrypt');
  cmd.declareString('debug', 'true|false','false');
  cmd.declareString('filename', 'local filename');

  //
  cmd.declareflag('print_cert', 'print cert details from cert');
  cmd.declareflag('print_private', 'print cert details from privatekey');

  cmd.declareflag('genkey', 'generate rsa keys public.pem and private.pem');
  cmd.declareflag('hash', 'hash password, using algo');
  cmd.declareflag('decrypt', 'crypt password (hexa), using algo and optional key');
  cmd.declareflag('encrypt', 'crypt password, using algo and optional key');

  cmd.declareflag('encrypt_pub', 'encrypt a file using public.pem, read from filename');
  cmd.declareflag('decrypt_priv', 'decrypt a file using private.pem, read from filename');

  cmd.declareflag('mkcert', 'make a self sign root cert, read from privatekey (option) & write to filename.crt and filename.key');
  cmd.declareflag('mkreq', 'make a certificate service request, read from privatekey & write to filename.csr filename.key (if privatekey not specified)');
  cmd.declareflag('signreq', 'make a certificate from a csr, read from filename and cert, write to filename.crt');
  //cmd.declareflag('selfsign', 'make a self sign cert, write to cert.crt cert.key');

  cmd.declareflag('set_password', 'set password from a private key,read from privatekey and password (optional) - if no password, will remove the existing password ');

  cmd.declareflag('dertopem', 'convert a binary/der private key or cert to base 64 pem format, read from cert or privatekey, write to cert.crt or privatekey.key ');
  cmd.declareflag('pemtoder', 'convert a base 64 pem format to binary/der private key or cert, read from cert or privatekey, write to cert.der or privatekey.der ');
  cmd.declareflag('p12topem', 'convert a pfx to pem, read from cert, write to cert.crt and cert.key');
  cmd.declareflag('pemtop12', 'convert a pem to pfx, read from cert and privatekey, write to cert.pfx');
  cmd.declareflag('p7topem', 'convert a p7b to pem, read from cert, write to cert.crt');
  cmd.declareflag('pemtop7', 'convert a pem to p7b, read from cert, write to cert.p7b');
  //
  cmd.parse(cmdline);

  debug:= cmd.readString('debug')='true';

  if cmd.existsProperty('decrypt')=true then
  begin
    LoadSSL;
    algo:=cmd.readString('algo');
    password:=cmd.readString('password');
    key:=cmd.readString('key');
    if crypt(algo,password,key,0)=true then writeln('ok') else writeln('not ok');
    freessl;
    exit;
  end;

  if cmd.existsProperty('encrypt')=true then
  begin
    LoadSSL;
    algo:=cmd.readString('algo');
    password:=cmd.readString('password');
    key:=cmd.readString('key');
    if crypt(algo,password,key,1)=true then writeln('ok') else writeln('not ok');
    freessl;
    exit;
  end;

  if cmd.existsProperty('hash')=true then
  begin
    LoadSSL;
    algo:=cmd.readString('algo');
    password:=cmd.readString('password');
    if hash(algo,password)=true then writeln('ok') else writeln('not ok');
    freessl;
    exit;
  end;

  if cmd.existsProperty('set_password')=true then
  begin
    LoadSSL;
    privatekey:=cmd.readString('privatekey');
    password:=cmd.readString('password');
    if set_password(privatekey,password)=true then writeln('ok') else writeln('not ok');
    freessl;
    exit;
  end;

  if cmd.existsProperty('encrypt_pub')=true then
  begin
    LoadSSL;
    filename:=cmd.readString('filename');
    hfile_ := CreateFile(pchar(filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
    if hfile_=thandle(-1) then begin log('invalid handle',1);exit;end;
    ReadFile (hfile_,mem_[0],sizeof(mem_),size_,nil);
    if size_>0 then Encrypt_Pub (strpas(@mem_[0]),encrypted);
    writeln(encrypted);
    closehandle(hfile_);
    freessl;
    exit;
  end;

  if cmd.existsProperty('decrypt_priv')=true then
  begin
    LoadSSL;
    filename:=cmd.readString('filename');
    hfile_ := CreateFile(pchar(filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
    if hfile_=thandle(-1) then begin log('invalid handle',1);exit;end;
    ReadFile (hfile_,mem_[0],sizeof(mem_),size_,nil);
    if size_>0 then Decrypt_Priv(strpas(@mem_[0]));
    closehandle(hfile_);
    freessl;
    exit;
  end;

  if cmd.existsProperty('genkey')=true then
    begin
    try
    LoadSSL;
    if generate_rsa_key_2 =true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('pemtop7')=true then
    begin
    try
    LoadSSL;
    //in
    cert:=cmd.readString('cert');
    if cert='' then filename:='cert.crt';
    //
    if PEM2P7B  (cert)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('p7topem')=true then
    begin
    try
    LoadSSL;
    //in
    cert:=cmd.readString('cert');
    if cert='' then cert:='cert.p7b';
    //
    if P7b2PEM (cert)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('pemtoder')=true then
      begin
      try
      LoadSSL;
      //in
      cert:=cmd.readString('cert');
      privatekey:=cmd.readString('privatekey') ;
      //
      if privatekey <>'' then
         if PVTPEM2DER (privatekey)=true then writeln('ok') else writeln('not ok');
      if cert <>'' then
         if X509PEM2DER (cert)=true then writeln('ok') else writeln('not ok');
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

  if cmd.existsProperty('p12topem')=true then
    begin
    try
    LoadSSL;
    //in
    cert:=cmd.readString('cert');
    if cert='' then cert:='cert.pfx';
    //
    if PFX2PEM (cert,cmd.readString('password'))=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('pemtop12')=true then
    begin
    try
    LoadSSL;
    //in
    cert:=cmd.readString('cert') ;
    if cert='' then cert:='cert.crt';
    privatekey:=cmd.readString('privatekey') ;
    if privatekey='' then privatekey:=changefileext(cert,'.key');
    //
    if PEM2PFX (cmd.readString('password'),privatekey,cert)=true then writeln('ok') else writeln('not ok');
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
    //in
    cn:=cmd.readString('cn') ;
    if cn='' then cn:='localhost';
    privatekey:=cmd.readString('privatekey') ;
    //out
    filename:=cmd.readString('filename');
    if filename='' then filename:='request.csr';
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
    filename:=cmd.readString('filename');
    if filename='' then filename:='request.csr';
    cert:=cmd.readString('cert');
    if cert='' then cert:='ca.crt';
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
    cert:=cmd.readString('cert');
    if cert='' then exit;
    if print_cert(cert)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

    if cmd.existsProperty('print_private')=true then
    begin
    try
    LoadSSL;
    privatekey:=cmd.readString('privatekey');
    if privatekey='' then exit;
    password:=cmd.readString('password') ;
    if print_private(privatekey,password)=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;



end.


