unit OpenSSLUtils;

{$mode objfpc}{$H+}

interface

uses
  windows, SysUtils, classes,dateutils,
  libeay32,utils,inifiles;

procedure LoadSSL;
procedure FreeSSL;
function generate_rsa_key:boolean;
function generate_rsa_key_2:boolean;
function mkcert(filename:string;cn:string;privatekey:string='';read_password:string='';serial:string='';ca:boolean=false):boolean;
function mkreq(cn:string;keyfile,csrfile:string):boolean;
function signreq(filename:string;cert:string;read_password:string='';alt:string='';ca:boolean=false):boolean;
//function selfsign(filename:string;subject:string):boolean;

function set_password(filename,password:string):boolean;

function P7B2PEM(filename:string):boolean;
function PEM2P7B(filename:string):boolean;

function PFX2PEM(filename,export_pwd:string):boolean;
function PEM2PFX(export_pwd,privatekey,cert:string):boolean;

function PVTDER2PEM(filename:string):boolean;
function PVTPEM2DER(filename:string):boolean;

function X509DER2PEM(filename:string):boolean;
function X509PEM2DER(filename:string):boolean;

function print_cert(filename:string):boolean;
function print_private(filename:string;password:string=''):boolean;

function Encrypt_Pub(sometext:string;var encrypted:string):boolean;
function Decrypt_Priv(ACryptedData:string):boolean;

function hash(algo,input:string):boolean;
function crypt(algo,input:string;keystr:string='';enc:integer=1):boolean;

function getDN(pDn: pX509_NAME): String;
function getTime(asn1_time: pASN1_TIME): TDateTime;
function getSerialNumber(x509:px509): String;

implementation

type
ReadKeyChar = AnsiChar;
//ReadKeyChar = Byte;
PReadKeyChar = ^ReadKeyChar;

//OpenSSL_add_all_algorithms() is not needed for newer OpenSSL versions and is ignored
//The same applies to OpenSSL_add_all_ciphers() and OpenSSL_add_all_digests()
//This is not entirely accurate (at least not any more). OpenSSL_add_all_algorithms is not ignored, it is simply a macro wrapping a call to OPENSSL_init_crypto, 
//see for example github.com/openssl/openssl/blob/…
procedure LoadSSL;
begin
  OpenSSL_add_all_algorithms;
  OpenSSL_add_all_ciphers;
  OpenSSL_add_all_digests;
  ERR_load_crypto_strings;
  ERR_load_RSA_strings;
end;


procedure FreeSSL;
begin
  EVP_cleanup;
  ERR_free_strings;
end;

function BIO_ReadAnsiString(bp: PBIO): AnsiString;
var Buf: AnsiString;
    a: TC_INT;
begin
  Result := '';
    SetLength(Buf, 512);
    repeat
     a := BIO_read(bp, @Buf[1], Length(Buf));
     if a > 0 then
      Result := Result + Copy(Buf, 1, a);
    until a <= 0;
  SetLength(Buf, 0);
end;

function LoadPEMFile(filePath: string): PBio;
var
{$IFNDEF MSWINDOWS}
  LEncoding: TEncoding;
  LOffset: Integer;
{$ENDIF}
  Buffer: TBytes;
  Stream: TStream;
begin
  log('LoadPEMFile');
  Stream := TFileStream.Create(filePath, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Buffer, Stream.size);
    Stream.ReadBuffer(Buffer[0], Stream.size);
{$IFNDEF MSWINDOWS}
{On traite les problèmes d'encodage de flux sur les plateformes différentes de Windows}
    LEncoding := nil;
    LOffset := TEncoding.GetBufferEncoding(Buffer, LEncoding);
    Buffer := LEncoding.Convert(LEncoding, TEncoding.UTF8, Buffer, LOffset,
      Length(Buffer) - LOffset);
{$ENDIF}
    Result := BIO_new_mem_buf(@Buffer[0], Length(Buffer));
  finally
    Stream.free;
  end;
end;

function LoadCertPublicKey(filePath: string): PEVP_PKEY;
var
  mem: PBIO;
  FX509: pX509;
  //Key: PEVP_PKEY;
  x: pX509=nil;
begin
  log('LoadCertPublicKey: '+filepath);
  //KeyBuffer := LoadPEMFile(filepath);
  //if KeyBuffer = nil then raise Exception.Create('Impossible de charger le buffer X509');

  mem := BIO_new(BIO_s_file());
  log('BIO_read_filename');
  BIO_read_filename(mem, PAnsiChar(filePath));

  try
    FX509 := PEM_read_bio_X509(mem, x, nil, nil);
    if not Assigned(FX509) then
      raise Exception.Create('PEM_read_bio_X509 failed');
    result := X509_get_pubkey(FX509);
  finally
    BIO_free(mem);
  end;
end;

function LoadPublicKey(KeyFile: string) :pEVP_PKEY ;
var
  mem: pBIO;
  k: pEVP_PKEY;
  rc:integer=0;
begin
  log('LoadPublicKey: '+KeyFile);
  k:=nil;
  mem := BIO_new(BIO_s_file()); //BIO типа файл
  log('BIO_read_filename');
  rc:=BIO_read_filename(mem, PAnsiChar(KeyFile)); // чтение файла ключа в BIO
  log(inttostr(rc));
  try
    log('PEM_read_bio_PUBKEY');
    result := PEM_read_bio_PUBKEY(mem, k, nil, nil); //преобразование BIO  в структуру pEVP_PKEY, третий параметр указан nil, означает для ключа не нужно запрашивать пароль
  finally
    BIO_free_all(mem);
  end;
end;

function LoadPrivateKey(KeyFile: string;password:string='') :pEVP_PKEY;
var
  mem: pBIO;
  k: pEVP_PKEY;
begin
  log('LoadPrivateKey: '+KeyFile);
  k := nil;
  mem := BIO_new(BIO_s_file());
  BIO_read_filename(mem, PAnsiChar(KeyFile));
  try
    log('PEM_read_bio_PrivateKey');
    if password=''
       then result := PEM_read_bio_PrivateKey(mem, k, nil, nil)
       else result := PEM_read_bio_PrivateKey(mem, k, nil, pchar(password));
  finally
    BIO_free_all(mem);
  end;
end;

{
Importer une clé publique RSA
Un fichier au format PEM contenant une clé publique RSA
commence par —–BEGIN PUBLIC KEY—–
puis est suivi de la clé en Base64
et se termine par —–END PUBLIC KEY—–.
}
function RSAOpenSSLPublicKey(filePath: string): pRSA;
var
  KeyBuffer: PBIO;
  pkey: PEVP_PKEY;
  x: pEVP_PKEY;
begin
  log('FromOpenSSLPublicKey: '+filepath);
  x:=nil;
  KeyBuffer := LoadPEMFile(filePath);
  if KeyBuffer = nil then
    raise Exception.Create('Impossible de charger le buffer');
  try
    pkey := PEM_read_bio_PUBKEY(KeyBuffer, x, nil, nil);
    if not Assigned(pkey) then
      raise Exception.Create('Impossible de charger la clé publique');
    try
      Result := EVP_PKEY_get1_RSA(pkey);
      if not Assigned(Result) then
        raise Exception.Create('Impossible de charger la clé publique RSA');
    finally
      EVP_PKEY_free(pkey);
    end;
  finally
    BIO_free(KeyBuffer);
  end;
end;
{
Importer une clé privée RSA (chiffrée ou non)
Un fichier au format PEM contenant un clé privée RSA
commence par —–BEGIN PRIVATE KEY—– puis est suivi de la clé en Base64
et se termine par —–END PRIVATE KEY—–.
Si la clé est chiffrée, alors le fichier au format PEM
commence par —–BEGIN RSA PRIVATE KEY—– puis est suivi de Proc-Type: 4,ENCRYPTED.
Ensuite, il y a des informations sur l’algorithme utilisé pour chiffrer la clé (par exemple AES-128-CBC)
puis il y a la clé chiffrée, en Base64.
Enfin, le fichier se termine par —–END RSA PRIVATE KEY—–.
}
function RSAOpenSSLPrivateKey(filePath: string; pwd: String=''): pRSA;
var
  KeyBuffer: PBio;
  p: PReadKeyChar;
  I: Integer;
  x: pRSA;
begin
  log('FromOpenSSLPrivateKey: '+filepath);
  x:=nil;
  KeyBuffer := LoadPEMFile(filePath);
  if KeyBuffer = nil then
    raise Exception.Create('cannot load buffer');
  try
    if pwd <> '' then
    begin
      p := GetMemory((length(pwd) + 1) * SizeOf(Char));
      for I := 0 to length(pwd) - 1 do p[I] := ReadKeyChar(pwd[I+1]);
      p[length(pwd)] := ReadKeyChar(#0);
    end
    else
      p := nil; //password will be prompted
    try
      Result := PEM_read_bio_RSAPrivateKey(KeyBuffer, x, nil, p);
      if not Assigned(Result) then
        raise Exception.Create('cannot load private key');
    finally
{On efface le mot de passe}
      FillChar(p, SizeOf(p), 0);
      FreeMem(p);
    end;
  finally
    BIO_free(KeyBuffer);
  end;

end;

{
Importer une clé publique RSA à partir d’un certificat X509
Un fichier au format PEM contenant un certificat X509
commence par —–BEGIN CERTIFICATE—– puis est suivi de la clé en Base64
et se termine par —–END CERTIFICATE—–.
}
function RSAOpenSSLCert(filePath: string): pRSA;
var
  KeyBuffer: PBIO;
  FX509: pX509;
  Key: PEVP_PKEY;
  x: pX509;
begin
  log('FromOpenSSLCert: '+filepath);
  x:=nil;
  //KeyBuffer := LoadPEMFile(Buffer, Length(Buffer));
  KeyBuffer := LoadPEMFile(filepath);
  if KeyBuffer = nil then
    raise Exception.Create('Impossible de charger le buffer X509');
  try
    FX509 := PEM_read_bio_X509(KeyBuffer, x, nil, nil);
    if not Assigned(FX509) then
      raise Exception.Create('Impossible de charger le certificat X509');
    Key := X509_get_pubkey(FX509);
    if not Assigned(Key) then
      raise Exception.Create('Impossible de charger la clé publique X509');
    try
      Result := EVP_PKEY_get1_RSA(Key);
      if not Assigned(Result) then
        raise Exception.Create('Impossible de charger la clé publique RSA');
    finally
      EVP_PKEY_free(Key);
    end;
  finally
    BIO_free(KeyBuffer);
  end;
end;

function PEM2P7B(filename:string):boolean;
var
p7: pPKCS7=nil;
certs:pSTACK_OFX509 = nil;
bp:pBIO;
x509_cert:pX509=nil;
begin

  result:=false;

log('PEM2P7B');
log('filename:'+filename);

  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509');
  x509_cert:=PEM_read_bio_X509(bp,nil,nil,nil);
  BIO_free(bp);
  if x509_cert=nil then
     begin
     writeln('PEM_read_bio_X509 failed');
     exit;
     end;

  //
  certs := sk_new_null();
  sk_push(certs, x509_cert);
  //

  //log('i2d_PKCS7_bio');
  //result:=i2d_PKCS7_bio (bp,p7)<>-1; //der
  //if result=false then writeln('i2d_X509_bio failed');
  //https://www.openssl.org/docs/man1.0.2/man3/PKCS7_sign.html
  //if signcert and pkey are NULL then a certificates only PKCS#7 structure is output.
  p7 := PKCS7_sign(nil, nil, certs, nil, PKCS7_BINARY);
  if p7=nil then writeln('PKCS7_sign failed');
  //finalize the structure
  log('PEM_write_bio_PKCS7');
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.p7b')), 'w+');
  PEM_write_bio_PKCS7(bp,p7);
  BIO_free(bp);
  sk_free(certs);
  result:=true;
end;

function P7B2PEM(filename:string):boolean;
var
bp:pBIO;
p7: pPKCS7;
begin
  result:=false;
  log('P7B2PEM');
  log('filename:'+filename);
  result:=false;
  bp := BIO_new_file(pchar(filename), 'r+');
  log('d2i_PKCS7_bio');
  //decode
  p7:=d2i_PKCS7_bio(bp, nil);
  BIO_free(bp);
  if p7 = nil then exit;

  //OBJ_obj2nid(p7^.type) should give us the type of p7b : NID_pkcs7_signed or NID_pkcs7_signedAndEnveloped
  //sk_num should give us number of certs // if more than one we should sk_X509_shift or sk_X509_value(certs, i)

  if (p7^.sign^.cert <> nil) then
  begin
       bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.crt')), 'w+');
       log('PEM_write_bio_X509');
       //PEM_write_bio_X509(bp,sk_X509_value(p7^.sign^.cert, 0));
       PEM_write_bio_X509(bp,sk_value(p7^.sign^.cert, 0));
       BIO_free(bp);
       result:=true;
  end;
end;

function PFX2PEM(filename,export_pwd:string):boolean;
const
  PKCS12_R_MAC_VERIFY_FAILURE =113;
var
    p12_cert:pPKCS12 = nil;
    pkey:pEVP_PKEY=nil;
    x509_cert:pX509=nil;
    additional_certs:pSTACK_OFX509 = nil;
    bp:pBIO;
    err_reason:integer;
begin
  result:=false;
  log('Convert2PEM');
  log('filename:'+filename);
  result:=false;
  bp := BIO_new_file(pchar(filename), 'r+');
  log('d2i_PKCS12_bio');
  //decode
  p12_cert:=d2i_PKCS12_bio(bp, nil);
  if p12_cert = nil then exit;
  log('PKCS12_parse');
  //this is the export password, not the private key password
  err_reason:=PKCS12_parse(p12_cert, pchar(export_pwd), pkey, x509_cert, additional_certs);
  //if err_reason<>0 then
  log(inttostr(err_reason));
  BIO_free(bp);
  if err_reason =0 then exit;

  //
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.crt')), 'w+');
  log('PEM_write_bio_X509');
  PEM_write_bio_X509(bp,x509_cert);
  BIO_free(bp);
  if pkey=nil then exit;
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.key')), 'w+');
  log('PEM_write_bio_PrivateKey');
  log('no password...');
  //the private key will have no password
  PEM_write_bio_PrivateKey(bp,pkey,nil{EVP_des_ede3_cbc()},nil,0,nil,nil);
  BIO_free(bp);
  //

  if x509_cert<>nil then X509_free(x509_cert); x509_cert := nil;
  if pkey<>nil then EVP_PKEY_free(pkey); pkey := nil;
  ERR_clear_error();
  PKCS12_free(p12_cert);
  result:=true;
end;

function PEM2PFX(export_pwd,privatekey,cert:string):boolean;
var
  err_reason:integer;
  bp:pBIO=nil;
  p12_cert:pPKCS12 = nil;
  pkey:pEVP_PKEY = nil;
  x509_cert:pX509 = nil;
  certs:pSTACK_OFX509 = nil;
begin
  result:=false;
  log('Convert2PKCS12');
  log('cert:'+cert);
  log('privatekey:'+privatekey);
  bp := BIO_new_file(pchar(privatekey), 'r+');
  log('PEM_read_bio_PrivateKey');
  //password will be prompted
  pkey:=PEM_read_bio_PrivateKey(bp,nil,nil,nil);
  BIO_free(bp);
  if pkey=nil then
     begin
     writeln('PEM_read_bio_PrivateKey failed');
     exit;
     end;

  bp := BIO_new_file(pchar(cert), 'r+');
  log('PEM_read_bio_X509');
  //x509_cert:=PEM_read_bio_X509(bp,nil,nil,nil);
  certs := sk_new_null();
    while 1=1 do
    begin
         x509_cert := PEM_read_bio_X509(bp, nil, nil, nil);
         if x509_cert =nil then break;
         sk_push(certs, x509_cert);
    end;
  BIO_free(bp);
  x509_cert :=sk_value(certs,0);
  if x509_cert=nil then
     begin
     writeln('PEM_read_bio_X509 failed');
     exit;
     end;

  log('PKCS12_new');
  p12_cert := PKCS12_new();
  if p12_cert=nil then exit;


  log('PKCS12_create');
  p12_cert := PKCS12_create(pchar(export_pwd), nil, pkey, nil, certs, 0, 0, 0, 0, 0);
  if p12_cert = nil then
     begin
     writeln('PKCS12_create failed, '+inttohex(ERR_peek_error,8));
     //(SSL: error:0B080074:x509 certificate routines: X509_check_private_key:key values mismatch)
     exit;
     end;

  log('i2d_PKCS12_bio');
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(cert,'.pfx')), 'w+');
  err_reason:=i2d_PKCS12_bio(bp, p12_cert);
  BIO_free(bp);


  if x509_cert<>nil then X509_free(x509_cert); x509_cert := nil;
  if pkey<>nil then EVP_PKEY_free(pkey); pkey := nil;
  ERR_clear_error();
  PKCS12_free(p12_cert);
  result:=err_reason<>0;
end;

function X509PEM2DER(filename:string):boolean;
var
x509_cert:pX509=nil;
bp:pBIO;
begin
result:=false;

log('X509PEM2DER');
log('filename:'+filename);

  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509');
  x509_cert:=PEM_read_bio_X509(bp,nil,nil,nil);
  BIO_free(bp);
  if x509_cert=nil then
     begin
     writeln('PEM_read_bio_X509 failed');
     exit;
     end;

  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.der')), 'w+');
  result:= i2d_X509_bio (bp,x509_cert )<>-1;
  if result=false then writeln('i2d_X509_bio failed');
  BIO_free(bp);

end;

function X509DER2PEM(filename:string):boolean;
var
hfile_:thandle=thandle(-1);
mem_:array[0..8192-1] of char;
size_:dword=0;
//
pemX509Bio,bp:pBIO;
X509Key:pX509=nil;
begin
  result:=false;
  //
  hfile_ := CreateFile(pchar(filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
  if hfile_=thandle(-1) then begin log('invalid handle',1);exit;end;
  ReadFile (hfile_,mem_[0],sizeof(mem_),size_,nil);
  closehandle(hfile_);
  //
  pemX509Bio := BIO_new(BIO_s_mem());
  BIO_write(pemX509Bio, @mem_[0], size_);
  BIO_flush(pemX509Bio);
  X509Key := d2i_X509_bio (pemX509Bio, X509Key);
  if X509Key=nil then exit;
  //
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.crt')), 'w+');
  log('PEM_write_bio_X509');
  PEM_write_bio_X509 (bp,X509Key);
  BIO_free(bp);
  //
  result:=true;
end;

function PVTDER2PEM(filename:string):boolean;
var
hfile_:thandle=thandle(-1);
mem_:array[0..8192-1] of char;
size_:dword=0;
//
pemPrivKeyBio,bp:pBIO;
privKey:pEVP_PKEY=nil;
begin
  result:=false;
  //
  hfile_ := CreateFile(pchar(filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
  if hfile_=thandle(-1) then begin log('invalid handle',1);exit;end;
  ReadFile (hfile_,mem_[0],sizeof(mem_),size_,nil);
  closehandle(hfile_);
  //
  pemPrivKeyBio := BIO_new(BIO_s_mem());
  BIO_write(pemPrivKeyBio, @mem_[0], size_);
  BIO_flush(pemPrivKeyBio);
  //BIO_read_filename easier?;
  privKey := d2i_PrivateKey_bio(pemPrivKeyBio, privKey {nil?});
  if privkey=nil then exit;
  //
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.key')), 'w+');
  log('PEM_write_bio_PrivateKey');
  log('no password...');
  //the private key will have no password
  PEM_write_bio_PrivateKey(bp,privKey,nil{EVP_des_ede3_cbc()},nil,0,nil,nil);
  BIO_free(bp);
  //
  result:=true;
end;

function PVTPEM2DER(filename:string):boolean;
var
p:pEVP_PKEY =nil;
bp:pBIO;
begin
result:=false;

log('PVTPEM2DER');
log('filename:'+filename);

p:=LoadPrivateKey(filename);
  if p=nil then
     begin
     writeln('LoadPrivateKey failed');
     exit;
     end;

  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.der')), 'w+');
  result:= i2d_PrivateKey_bio  (bp,p )<>-1;
  if result=false then writeln('i2d_X509_bio failed');
  BIO_free(bp);

end;

{
function selfsign(filename:string;subject:string):boolean;
var
    x:pX509 = nil;
    tmp:pX509_NAME=nil;
    pkey:pEVP_PKEY = nil;
    rsa:pRSA=nil;
    bp:pBIO=nil;
begin
  result:=false;

  x := X509_new();

  //OpenSSL provides the EVP_PKEY structure for storing an algorithm-independent private key in memory
  log('EVP_PKEY_new');
  pkey := EVP_PKEY_new();

  //generate key
  log('RSA_generate_key');
  rsa := RSA_generate_key(
    2048,   //* number of bits for the key - 2048 is a sensible value */
    RSA_F4, //* exponent - RSA_F4 is defined as 0x10001L */
    nil,   //* callback - can be NULL if we aren't displaying progress */
    nil    //* callback argument - not needed in this case */
    );

   //assign key to our struct
   log('EVP_PKEY_assign_RSA');
   EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));

   X509_set_version(x, 2); //* version 3 certificate */
   ASN1_INTEGER_set(X509_get_serialNumber(x),0);
   X509_gmtime_adj(X509_get_notBefore(x), 0);
   X509_gmtime_adj(X509_get_notAfter(x), 365 * 24 * 3600);

   tmp := X509_get_subject_name(x);
   X509_NAME_add_entry_by_txt(tmp, 'CN', MBSTRING_ASC, pchar(subject), -1, -1, 0);
   X509_set_subject_name(x, tmp);

   X509_set_pubkey(x, pkey);
   X509_sign(x, pkey, EVP_sha256 ());

   bp := BIO_new_file(pchar(ChangeFileExt (filename,'.key')), 'w+');
  //PEM_write_bio_PrivateKey(bp,pkey,nil,nil,0,nil,nil);
  //if you want a prompt for passphrase
  log('PEM_write_bio_PrivateKey');
  PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);
  BIO_free(bp);

  bp := BIO_new_file(pchar(filename), 'w+');
  log('PEM_write_bio_X509');
  PEM_write_bio_X509(bp,x);
  BIO_free(bp);

   result:=x<>nil;

   if (x<>nil) then X509_free(x);
   if (pkey<>nil) then EVP_PKEY_free(pkey);

end;
}

function name_add_entry(section:string;name:px509_name):boolean;
var
//
ini:TIniFile;
ident:tstrings;
s:string;
i:byte;
begin
  log('name_add_entry');
  result:=false;
  if FileExists ('tinyssl.ini') then
   begin
   try
   ini:=tinifile.Create ('tinyssl.ini');
   ident:=tstringlist.Create ;
   ini.ReadSection(section,ident) ;
   for i:=0 to ident.count-1 do
       begin
       s:=ini.ReadString (section,ident[i],'');
       log('X509_NAME_add_entry_by_txt');
       X509_NAME_add_entry_by_txt(name, pchar(ident[i]),  MBSTRING_ASC,pchar(s), -1, -1, 0);
       end;
   ident.Free ;
   result:=true;
   except
   on e:exception do;
   end;
   end; //if FileExists ('tinyssl.ini') then
end;

function ini_readstring(section,ident:string):string;
var
//
ini:TIniFile;
begin
  //log('ini_readstring');
  result:='';
  if FileExists ('tinyssl.ini') then
   begin
   try
   ini:=tinifile.Create ('tinyssl.ini');
   result:=ini.ReadString (section,ident,'');
   except
   on e:exception do;
   end;
   end; //if FileExists ('tinyssl.ini') then
end;

function add_ext(cert: PX509; nid: TC_INT; value: PAnsiChar): Boolean;
var ex: PX509_EXTENSION=nil;
    ctx: X509V3_CTX;
begin
  log('add_ext '+strpas(value));
  Result := false;
  ctx.db := nil;
  log('X509V3_set_ctx');
  X509V3_set_ctx(@ctx, cert, cert, nil, nil, 0);
  log('X509V3_EXT_conf_nid');
  ex := X509V3_EXT_conf_nid(nil, @ctx, nid, value);
  if ex <> nil then
  begin
    log('X509_add_ext');
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    Result := True;
  end;

end;

// sign cert
function do_X509_sign(cert:pX509; pkey:pEVP_PKEY;const md:pEVP_MD):integer;
var
rv:integer;
mctx:EVP_MD_CTX;
pkctx:pEVP_PKEY_CTX = nil;
begin
        log('EVP_MD_CTX_init');
	EVP_MD_CTX_init(@mctx);
        log('EVP_DigestSignInit');
	rv := EVP_DigestSignInit(@mctx, @pkctx, md, nil, pkey);
        log('X509_sign_ctx');
	if (rv > 0) then rv := X509_sign_ctx(cert, @mctx);
        log('EVP_MD_CTX_cleanup');
	EVP_MD_CTX_cleanup(@mctx);
	if rv > 0 then result:= 1 else result:= 0;
end;

function hash_pubkey(x509_cert:pX509):boolean;
const
  X509V3_ADD_DEFAULT =0;
var
ret:integer = 0;
rsa:pRSA=nil;
digest:array[0..63] of byte;
size,i:cardinal;
subjectKeyIdentifier:pASN1_OCTET_STRING;
bin:pointer;
begin
       result:=false;
       rsa:=EVP_PKEY_get1_RSA(X509_get_pubkey (x509_cert));
       //Writeln('BN_bn2hex E: ', BN_bn2hex(rsa^.e ));
       bin:=getmem(BN_num_bytes(rsa^.e));
       BN_bn2bin(rsa^.e,bin);
       //X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len); // not in openssl 1.x
       ret:=evp_digest(bin , BN_num_bytes(rsa^.e),@digest[0],size,EVP_sha1(),nil);
       if ret=1 then
         begin
         //write('hash sha1:');
         //for i:=0 to size -1 do write(inttohex(digest[i],2));
         //writeln;
         subjectKeyIdentifier := ASN1_OCTET_STRING_new;
         ASN1_OCTET_STRING_set(subjectKeyIdentifier, @digest[0], SHA_DIGEST_LENGTH);
         log('X509_add1_ext_i2d');
         X509_add1_ext_i2d(x509_cert, NID_subject_key_identifier, subjectKeyIdentifier, 0, X509V3_ADD_DEFAULT);
         ASN1_OCTET_STRING_free(subjectKeyIdentifier);
         result:=true;
         end;
end;

//the private key of the resulting cert is the request.key
function signreq(filename:string;cert:string;read_password:string='';alt:string='';ca:boolean=false):boolean;
const
   LN_commonName=                   'commonName';
   //NID_commonName=                  13;
   X509V3_ADD_DEFAULT =0;
var
ret:integer = 0;
pkey:PEVP_PKEY=nil;
pktmp:PEVP_PKEY=nil;
rsa:pRSA=nil;
cert_rsa:pRSA=nil;
x509_ca:pX509=nil;
x509_cert:pX509=nil;
X509_REQ:pX509_REQ=nil;
bp:pBIO;
serial:integer = 1;
days:long = 365 * 24 * 3600; // 1 year
subject:pX509_NAME = nil;
tmpname:pX509_NAME = nil;
//test
cert_entry:pX509_NAME_ENTRY=nil;
entryData:pASN1_STRING;
cn:ppansichar;
//
value:string;
digest:array[0..63] of byte;
size,i:cardinal;
subjectKeyIdentifier:pASN1_OCTET_STRING;
bin:pointer;
label free_all;
begin
  log('signreq');
  log('filename:'+filename);
  log('cert:'+cert);
  result:=false;
  // load ca
  bp := BIO_new_file(pchar(cert), 'r+');
  log('PEM_read_bio_X509');
  x509_ca:=PEM_read_bio_X509(bp,nil,nil,nil);
  BIO_free(bp);
  if x509_ca=nil then goto free_all;

  //loadCAPrivateKey
  try
  //rsa:=RSAOpenSSLPrivateKey(ChangeFileExt (cert,'.key'),read_password);
  pkey:=LoadPrivateKey (ChangeFileExt (cert,'.key'),read_password);
  if pkey=nil then exception.Create ('pkey is nul');
  except
  on e:exception do begin log(e.message,1);exit;end;
  end; //try

  //generate key
  {
  log('EVP_PKEY_new');
  pkey := EVP_PKEY_new();
  log('EVP_PKEY_assign_RSA');
  EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
  }

  // load X509 Req
  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509_REQ');
  X509_REQ := PEM_read_bio_X509_REQ(bp, nil, nil, nil);
  BIO_free(bp);
  if X509_REQ=nil then goto free_all;
  //
  x509_cert := X509_new();
  // set version to X509 v3 certificate
  log('X509_set_version');
  X509_set_version(x509_cert,2);
  // set serial
  log('X509_get_serialNumber');
  ASN1_INTEGER_set(X509_get_serialNumber(x509_cert), serial);
  // set issuer name frome ca
  log('X509_set_issuer_name');
  X509_set_issuer_name(x509_cert, X509_get_subject_name(x509_ca ));
  //test ok
  {
  cert_entry := X509_NAME_get_entry(X509_get_subject_name(x509_ca ),X509_NAME_get_index_by_NID(X509_get_subject_name(x509_ca ), NID_commonName, 0));
  entryData := X509_NAME_ENTRY_get_data( cert_entry );
  ASN1_STRING_to_UTF8(CN, entryData);
  writeln(strpas(cn^));
  }
  // set time
  X509_gmtime_adj(X509_get_notBefore(x509_cert), 0);
  X509_gmtime_adj(X509_get_notAfter(x509_cert), days);
  //log('X509_NAME_add_entry_by_txt');
  //X509_NAME_add_entry_by_txt(subject, 'CN', MBSTRING_ASC,pchar('localhost'), -1, -1, 0);
  log('X509_set_subject_name'); //from req -> CN
  X509_set_subject_name(x509_cert, X509_REQ_get_subject_name(X509_REQ));
  //X509_NAME_add_entry_by_NID(X509_get_subject_name(X509_cert), NID_pkcs9_emailAddress, MBSTRING_ASC, pchar('me@domain.com'), -1, -1, 0);
  // set pubkey from req
  pktmp := X509_REQ_get_pubkey(X509_REQ);
  log('X509_set_pubkey');
  ret := X509_set_pubkey(x509_cert, pktmp);
  EVP_PKEY_free(pktmp);
  //

  if ca=true then add_ext(x509_cert, NID_basic_constraints, 'critical,CA:true');
  if alt<>'' then add_ext(x509_cert, NID_subject_alt_name,pchar(alt)); //'DNS:localhost'

  //rfc 5280 - key_usage
  value:=ini_readstring('req_ext','key_usage');
  if value<>'' then add_ext(x509_cert, NID_key_usage, pchar(value)); //'critical,digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment'
  value:=ini_readstring('req_ext','subject_key_identifier');
  //if value<>'' then add_ext(x509_cert, NID_subject_key_identifier, pchar(value)); //'hash'
  if value='hash' then hash_pubkey (x509_cert);
  //not ready, see https://github.com/warmlab/study/blob/master/openssl/x509.c
  //value:=ini_readstring('req_ext','authority_key_identifier');
  //if value<>'' then add_ext(x509_cert, NID_authority_key_identifier, pchar(value)); //'keyid:always,issuer:always'
  value:=ini_readstring('req_ext','ext_key_usage');
  if value<>'' then add_ext(x509_cert, NID_ext_key_usage, pchar(value)); //'critical, clientAuth, serverAuth'

  //do_X509_sign;
  log('do_X509_sign');
  do_X509_sign(x509_cert, pkey, EVP_sha256 ());
  //or simpler?
  //X509_sign(x509_cert, pkey,EVP_sha256());
  //

  {
  cert_rsa := EVP_PKEY_get1_RSA(pkey);
  bp := BIO_new_file(pchar('signed.key'), 'w+');
  log('PEM_write_bio_RSAPrivateKey');
  PEM_write_bio_RSAPrivateKey(bp, cert_rsa,nil {EVP_des_ede3_cbc}, nil, 0, nil, nil);
  BIO_free(bp);
  RSA_free(cert_rsa);
  }
  {
  bp := BIO_new_file(pchar('signed.key'), 'w+');
  log('PEM_write_bio_PrivateKey');
  PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);
  BIO_free(bp);
  }

  //save cert
  bp := BIO_new_file(pchar(ChangeFileExt (filename,'.crt') ), 'w+');
  log('PEM_write_bio_X509');
  PEM_write_bio_X509(bp,x509_cert);
  BIO_free(bp);
  //
  free_all:

  	X509_free(x509_cert);
  	//BIO_free_all(out);

  	X509_REQ_free(X509_REQ);
  	X509_free(x509_ca);
  	EVP_PKEY_free(pkey);

  	result:= ret = 1;

end;


{
PEM Format
Most CAs (Certificate Authority) provide certificates in PEM format in Base64 ASCII encoded files.
The certificate file types can be .pem, .crt, .cer, or .key.
The .pem file can include the server certificate, the intermediate certificate and the private key in a single file.
The server certificate and intermediate certificate can also be in a separate .crt or .cer file.
The private key can be in a .key file.

PKCS#12 Format
The PKCS#12 certificates are in binary form, contained in .pfx or .p12 files.
The PKCS#12 can store the server certificate, the intermediate certificate and the private key in a single .pfx file with password protection.
These certificates are mainly used on the Windows platform.
}

//openssl pkcs12 -inkey priv.key -in cert.crt -export -out cert.pfx
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -nodes -> no encrypted private key
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -> encrypted private key
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.key -nodes -nocerts -> private key only
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -nokeys -> cert only
function mkcert(filename:string;cn:string;privatekey:string='';read_password:string='';serial:string='';ca:boolean=false):boolean;
var
    pkey:PEVP_PKEY=nil;
    rsa:pRSA=nil;
    x509:pX509=nil;
    name:pX509_NAME=nil;
    hfile:thandle=thandle(-1);
    f:file;
    bp:pBIO;
    ret:integer;
    days:long = 5 * 365 * 24 * 3600; // 5 years
    //
    bc:pBASIC_CONSTRAINTS;
    iserial:integer=1;
    asn1:pASN1_INTEGER =nil;
    p:pBIGNUM=nil;
    ctx:pBN_CTX=nil ;
    //
    value:string;
begin
  log('mkCAcert');
  log('filename:'+filename);
  log('cn:'+cn);
  log('privatekey:'+privatekey);
result:=false;

  if privatekey='' then
  begin
  log('RSA_generate_key');
  rsa := RSA_generate_key(
    2048,   //* number of bits for the key - 2048 is a sensible value */
    RSA_F4, //* exponent - RSA_F4 is defined as 0x10001L */
    nil,   //* callback - can be NULL if we aren't displaying progress */
    nil    //* callback argument - not needed in this case */
    );
  //generate key
  //OpenSSL provides the EVP_PKEY structure for storing an algorithm-independent private key in memory
  log('EVP_PKEY_new');
  pkey := EVP_PKEY_new();
  //assign key to our struct
  //log('EVP_PKEY_assign_RSA');
  //EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
  log('EVP_PKEY_set1_RSA');
  EVP_PKEY_set1_RSA (pkey,rsa);
  end
  else
  begin
  log('Reusing '+privatekey+'...',1);
  try
  //rsa:=RSAOpenSSLPrivateKey(privatekey,read_password); //password will be prompted
  pkey:=LoadPrivateKey (privatekey,read_password);
  if pkey=nil then exception.Create ('pkey is nul');
  except
  on e:exception do begin log(e.message,1);exit;end;
  end; //try
  end;



//OpenSSL uses the X509 structure to represent an x509 certificate in memory
log('X509_new');
x509 := X509_new();
// set version to X509 v3 certificate
log('X509_set_version');
X509_set_version(x509,2);
//Now we need to set a few properties of the certificate
if serial='' then  ASN1_INTEGER_set (X509_get_serialNumber(x509), iserial);
if serial<>'' then
begin
ctx := BN_CTX_new();
p := BN_new();
BN_hex2bn(p, @serial[1]);
//openssl x509 -noout -serial -in ca.crt
//Writeln('BN_bn2hex: ', strpas(BN_bn2hex(p )));
asn1:=BN_to_ASN1_INTEGER (p,nil);
X509_set_serialNumber(x509,asn1);
end;
//
X509_gmtime_adj(X509_get_notBefore(x509), 0);
X509_gmtime_adj(X509_get_notAfter(x509), days);
//Now we need to set the public key for our certificate using the key we generated earlier
log('X509_set_pubkey');
X509_set_pubkey(x509, pkey);
//Since this is a self-signed certificate, we set the name of the issuer to the name of the subject
log('X509_NAME_new');
name := X509_NAME_new ; //X509_get_subject_name(x509);
//
name_add_entry('cert',name);
//
log('X509_NAME_add_entry_by_txt');
X509_NAME_add_entry_by_txt(name, 'CN', MBSTRING_ASC,pchar(cn), -1, -1, 0);
//
log('X509_set_subject_name');
ret:=X509_set_subject_name(x509, name);
//Now we can actually set the issuer name:
log('X509_set_issuer_name');
X509_set_issuer_name(x509, name);

{
bc:=BASIC_CONSTRAINTS_new;
bc^.ca :=1;
X509_add1_ext_i2d(x509, NID_basic_constraints,bc,1,0 ); //'critical,CA:TRUE'
}

//https://www.openssl.org/docs/man1.1.1/man3/X509V3_EXT_d2i.html
if ca=true then add_ext(x509, NID_basic_constraints, 'critical,CA:TRUE');
value:=ini_readstring('cert_ext','key_usage');
if value<>'' then add_ext(x509, NID_key_usage, pchar(value)); //'critical,keyCertSign,cRLSign'
value:=ini_readstring('cert_ext','subject_key_identifier');
//if value<>'' then add_ext(x509, NID_subject_key_identifier, pchar(value)); //'hash'
if value='hash' then hash_pubkey (x509);
//value:=ini_readstring('cert_ext','authority_key_identifier');
//if value<>'' then add_ext(x509, NID_authority_key_identifier, pchar(value)); //'keyid:always,issuer:always'
value:=ini_readstring('cert_ext','ext_key_usage');
if value<>'' then add_ext(x509, NID_ext_key_usage, pchar(value)); //'critical, clientAuth, serverAuth'

//And finally we are ready to perform the signing process. We call X509_sign with the key we generated earlier. The code for this is painfully simple:
log('X509_sign');
X509_sign(x509, pkey, EVP_sha256());

//write out to disk
//if we loaded an existing private key, we could skip the below
if privatekey='' then
begin
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+ChangeFileExt (filename,'.key')), 'w+');
  //PEM_write_bio_PrivateKey(bp,pkey,nil,nil,0,nil,nil);
  //if you want a prompt for passphrase
  log('PEM_write_bio_PrivateKey');
  ret:= PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil); //not saving as RSA key??
  BIO_free(bp);
  if ret=0 then exit;
end;

bp := BIO_new_file(pchar(GetCurrentDir+'\'+filename), 'w+');
log('PEM_write_bio_X509');
ret:=PEM_write_bio_X509(bp,x509);
BIO_free(bp);
if ret=0 then exit;

//or a bundle
{
bp := BIO_new_file(pchar(GetCurrentDir+'\cert.crt'), 'w+');
PEM_write_bio_X509(bp,x509);
PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);
BIO_free(bp);
}
//free
X509_free(x509);
EVP_PKEY_free(pkey);
RSA_free(rsa);
//
result:=true;
end;

//to sign a csr
//openssl x509 -req -in device.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out device.crt -days 500 -sha256
function mkreq(cn:string;keyfile,csrfile:string):boolean;
var
ret:integer;
rsa:pRSA;
bp:pBIO;
req:pX509_REQ;
key:pEVP_PKEY;
name:pX509_NAME;
begin
  log('mkCAcert');
  log('csrfile:'+csrfile);
  log('privatekey:'+keyfile);
  log('cn:'+cn);
result:=false;

    if keyfile='' then
    begin
    log('RSA_generate_key');
    rsa := RSA_generate_key(
    2048,   //* number of bits for the key - 2048 is a sensible value */
    RSA_F4, //* exponent - RSA_F4 is defined as 0x10001L */
    nil,   //* callback - can be NULL if we aren't displaying progress */
    nil    //* callback argument - not needed in this case */
    );
    //generate key
    //OpenSSL provides the EVP_PKEY structure for storing an algorithm-independent private key in memory
    log('EVP_PKEY_new');
    key := EVP_PKEY_new();
    //assign key to our struct
    //log('EVP_PKEY_assign_RSA');
    //EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
    log('EVP_PKEY_set1_RSA');
    EVP_PKEY_set1_RSA (key,rsa);
    end
    else
    begin
    log('Reusing '+keyfile+'...',1);
    try
    //rsa:=RSAOpenSSLPrivateKey(keyfile,''); //password will be prompted
    key:=LoadPrivateKey(keyfile);
    if key=nil then exception.Create ('pkey is nul');
    except
    on e:exception do begin log(e.message,1);exit;end;
    end; //try
    end;

        log('X509_REQ_new');
	req := X509_REQ_new();
	if req=nil then exit;

        //
	X509_REQ_set_version(req, 0); //v1 ?
	X509_REQ_set_pubkey(req, key);

        log('X509_NAME_new');
	name := X509_NAME_new; //X509_REQ_get_subject_name(req);
        //
        name_add_entry('req',name);
        //
        log('X509_NAME_add_entry_by_txt');
	X509_NAME_add_entry_by_txt(name, 'CN', MBSTRING_ASC,pchar(cn), -1, -1, 0);
        log('X509_REQ_set_subject_name');
        ret:=X509_REQ_set_subject_name(Req, name); //since X509_REQ_get_subject_name(req) failed on me
        X509_NAME_free(name);

        //add extensions?

        log('X509_REQ_sign');
	X509_REQ_sign(req, key, EVP_sha256());

        //we did not load a privatekey so lets save it
        if keyfile='' then
        begin
        bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(csrfile,'.key')), 'w+');
        //the private key will have no password
        //log('PEM_write_bio_RSAPrivateKey');
        //ret := PEM_write_bio_RSAPrivateKey(bp, rsa, nil, nil, 0, nil, nil);
        log('PEM_write_bio_PrivateKey');
        log('no password...');
        ret := PEM_write_bio_PrivateKey(bp, key, nil, nil, 0, nil, nil);
	BIO_free(bp);
        end;

        //save cert
        bp := BIO_new_file(pchar(GetCurrentDir+'\'+csrfile), 'w+');
        log('PEM_write_bio_X509_REQ');
        PEM_write_bio_X509_REQ(bp, req);
	BIO_free(bp);

        //free
        EVP_PKEY_free(key);
	X509_REQ_free(req);

result:=true;

end;

//on the remote ssh server, generate the pub key from the private key generated on the client
//ssh-keygen -y -f private.pem > key.pub
//or ssh-keygen -f public.pem -i -m PKCS8 > key.pub
//copy the pub key to the authorized keys
//cat key.pub >> ~/.ssh/authorized_keys
//should work as well : ssh-copy-id -i /path/to/key/file user@host.com
//Remember that .ssh folder has to be 700. The authorized_keys file should be 600
//or the other way (no success here for now)
//on the remote ssh server, generate a key pair
//ssh-keygen -b 2048 -t rsa -m PEM
//and use either the pub or priv key from there
//see also https://docs.oracle.com/en/cloud/cloud-at-customer/occ-get-started/generate-ssh-key-pair.html

//https://stackoverflow.com/questions/20065304/differences-between-begin-rsa-private-key-and-begin-private-key
//BEGIN RSA PRIVATE KEY is PKCS#1 and is just an RSA key.
//It is essentially just the key object from PKCS#8, but without the version or algorithm identifier in front.
//BEGIN PRIVATE KEY is PKCS#8 and indicates that the key type is included in the key data itself.

//https://superuser.com/questions/1720991/differences-between-begin-rsa-private-key-and-begin-openssh-private-key
//PKCS#1 key files (BEGIN RSA PRIVATE KEY) come from the PEM encrypted messaging project.
//The format is fairly outdated, e.g. it's weak against passphrase bruteforcing. Even OpenSSL itself later started using a newer PKCS#8 format (which uses BEGIN PRIVATE KEY or BEGIN ENCRYPTED PRIVATE KEY headers) for all new private keys.

//https://stackoverflow.com/questions/65449771/difference-between-openssl-genrsa-and-openssl-genpkey-algorithm-rsa#:~:text=Both%20ways%20create%20RSA%20keys,KEY%22%20for%20more%20on%20this.
//Both ways create RSA keys, albeit in different formats.
//genrsa outputs a RSA key in PKCS#1 format while genpkey outputs a more generic container which can manage different kinds of keys (like ECC).

//PEM_write*_PrivateKey (since 1.0.0 in 2010) writes PKCS8-format
function generate_rsa_key:boolean;
var

	ret:integer; //= 0;
	rsa:pRSA;//				 = nil;
	bne:pBIGNUM;// = nil;
	bp_public:pBIO;// = nil;
  bp_private:pBIO;// = nil;

	bits:integer; // = 2048;
	e:ulong; // = RSA_F4;
        //
        pkey:PEVP_PKEY;
  label free_all;
begin
  //
  ret:=0;
  rsa:=nil;
  bne:=nil;
  bp_public :=nil;
  bp_private :=nil;
  bits:=2048;
  e :=RSA_F4;

	// 1. generate rsa key
	bne := BN_new();
	ret := BN_set_word(bne,e);
	if ret <> 1 then goto free_all;

	rsa := RSA_new();
        log('1. generate rsa key');
        ret := RSA_generate_key_ex(rsa, bits, bne, nil);
	if ret <> 1 then goto free_all;

        log('EVP_PKEY_new');
        pkey := EVP_PKEY_new();
        log('EVP_PKEY_assign_RSA');
        EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));

	// 2. save public key
	bp_public := BIO_new_file(pchar(GetCurrentDir+'\public.pem'), 'w+');
        log('2. save public key OK');
        //ret:=PEM_write_bio_RSAPublicKey (bp_public ,rsa);
        ret:=PEM_write_bio_PUBKEY (bp_public ,pkey); //why not RSA ?
	if ret <>1 then goto free_all;

	// 3. save private key
	bp_private := BIO_new_file(pchar(GetCurrentDir+'\private.pem'), 'w+');
        //the private key will have no password
        log('3. save private key');
        log('no password...');
	ret := PEM_write_bio_RSAPrivateKey(bp_private, rsa, nil, nil, 0, nil, nil);  //why RSA?
        //ret := PEM_write_bio_PrivateKey(bp_private, pkey, nil, nil, 0, nil, nil);

	// 4. free
free_all:
       log('free_all');
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(rsa);
	BN_free(bne);
        //if pkey<>nil then EVP_PKEY_free(pkey);

	if ret=1 then result:=true else result:=false;
end;

//PKCS#8
function generate_rsa_key_2:boolean;
var
ret:integer; //= 0;
rsa:pRSA;//				 = nil;
bne:pBIGNUM;// = nil;
bp_public:pBIO;// = nil;
bp_public2:pbio;
bp_private:pBIO;// = nil;

bits:integer; // = 2048;
e:ulong; // = RSA_F4;
//
pkey:PEVP_PKEY;
label free_all;
begin

  //
  ret:=0;
  rsa:=nil;
  bne:=nil;
  bp_public :=nil;
  bp_private :=nil;
  bits:=2048;
  e :=RSA_F4;

	// 1. generate rsa key
	bne := BN_new();
	ret := BN_set_word(bne,e);
	if ret <> 1 then goto free_all;

	rsa := RSA_new();
        log('1. generate rsa key');
        ret := RSA_generate_key_ex(rsa, bits, bne, nil);
	if ret <> 1 then goto free_all;

        log('EVP_PKEY_new');
        pkey := EVP_PKEY_new();
        log('EVP_PKEY_set1_RSA');
        ret:=EVP_PKEY_set1_RSA (pkey,rsa);
        if ret <> 1 then goto free_all;

        // 2. save public key to pem
	bp_public := BIO_new_file(pchar(GetCurrentDir+'\public.pem'), 'w+');
        log('2. save public key OK');
        ret:=PEM_write_bio_PUBKEY (bp_public ,pkey);
	if ret <>1 then goto free_all;

        // 2.1 save public key to rsa -> creates the same file as above ...
	{
        bp_public2 := BIO_new_file(pchar(GetCurrentDir+'\public_rsa.pub'), 'w+');
        log('2.1 save public key OK');
        ret:=PEM_write_bio_RSA_PUBKEY (bp_public2 ,rsa);
	if ret <>1 then goto free_all;
        }

	// 3. save private key
        //check PEM_write_bio_RSAPrivateKey ?
	bp_private := BIO_new_file(pchar(GetCurrentDir+'\private.pem'), 'w+');
        //the private key will have no password
        log('3. save private key');
        log('no password...');
        ret := PEM_write_bio_PrivateKey(bp_private, pkey, nil, nil, 0, nil, nil);

	// 4. free
free_all:
        log('free_all');
	BIO_free_all(bp_public);
    //BIO_free_all(bp_public2);
	BIO_free_all(bp_private);
	RSA_free(rsa);
	BN_free(bne);
        if pkey<>nil then EVP_PKEY_free(pkey);

	if ret=1 then result:=true else result:=false;

end;

//RSA_public_encrypt, RSA_private_decrypt - RSA public key cryptography
//versus
//RSA_private_encrypt, RSA_public_decrypt - low-level signature operations ... using the private key rsa
function Encrypt_Pub(sometext:string;var encrypted:string):boolean;
var
	rsa: pRSA; // структура RSA
	size: Integer;
	FCryptedBuffer: pointer; // Выходной буфер
	b64, mem: pBIO;
	str, data: AnsiString;
	len, b64len: Integer;
	penc64: PAnsiChar;
	err: Cardinal;
        //
        //FPublicKey: pEVP_PKEY;
        FKey: pEVP_PKEY=nil;
        bp:pBIO;
begin
  result:=false;
  FKey := LoadPublicKey('public.pem');

  //load the private key but then you lose the benefit of private/public key...
  //unless you want both end to encrypt/decrypt with a unique private key
  //FKey := LoadPrivateKey('private.pem');

  //
  if FKey=nil then exit;
  //
	rsa := EVP_PKEY_get1_RSA(FKey); // Получение RSA структуры
	EVP_PKEY_free(FKey); // Освобождение pEVP_PKEY
	size := RSA_size(rsa); // Получение размера ключа
	GetMem(FCryptedBuffer, size); // Определение размера выходящего буфера
	str := AnsiString(sometext); // Строка для шифрования

	//Шифрование
	len := RSA_public_encrypt(Length(str),  // Размер строки для шифрования
							  PAnsiChar(str),  // Строка шифрования
							  FCryptedBuffer,  // Выходной буфер
							  rsa, // Структура ключа
							  RSA_PKCS1_PADDING // Определение выравнивания
							  );

	if len > 0 then // длина буфера после шифрования
	  begin
          log(inttostr(len));
	  // полученный бинарный буфер преобразуем в человекоподобный base64
		b64 := BIO_new(BIO_f_base64); // BIO типа base64
                BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
		mem := BIO_push(b64, BIO_new(BIO_s_mem)); // Stream
		try
			BIO_write(mem, FCryptedBuffer, len); // Запись в Stream бинарного выходного буфера
			BIO_flush(mem);
			b64len := BIO_get_mem_data(mem, penc64); //получаем размер строки в base64
			SetLength(data, b64len); // задаем размер выходному буферу
			Move(penc64^, PAnsiChar(data)^, b64len); // Перечитываем в буфер data строку в base64
                        encrypted:=data;
		finally
			BIO_free_all(mem);
		end;
	  end
	  else
	  begin // читаем ошибку, если длина шифрованной строки -1
		err := ERR_get_error;
		repeat
			log(string(ERR_error_string(err, nil)),1);
			err := ERR_get_error;
		until err = 0;
	  end;
	RSA_free(rsa);
        result:=true;
end;

{
-Generate private key
openssl genrsa 2048 > private2.pem
-Generate public key from private
openssl rsa -in private2.pem -pubout > public2.pem
}
function Decrypt_Priv(ACryptedData:string):boolean;
var
  rsa: pRSA=nil;
  out_: AnsiString;
  str, data: PAnsiChar;
  len, b64len: Integer;
  penc64: PAnsiChar;
  b64, mem, bio_out, bio: pBIO;
  size: Integer;
  err: Cardinal;
  //
  FKey: pEVP_PKEY=nil;
  bp:pBIO;
  x: pEVP_PKEY;
begin

        //FKey:=LoadPublicKey('public.pem');
        FKey:=LoadPrivateKey('private.pem');
        if FKey = nil then
        begin
        	err := ERR_get_error;
        	repeat
        		log(string(ERR_error_string(err, nil)),1);
        		err := ERR_get_error;
        	until err = 0;
                exit;
        	end;

        //
        log('EVP_PKEY_get1_RSA');
	rsa := EVP_PKEY_get1_RSA(FKey);
        EVP_PKEY_free(FKey);
        if rsa=nil then exit;


        //we could load the rsa directly from the private key as well
        {
        bp := BIO_new_file(pchar('private.pem'), 'r+');
        log('PEM_read_bio_RSAPrivateKey');
        rsa:=PEM_read_bio_RSAPrivateKey   (bp,nil,nil,nil);
        BIO_free(bp);
        if rsa=nil then exit;
        }

        log('RSA_size');
        size := RSA_size(rsa);
        log('RSA_size:'+inttostr(size));
	GetMem(data, size);  // Определяем размер выходному буферу дешифрованной строки
	GetMem(str, size); // Определяем размер шифрованному буферу после конвертации из base64
        //
        log('Length(ACryptedData):'+inttostr(Length(ACryptedData)));
	//Decode base64
	b64 := BIO_new(BIO_f_base64);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	mem := BIO_new_mem_buf(PAnsiChar(ACryptedData), Length(ACryptedData));
	BIO_flush(mem);
	mem := BIO_push(b64, mem);
	len:=BIO_read(mem, str , Length(ACryptedData)); // Получаем шифрованную строку в бинарном виде
        log('BIO_read:'+inttostr(len));
	BIO_free_all(mem);
	// Дешифрование
        log('RSA_private_decrypt');
	len := RSA_private_decrypt(size, PCharacter(str), PCharacter(data), rsa, RSA_PKCS1_PADDING);
        log('RSA_private_decrypt:'+inttostr(len));
        if len > 0 then
	begin
	// в буфер data данные расшифровываются с «мусором» в конца, очищаем, определяем размер переменной out_ и переписываем в нее нужное количество байт из data
		SetLength(out_, len);
		Move(data^, PAnsiChar(out_ )^, len);
                writeln(out_);
	end
	else
        begin // читаем ошибку, если длина шифрованной строки -1
		err := ERR_get_error;
		repeat
			writeln(string(ERR_error_string(err, nil)));
			err := ERR_get_error;
		until err = 0;
	end;
end;

//openssl rsa -noout -text -in ca.key
function print_private(filename:string;password:string=''):boolean;
var
   rsa:pRSA=nil;
   pkey:pEVP_PKEY ;
   bin:pointer;
   size,i,b64len:cardinal;
   digest:array [0..EVP_MAX_MD_SIZE-1] of byte;
   modulus:pbignum;
   bio_mem,bio_base64,bio:pbio;
   data:array [0..4095] of char;
begin
  result:=false;
  //rsa:=RSAOpenSSLPrivateKey (filename,password); //password will be prompted
  pkey:=LoadPrivateKey (filename,password);
  //lets display the pubkey
  bio_mem := BIO_new(BIO_s_mem());
  bio_base64 := BIO_new(BIO_f_base64());
  bio:=BIO_push(bio_base64, bio_mem);
  //write to bio
  PEM_write_bio_PUBKEY(bio_base64, pkey );
  Bio_flush(bio_base64);
  //read from bio
  b64len:=BIO_read(bio_base64, @data[0], sizeof(data)-1);
  writeln();
  data[b64len] := #0;
  writeln(data);
  //EVP_PKEY_free(key);
  BIO_free(bio);//BIO_free(bio_base64);BIO_free(bio_mem);
  rsa:=EVP_PKEY_get1_RSA(pkey);
  //try if rsa<>nil then Writeln('BN_bn2hex N: ', strpas(BN_bn2hex(rsa^.n )));except end;
  //try if rsa<>nil then Writeln('BN_bn2hex D: ', strpas(BN_bn2hex(rsa^.d  )));except end; //exponent
  try if rsa<>nil then Writeln('BN_bn2hex E: ', BN_bn2hex(rsa^.e ));except end;
  //
  bin:=getmem(BN_num_bytes(rsa^.e));
  BN_bn2bin(rsa^.e,bin);
  if evp_digest(bin , BN_num_bytes(rsa^.e),@digest[0],size,EVP_sha1(),nil)=1 then
     begin
     write('hash sha1:');
     for i:=0 to size -1 do write(inttohex(digest[i],2));
     writeln;
     end;

  //try if rsa<>nil then Writeln('BN_bn2hex P: ', strpas(BN_bn2hex(rsa^.p   )));except end;
  //try if rsa<>nil then Writeln('BN_bn2hex Q: ', strpas(BN_bn2hex(rsa^.q   )));except end;
   result:=true;
end;

function getSerialNumber(x509:px509): String;
var
   Buffer : array [0..31] of char;
   v: pASN1_OCTET_STRING ;
   b:byte;
begin
  result:='';
   v := X509_get_serialNumber(x509);
   //StrLCopy(pansichar(@buffer), v^.data, v^.length);
   for b:=0 to v^.length-1 do result:=result+inttohex(pbyte(v^.data)[b],2); //to be checked
   //Result:=Buffer;
end;

function getDN(pDn: pX509_NAME): String;
var
  buffer: array [0..1023] of char;
begin
X509_NAME_oneline(pDn, @buffer, SizeOf(buffer));
result := StrPas(@buffer);
end;

// Extract a ASN1 time

function getTime(asn1_time: pASN1_TIME): TDateTime;
var
  buffer: array [0..31] of char;
  tz, Y, M, D, h, n, s: integer;
//  tmpbio: pBIO;
  function Char2Int(d, u: char): integer;
  begin
  if (d < '0') or (d > '9') or (u < '0') or (u > '9') then
    raise exception.Create('Invalid ASN1 date format (invalid char).');
  result := (Ord(d) - Ord('0'))*10 + Ord(u) - Ord('0');
  end;
begin
{
i2d_ASN1_TIME(asn1_time, @buffer2);
if buffer='' then
  result := time
else
  result := 0;
}

if (asn1_time^.asn1_type <> V_ASN1_UTCTIME)
    and (asn1_time^.asn1_type <> V_ASN1_GENERALIZEDTIME) then
  raise exception.Create('Invalid ASN1 date format.');

tz := 0;
s := 0;

StrLCopy(@buffer, asn1_time^.data, asn1_time^.length);

if asn1_time^.asn1_type = V_ASN1_UTCTIME then
  begin
  if asn1_time^.length < 10 then
    raise exception.Create('Invalid ASN1 UTC date format (too short).');
	Y := Char2Int(buffer[0], buffer[1]);
    if Y < 50 then
      Y := Y + 100;
    Y := Y + 1900;
    M := Char2Int(buffer[2], buffer[3]);
    D := Char2Int(buffer[4], buffer[5]);
    h := Char2Int(buffer[6], buffer[7]);
    n := Char2Int(buffer[8], buffer[9]);
    if (buffer[10] >= '0') and (buffer[10] <= '9')
        and (buffer[11] >= '0') and (buffer[11] <= '9') then
      s := Char2Int(buffer[10], buffer[11]);
    if buffer[asn1_time^.length-1] = 'Z' then
      tz := 1;
  end
else if asn1_time^.asn1_type = V_ASN1_GENERALIZEDTIME then
  begin
  if asn1_time^.length < 12 then
    raise exception.Create('Invalid ASN1 generic date format (too short).');
    Y := Char2Int(buffer[0], buffer[1])*100 + Char2Int(buffer[2], buffer[3]);;
    M := Char2Int(buffer[4], buffer[5]);
    D := Char2Int(buffer[6], buffer[7]);
    h := Char2Int(buffer[8], buffer[9]);
    n := Char2Int(buffer[10], buffer[11]);
    if (buffer[12] >= '0') and (buffer[12] <= '9')
        and (buffer[13] >= '0') and (buffer[13] <= '9') then
      s := Char2Int(buffer[12], buffer[13]);
    if buffer[asn1_time^.length-1] = 'Z' then
      tz := 1;
  end;
if tz > 0 then
  result := IncHour(EncodeDateTime(Y, M, D, h+tz, n, s, 0), tz)
else
  result := EncodeDateTime(Y, M, D, h, n, s, 0);
{tmpbio := BIO_new(BIO_s_mem());
ASN1_TIME_print(tmpbio, asn1_time);
BIO_read(tmpbio, @buffer, SizeOf(buffer));
BIO_free_all(tmpbio);
if buffer = '' then
  result := time
else
  result := time}
end;


//openssl x509 -noout -text -in ca.crt
//openssl pkey -in ca.key -pubout -outform pem
//openssl x509 -in certificate.crt -pubkey -noout -outform pem | sha256sum
function print_cert(filename:string):boolean;
var
    rsa:pRSA=nil;
    //
    ctx:pBN_CTX;
    p:pBIGNUM;
    bp:pBIO=nil;
    n:integer=0;
    x509:pX509 ;
    key:pEVP_PKEY ;
    digest:array [0..EVP_MAX_MD_SIZE-1] of byte;
    size,i,num,b64len:cardinal;
    context:PEVP_MD_CTX;
    bin:pointer;
    name:pX509_NAME=nil;
    usage:PASN1_STRING;
    certs:pSTACK_OFX509;
    bio_mem,bio_base64,bio:pBIO;
    data:array [0..4095] of char;
begin
  result:=false;
  //rsa:=RSAOpenSSLCert(filename);

  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509_REQ');
  certs := sk_new_null();
  while 1=1 do
  begin
       X509 := PEM_read_bio_X509(bp, nil, nil, nil);
       if x509 =nil then break;
       sk_push(certs, X509);
  end;
  BIO_free(bp);
  //

  for num:=0 to sk_num (certs) -1 do
  begin
  x509:=sk_value(certs,num);
  writeln('***********************************************');
  //
  log('X509_get_subject_name');
  NAME:=X509_get_subject_name(x509);
  writeln('subject_name:'+getdn(name));
  //
  //
  log('X509_get_issuer_name');
  NAME:=X509_get_issuer_name(x509);
  writeln('issuer_name:'+getdn(name));
  //

  log('X509_get_pubkey');
  key:=X509_get_pubkey (x509);
  //lets display the pubkey
  bio_mem := BIO_new(BIO_s_mem());
  bio_base64 := BIO_new(BIO_f_base64());
  bio:=BIO_push(bio_base64, bio_mem);
  //write to bio
  PEM_write_bio_PUBKEY(bio_base64, key );
  Bio_flush(bio_base64);
  //read from bio
  b64len:=BIO_read(bio_base64, @data[0], sizeof(data)-1);
  writeln();
  data[b64len] := #0;
  writeln(data);
  //EVP_PKEY_free(key);
  BIO_free(bio);//BIO_free(bio_base64);BIO_free(bio_mem);

  //key:=LoadCertPublicKey(filename);
  rsa:=EVP_PKEY_get1_RSA(key);

  //try if rsa<>nil then Writeln('BN_bn2hex N: ', strpas(BN_bn2hex(rsa^.n )));except end;
  //try if rsa<>nil then Writeln('BN_bn2hex D: ', strpas(BN_bn2hex(rsa^.d  )));except end; //exponent
  //n := BN_num_bytes(rsa^.e); writeln(inttostr(n)+' bytes');
  try if rsa<>nil then Writeln('Modulo: ', BN_bn2hex(rsa^.e ));except end;
  //
  bin:=getmem(BN_num_bytes(rsa^.e));
  BN_bn2bin(rsa^.e,bin);
  {
  size:=0;
  context := EVP_MD_CTX_create();
  EVP_DigestInit(context,EVP_sha1());
  EVP_DigestUpdate(context, bin, BN_num_bytes(rsa^.e));
  EVP_DigestFinal(context, @digest[0], size);
  EVP_MD_CTX_destroy (context);
  }
  //
  if evp_digest(bin , BN_num_bytes(rsa^.e),@digest[0],size,EVP_sha1(),nil)=1 then
     begin
     write('hash sha1:');
     for i:=0 to size -1 do write(inttohex(digest[i],2));
     writeln;
     end;
  //try if rsa<>nil then Writeln('BN_bn2hex P: ', strpas(BN_bn2hex(rsa^.p   )));except end;
  //try if rsa<>nil then Writeln('BN_bn2hex Q: ', strpas(BN_bn2hex(rsa^.q   )));except end;

  writeln('key_usage:');
  usage := X509_get_ext_d2i(x509, NID_key_usage, nil, nil);
  if (byte(usage^.data^) and $80)=$80 then writeln('digitalSignature');
  if (byte(usage^.data^) and $40)=$40 then writeln('nonrepudiation ');
  if (byte(usage^.data^) and $20)=$20 then writeln('keyEncipherment ');
  if (byte(usage^.data^) and $10)=$10 then writeln('dataEncipherment');
  if (byte(usage^.data^) and $08)=$08 then writeln('keyAgreement');
  if (byte(usage^.data^) and $04)=$04 then writeln('keyCertSign');
  if (byte(usage^.data^) and $02)=$02 then writeln('cRLSign');

  {
  //todo
  usage:=X509_get_ext_d2i(x509, NID_ext_key_usage,nil, nil);
  }

  try
  log('X509_get_notBefore');
  writeln('notBefore:'+DateTimeToStr (getTime (X509_get_notBefore(x509))));
  log('X509_get_notAfter');
  writeln('notAfter:'+DateTimeToStr (getTime (X509_get_notAfter (x509))));
  except
  on e:exception do writeln(e.message);
  end;

  end; //for i...

  {
  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509');
  x509:=PEM_read_bio_X509(bp,nil,nil,nil);
  key:=X509_get_pubkey(x509);
  BIO_free(bp);
  }

  //or
  {
  bp := BIO_new(BIO_s_mem);
  log('BN_print');
  BN_print(bp, rsa^.e);
  log('BIO_ReadAnsiString');
  Writeln('BN_print: ',BIO_ReadAnsiString(bp));
  BIO_free(bp);
  }
  //test ok
  {
  ctx := BN_CTX_new();
  p := BN_new();
  BN_hex2bn(p, 'F7E75FDC469067FFDC4E847C51F452DF');
  Writeln('BN_bn2hex: ', strpas(BN_bn2hex(p )));
  }
  //
  result:=true;
end;

function set_password(filename,password:string):boolean;
var
pkey:pEVP_PKEY ;
bp:pBio;
begin
result:=false;
pkey:=LoadPrivateKey (filename);
if pkey=nil then
           begin
           writeln('LoadPrivateKey failed');
           exit;
           end;

  bp := BIO_new_file(pchar(GetCurrentDir+'\'+'new_'+filename), 'w+');
  log('PEM_write_bio_PrivateKey');
  //with or without a password
  if password=''
     then result:=PEM_write_bio_PrivateKey(bp,pkey,nil,nil,0,nil,nil)<>-1
     else result:=PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc,pchar(password),length(password),nil,nil)<>-1;

  BIO_free(bp);

end;

//test...wip
function hextosomething(str:string):boolean;
var
b:pBIGNUM;
p:pointer;
len,i:integer;
begin

  b:=BN_new();
  len:=BN_hex2bn(b,pchar(str));
  if len<=0 then exit;
  getmem(p,len);
  p:=bn_bn2hex(b);
  for i:=1 to len do begin write(chr(byte(p^)));inc(p);end;
  BN_free(b);

end;

function crypt(algo,input:string;keystr:string='';enc:integer=1):boolean;
const EVP_MAX_MD_SIZE=64;
const MD5_DIGEST_LENGTH=16;
      //key:array[0..15] of byte=($11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11);
      //iv:array[0..7] of byte=($22,$22,$22,$22,$22,$22,$22,$22);
var
context:PEVP_CIPHER_CTX=nil ;
cipher :pEVP_CIPHER=nil;
buffer:array [0..EVP_MAX_MD_SIZE -1] of byte;
buffer_len:cardinal=0;
i:byte;
ret,remain:integer;
//
//key:array [0..7] of char;
//iv:array [0..7] of char;
digest:array [0..MD5_DIGEST_LENGTH-1] of byte;
key,iv,encrypted:array of byte;
begin

   result:=false;

   log('input:'+input);
   log('algo:'+algo);

   log('EVP_CIPHER_CTX_new');
   context:=EVP_CIPHER_CTX_new ;

   //cbc requires iv
   //ecb does not require iv
   log('EVP_CIPHER_CTX_init');
   EVP_CIPHER_CTX_init (context);
   //
   //DES uses a key length of 8 bytes (64 bits).
   //DES uses an IV length of 8 bytes (64 bits).
   //Triple DES uses a key length of 24 bytes (192 bits).
   if lowercase(algo)='des_ecb' then cipher := EVP_des_ecb(); //ok
   if lowercase(algo)='des_cbc' then cipher := EVP_des_cbc(); //ok
   //
   if lowercase(algo)='des_ede3_ecb' then cipher := EVP_des_ede3_ecb (); //ok
   if lowercase(algo)='des_ede3_cbc' then cipher := EVP_des_ede3_cbc(); //ok
   //
   if lowercase(algo)='rc4' then cipher := EVP_rc4(); //ok
   if lowercase(algo)='rc2_ecb' then cipher := EVP_rc2_ecb (); //ok

   //The following algorithms will be used based on the size of the key:
   //16 bytes = AES-128
   //24 bytes = AES-192
   //32 bytes = AES-256
   if lowercase(algo)='aes_128_ecb' then cipher := EVP_aes_128_ecb(); //ok
   if lowercase(algo)='aes_192_ecb' then cipher := EVP_aes_192_ecb(); //ok
   if lowercase(algo)='aes_256_ecb' then cipher := EVP_aes_256_ecb(); //ok

   if cipher=nil then exit;

   //lets retrieve some cipher details (key and iv length)
   ret:=EVP_CipherInit_ex(context, cipher, nil, nil, nil,enc);
   if ret<>1 then raise exception.Create ('EVP_CipherInit_ex failed');
   log('key_length:'+inttostr(EVP_CIPHER_CTX_key_length(context)));
   log('iv_length:'+inttostr(EVP_CIPHER_CTX_iv_length(context)));
   log('block_size:'+inttostr(EVP_CIPHER_block_size(cipher)));

   //lets md5 hash our key (which will give us 16 bytes so not fit for all algo's)
   //this is optional : all we need is a 16 bytes buffer acting as a key
   //md5 digest in one go thanks to EVP_Digest
   {
   log('EVP_Digest');
   ret:=EVP_Digest(@key[0],sizeof(key),@digest,buffer_len,evp_md5,nil);
   if ret<>1 then raise exception.Create ('EVP_Digest failed');
   //writeln(buffer_len);
   write('key:');
   for i:=0 to buffer_len -1 do write(inttohex(digest[i],2));
   writeln;
   }

   //a key was supplied
   if keystr<>'' then
   begin
   key:=HexaStringToByte2 (keystr);
   write('key:');
   for i:=0 to length(key) -1 do write(inttohex(key[i],2));
   writeln;
   end;

   //a key was NOT supplied : use a random key with size N (rather than digest md5 hash)
   if (EVP_CIPHER_CTX_key_length(context)>0) and (keystr='') then
   begin
   setlength(key,EVP_CIPHER_CTX_key_length(context));
   RAND_bytes(@key[0],length(key));
   write('key:');
   for i:=0 to length(key) -1 do write(inttohex(key[i],2));
   writeln;
   end;

   //random iv
   if EVP_CIPHER_CTX_iv_length(context)>0 then
   begin
   setlength(iv,EVP_CIPHER_CTX_iv_length(context));
   RAND_bytes(@iv[0],length(iv));
   write('iv:');
   for i:=0 to length(iv) -1 do write(inttohex(iv[i],2));
   writeln;
   end;

   //EVP_CIPHER_CTX_set_key_length(context, length(key)); // RC2 is an algorithm with variable key size. Therefore the key size must generally be set.

   //It should be set to 1 for encryption, 0 for decryption
   log('EVP_CipherInit_ex');
   if pos('_cbc',lowercase(algo))>0
      then ret:=EVP_CipherInit_ex(context, cipher, nil, @key[0], @iv[0],-1)  //or digest for hash
      else ret:=EVP_CipherInit_ex(context, cipher, nil, @key[0], nil,-1); //-1 use the previous value
   if ret<>1 then raise exception.Create ('EVP_CipherInit_ex failed');

   log('EVP_CipherUpdate');
   if enc=0
      then
      begin
      encrypted:=HexaStringToByte2 (input);
      ret:=EVP_CipherUpdate(context,@buffer[0],@buffer_len,@encrypted[0],length(encrypted));
      end
      else ret:=EVP_CipherUpdate(context,@buffer[0],@buffer_len,pansichar(input),length(input));
   if ret<>1 then raise exception.Create ('EVP_CipherUpdate failed');
   //writeln(buffer_len);

   log('EVP_CipherFinal_ex');
   remain:=0;
   ret:=EVP_CipherFinal_ex(context, @buffer[buffer_len], @remain);
   if ret<>1 then raise exception.Create ('EVP_CipherFinal_ex failed');
   inc(buffer_len,remain);
   //writeln(remain);

   log('EVP_CIPHER_CTX_free');
   EVP_CIPHER_CTX_free (context);

   if buffer_len<=0 then exit;
   for i:=0 to buffer_len -1 do write(inttohex(buffer[i],2));
   writeln;

   if enc=0
      then
      begin
      for i:=0 to buffer_len -1 do write(chr(buffer[i]));
      writeln;
      end;

   result:=true;
end;

function hash(algo,input:string):boolean;
const EVP_MAX_MD_SIZE=64;
var
context:pEVP_MD_CTX;
md :pEVP_MD;
digest:array [0..EVP_MAX_MD_SIZE -1] of byte;
digest_len:cardinal=0;
i:byte;
begin
   result:=false;
   context := EVP_MD_CTX_create();
   //if algo='MD2' then md := EVP_md2();
   if uppercase(algo)='MD4' then md := EVP_md4();
   if uppercase(algo)='MD5' then md := EVP_md5();
   if uppercase(algo)='SHA' then md := EVP_sha();
   if uppercase(algo)='SHA1' then md := EVP_sha1();
   if uppercase(algo)='SHA224' then md := EVP_sha224();
   if uppercase(algo)='SHA256' then md := EVP_sha256();
   if uppercase(algo)='SHA384' then md := EVP_sha384();
   if uppercase(algo)='SHA512' then md := EVP_sha256();
   if uppercase(algo)='RIPEMD160' then md := EVP_ripemd160();

   EVP_DigestInit(context,md);
   EVP_DigestUpdate(context, pchar(input), length(input));
   EVP_DigestFinal(context, @digest[0], digest_len);
   EVP_MD_CTX_destroy (context);

   if digest_len<=0 then exit;
   for i:=0 to digest_len -1 do write(inttohex(digest[i],2));
   writeln;
   result:=true;
end;

end.

