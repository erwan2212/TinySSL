unit OpenSSLUtils;

{$mode objfpc}{$H+}

interface

uses
  windows, SysUtils, classes,
  libeay32,utils;

procedure LoadSSL;
procedure FreeSSL;
function generate_rsa_key:boolean;
function mkCAcert(filename:string;cn:string;privatekey:string='';read_password:string=''):boolean;
function mkreq(cn:string;keyfile,csrfile:string):boolean;
function signreq(filename:string;cert:string;read_password:string='';alt:string=''):boolean;
function selfsign(subject:string):boolean;
function Convert2PEM(filename,export_pwd:string):boolean;
function Convert2PKCS12(filename,export_pwd,privatekey,cert:string):boolean;

function EncryptPub(sometext:string;var encrypted:string):boolean;
function DecryptPriv(ACryptedData:string):boolean;

implementation

type
ReadKeyChar = AnsiChar;
//ReadKeyChar = Byte;
PReadKeyChar = ^ReadKeyChar;

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

function LoadPublicKey(KeyFile: string) :pEVP_PKEY ;
var
  mem: pBIO;
  k: pEVP_PKEY;
  rc:integer=0;
begin
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

function LoadPrivateKey(KeyFile: string) :pEVP_PKEY;
var
  mem: pBIO;
  k: pEVP_PKEY;
begin
  k := nil;
  mem := BIO_new(BIO_s_file());
  BIO_read_filename(mem, PAnsiChar(KeyFile));
  try
    log('PEM_read_bio_PrivateKey');
    result := PEM_read_bio_PrivateKey(mem, k, nil, nil);
  finally
    BIO_free_all(mem);
  end;
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

{
Importer une clé publique RSA
Un fichier au format PEM contenant une clé publique RSA
commence par —–BEGIN PUBLIC KEY—–
puis est suivi de la clé en Base64
et se termine par —–END PUBLIC KEY—–.
}
function FromOpenSSLPublicKey(filePath: string): pRSA;
var
  KeyBuffer: PBIO;
  pkey: PEVP_PKEY;
  x: pEVP_PKEY;
begin
  log('FromOpenSSLPublicKey');
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
function FromOpenSSLPrivateKey(filePath: string; pwd: String=''): pRSA;
var
  KeyBuffer: PBio;
  p: PReadKeyChar;
  I: Integer;
  x: pRSA;
begin
  log('FromOpenSSLPrivateKey');
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
function FromOpenSSLCert(filePath: string): pRSA;
var
  KeyBuffer: PBIO;
  FX509: pX509;
  Key: PEVP_PKEY;
  x: pX509;
begin
  log('FromOpenSSLCert');
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

function Convert2PKCS12(filename,export_pwd,privatekey,cert:string):boolean;
var
  err_reason:integer;
  bp:pBIO;
  p12_cert:pPKCS12 = nil;
  pkey:pEVP_PKEY; x509_cert:pX509;
  additional_certs:pSTACK_OFX509 = nil;
begin
  log('Convert2PKCS12');
  bp := BIO_new_file(pchar(privatekey), 'r+');
  log('PEM_read_bio_PrivateKey');
  //password will be prompted
  pkey:=PEM_read_bio_PrivateKey(bp,nil,nil,nil);
  BIO_free(bp);

  bp := BIO_new_file(pchar(cert), 'r+');
  log('PEM_read_bio_X509');
  x509_cert:=PEM_read_bio_X509(bp,nil,nil,nil);
  BIO_free(bp);

  log('PKCS12_new');
  p12_cert := PKCS12_new();
  if p12_cert=nil then exit;


  log('PKCS12_create');
  p12_cert := PKCS12_create(pchar(export_pwd), nil, pkey, x509_cert, nil, 0, 0, 0, 0, 0);
  if p12_cert = nil then exit;

  log('i2d_PKCS12_bio');
  bp := BIO_new_file(pchar(filename), 'w+');
  err_reason:=i2d_PKCS12_bio(bp, p12_cert);
  BIO_free(bp);


  if x509_cert<>nil then X509_free(x509_cert); x509_cert := nil;
  if pkey<>nil then EVP_PKEY_free(pkey); pkey := nil;
  ERR_clear_error();
  PKCS12_free(p12_cert);
  result:=err_reason<>0;
end;

function Convert2PEM(filename,export_pwd:string):boolean;
const
  PKCS12_R_MAC_VERIFY_FAILURE =113;
var
    p12_cert:pPKCS12 = nil;
    pkey:pEVP_PKEY;
    x509_cert:pX509;
    additional_certs:pSTACK_OFX509 = nil;
    bp:pBIO;
    err_reason:integer;
begin
  log('Convert2PEM');
  result:=false;
  bp := BIO_new_file(pchar(filename), 'r+');
  log('d2i_PKCS12_bio');
  //decode
  p12_cert:=d2i_PKCS12_bio(bp, nil);
  log('PKCS12_parse');
  //this is the export password, not the private key password
  err_reason:=PKCS12_parse(p12_cert, pchar(export_pwd), pkey, x509_cert, additional_certs);
  //if err_reason<>0 then
  log(inttostr(err_reason));
  BIO_free(bp);
  if err_reason =0 then exit;

  if p12_cert = nil then exit;


  //
  bp := BIO_new_file(pchar(GetCurrentDir+'\cert.crt'), 'w+');
  log('PEM_write_bio_X509');
  PEM_write_bio_X509(bp,x509_cert);
  BIO_free(bp);
  bp := BIO_new_file(pchar(GetCurrentDir+'\cert.key'), 'w+');
  log('PEM_write_bio_PrivateKey');
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

function selfsign(subject:string):boolean;
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

   bp := BIO_new_file(pchar('cert.key'), 'w+');
  //PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),pchar(''),0,nil,nil);
  //if you want a prompt for passphrase
  log('PEM_write_bio_PrivateKey');
  PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);
  BIO_free(bp);

  bp := BIO_new_file(pchar('cert.crt'), 'w+');
  log('PEM_write_bio_X509');
  PEM_write_bio_X509(bp,x);
  BIO_free(bp);

   result:=x<>nil;

   if (x<>nil) then X509_free(x);
   if (pkey<>nil) then EVP_PKEY_free(pkey);

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

//the private key of the resulting cert is the request.key
function signreq(filename:string;cert:string;read_password:string='';alt:string=''):boolean;
const
   LN_commonName=                   'commonName';
   //NID_commonName=                  13;
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
label free_all;
begin
  result:=false;
  // load ca
  bp := BIO_new_file(pchar(cert), 'r+');
  log('PEM_read_bio_X509');
  x509_ca:=PEM_read_bio_X509(bp,nil,nil,nil);
  BIO_free(bp);
  if x509_ca=nil then goto free_all;
  //loadCAPrivateKey
  {
  bp := BIO_new_file(pchar('ca.key'), 'r+');
  log('PEM_read_bio_RSAPrivateKey');
  rsa:=PEM_read_bio_RSAPrivateKey   (bp,nil,nil,nil);
  BIO_free(bp);
  }
  rsa:=FromOpenSSLPrivateKey(ChangeFileExt (cert,'.key'),read_password);
  if rsa=nil then goto free_all;
  //
  log('EVP_PKEY_new');
  pkey := EVP_PKEY_new();
  log('EVP_PKEY_assign_RSA');
  EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
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
  log('X509_set_subject_name');
  X509_set_subject_name(x509_cert, X509_REQ_get_subject_name(X509_REQ));
  //X509_NAME_add_entry_by_NID(X509_get_subject_name(X509_cert), NID_pkcs9_emailAddress, MBSTRING_ASC, pchar('me@domain.com'), -1, -1, 0);
  // set pubkey from req
  pktmp := X509_REQ_get_pubkey(X509_REQ);
  log('X509_set_pubkey');
  ret := X509_set_pubkey(x509_cert, pktmp);
  EVP_PKEY_free(pktmp);
  //

  //add_ext(x509_cert, NID_basic_constraints, 'critical,CA:false');
  //add_ext(x509_cert, NID_key_usage, 'critical,digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment');
  //add_ext(x509_cert, NID_authority_key_identifier, 'keyid:always,issuer:always');
  //add_ext(x509_cert, NID_subject_key_identifier, 'hash');
  if alt<>'' then add_ext(x509_cert, NID_subject_alt_name,pchar(alt)); //'DNS:localhost'

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
  //
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
function mkCAcert(filename:string;cn:string;privatekey:string='';read_password:string=''):boolean;
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
begin
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
  end
  else
  begin
  log('Reusing '+privatekey+'...',1);
  //pkey:=LoadPrivateKey(privatekey);
  //if pkey=nil then begin log('pkey is nul');exit;end;
  try
  rsa:=FromOpenSSLPrivateKey(privatekey,read_password); //password will be prompted
  if rsa=nil then raise exception.Create ('rsa is null');
  except
  on e:exception do begin log(e.message,1);exit;end;
  end; //try
  end;
//generate key
//OpenSSL provides the EVP_PKEY structure for storing an algorithm-independent private key in memory
log('EVP_PKEY_new');
pkey := EVP_PKEY_new();
//assign key to our struct
log('EVP_PKEY_assign_RSA');
EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
//Writeln('BN_bn2hex: ', strpas(BN_bn2hex(rsa^.n )));
{
bp := BIO_new(BIO_s_mem);
log('BN_print');
BN_print(bp, pkey^.pkey.rsa^.n);
log('BIO_ReadAnsiString');
Writeln('BN_print: ',BIO_ReadAnsiString(bp));
}
//OpenSSL uses the X509 structure to represent an x509 certificate in memory
log('X509_new');
x509 := X509_new();
//Now we need to set a few properties of the certificate
ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
//
X509_gmtime_adj(X509_get_notBefore(x509), 0);
X509_gmtime_adj(X509_get_notAfter(x509), days);
//Now we need to set the public key for our certificate using the key we generated earlier
log('X509_set_pubkey');
X509_set_pubkey(x509, pkey);
//Since this is a self-signed certificate, we set the name of the issuer to the name of the subject
log('X509_get_subject_name');
name := X509_get_subject_name(x509);
//X509_NAME_add_entry_by_txt(name, 'C',  MBSTRING_ASC,pchar('FR'), -1, -1, 0);
//X509_NAME_add_entry_by_txt(name, 'O',  MBSTRING_ASC,pchar('MyCompany Inc.'), -1, -1, 0);
X509_NAME_add_entry_by_txt(name, 'CN', MBSTRING_ASC,pchar(cn), -1, -1, 0);
//Now we can actually set the issuer name:
log('X509_set_issuer_name');
X509_set_issuer_name(x509, name);
{
bc:=BASIC_CONSTRAINTS_new;
bc^.ca :=1;
X509_add1_ext_i2d(x509, NID_basic_constraints,bc,1,0 ); //'critical,CA:TRUE'
}

//add_ext(x509, NID_basic_constraints, 'critical,CA:TRUE');
//add_ext(x509, NID_key_usage, 'critical,keyCertSign,cRLSign');
//add_ext(x509, NID_subject_key_identifier, 'hash');
//add_ext(x509, NID_authority_key_identifier, 'keyid:always,issuer:always');

//And finally we are ready to perform the signing process. We call X509_sign with the key we generated earlier. The code for this is painfully simple:
log('X509_sign');
X509_sign(x509, pkey, EVP_sha256());

//write out to disk
//if we loaded an existing private key, we could skip the below
if privatekey='' then
begin
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+ChangeFileExt (filename,'.key')), 'w+');
  //PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),pchar(''),0,nil,nil);
  //if you want a prompt for passphrase
  log('PEM_write_bio_PrivateKey');
  ret:= PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);
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
//
EVP_PKEY_free(pkey);
X509_free(x509);
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
    end
    else
    begin
    log('Reusing '+keyfile+'...',1);
    //pkey:=LoadPrivateKey(privatekey);
    //if pkey=nil then begin log('pkey is nul');exit;end;
    rsa:=FromOpenSSLPrivateKey(keyfile,''); //password will be prompted
    end;

        //we loaded the file, no need to save it again
        if keyfile='' then
        begin
        bp := BIO_new_file(pchar(GetCurrentDir+'\'+keyfile), 'w+');
        //the private key will have no password
        log('PEM_write_bio_RSAPrivateKey');
        log('no password...');
        ret := PEM_write_bio_RSAPrivateKey(bp, rsa, nil, nil, 0, nil, nil);
	BIO_free(bp);
        end;

        log('X509_REQ_new');
	req := X509_REQ_new();

	if req=nil then exit;

        log('EVP_PKEY_new');
	key := EVP_PKEY_new();
        log('EVP_PKEY_assign');
	EVP_PKEY_assign(key,EVP_PKEY_RSA,PCharacter(rsa));
        //
	X509_REQ_set_version(req, 0);
	X509_REQ_set_pubkey(req, key);

        log('X509_REQ_get_subject_name');
	name := X509_NAME_new; //X509_REQ_get_subject_name(req);
        log('X509_NAME_add_entry_by_txt');
	X509_NAME_add_entry_by_txt(name, 'CN', MBSTRING_ASC,pchar(cn), -1, -1, 0);
        log('X509_REQ_set_subject_name');
        ret:=X509_REQ_set_subject_name(Req, name); //since X509_REQ_get_subject_name(req) failed on me
        X509_NAME_free(name);

        //add extensions?

        log('X509_REQ_sign');
	X509_REQ_sign(req, key, EVP_sha256());

	EVP_PKEY_free(key);

        bp := BIO_new_file(pchar(GetCurrentDir+'\'+csrfile), 'w+');
        log('PEM_write_bio_X509_REQ');
        PEM_write_bio_X509_REQ(bp, req);
	BIO_free(bp);

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


	// 2. save public key
	bp_public := BIO_new_file(pchar(GetCurrentDir+'\public.pem'), 'w+');
	//ret := PEM_write_bio_RSAPublicKey(bp_public, rsa);
        log('EVP_PKEY_new');
        pkey := EVP_PKEY_new();
        log('EVP_PKEY_assign_RSA');
        EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
        log('2. save public key OK');
        ret:=PEM_write_bio_PUBKEY (bp_public ,pkey);
	if ret <>1 then goto free_all;

	// 3. save private key
	bp_private := BIO_new_file(pchar(GetCurrentDir+'\private.pem'), 'w+');
        //the private key will have no password
        log('3. save private key');
        log('no password...');
	ret := PEM_write_bio_RSAPrivateKey(bp_private, rsa, nil, nil, 0, nil, nil);

	// 4. free
free_all:

	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(rsa);
	BN_free(bne);

	if ret=1 then result:=true else result:=false;
end;

//RSA_public_encrypt, RSA_private_decrypt - RSA public key cryptography
//versus
//RSA_private_encrypt, RSA_public_decrypt - low-level signature operations ... using the private key rsa
function EncryptPub(sometext:string;var encrypted:string):boolean;
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
function DecryptPriv(ACryptedData:string):boolean;
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
        log(inttostr(size));
	GetMem(data, size);  // Определяем размер выходному буферу дешифрованной строки
	GetMem(str, size); // Определяем размер шифрованному буферу после конвертации из base64

	//Decode base64
	b64 := BIO_new(BIO_f_base64);
	mem := BIO_new_mem_buf(PAnsiChar(ACryptedData), Length(ACryptedData));
	BIO_flush(mem);
	mem := BIO_push(b64, mem);
	BIO_read(mem, str , Length(ACryptedData)); // Получаем шифрованную строку в бинарном виде
	BIO_free_all(mem);
	// Дешифрование
        log('RSA_private_decrypt');
	len := RSA_private_decrypt(size, PCharacter(str), PCharacter(data), rsa, RSA_PKCS1_PADDING);
        log(inttostr(len));
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

end.

