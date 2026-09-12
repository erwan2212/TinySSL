program PubKeyToSSH;

uses
  SysUtils, openssl, opensslbio, opensslpem, opensslrsa, opensslevp, opensslbn;

function BN_bn2binpad(a: PBIGNUM; to_: PByte; tolen: Integer): Integer; cdecl; external LIBEAY_NAME;
function BN_num_bytes(a: PBIGNUM): Integer; cdecl; external LIBEAY_NAME;

procedure PrintSSHKey(pubkey: PEVP_PKEY);
var
  rsa: PRSA;
  n, e: PBIGNUM;
  bio_mem: PBIO;
  key_buf: array[0..4095] of Char;
  key_len, len: Integer;
  buf: TBytes;
begin
  rsa := EVP_PKEY_get0_RSA(pubkey);
  if rsa = nil then
  begin
    WriteLn('Public key is not RSA');
    Exit;
  end;

  // Get modulus and exponent
  n := RSA_get0_n(rsa);
  e := RSA_get0_e(rsa);

  // Allocate buffer for modulus and exponent
  SetLength(buf, BN_num_bytes(n) + BN_num_bytes(e) + 2 * SizeOf(Integer));

  // Write exponent
  len := htonl(BN_num_bytes(e));
  Move(len, buf[0], SizeOf(Integer));
  key_len := SizeOf(Integer);
  key_len := key_len + BN_bn2binpad(e, @buf[key_len], BN_num_bytes(e));

  // Write modulus
  len := htonl(BN_num_bytes(n));
  Move(len, buf[key_len], SizeOf(Integer));
  key_len := key_len + SizeOf(Integer);
  key_len := key_len + BN_bn2binpad(n, @buf[key_len], BN_num_bytes(n));

  // Base64 encode
  bio_mem := BIO_new(BIO_s_mem());
  BIO_write(bio_mem, @buf[0], key_len);
  BIO_flush(bio_mem);

  key_len := BIO_read(bio_mem, @key_buf[0], SizeOf(key_buf) - 1);
  if key_len > 0 then
  begin
    key_buf[key_len] := #0;
    WriteLn('ssh-rsa ', key_buf);
  end
  else
    WriteLn('Error reading from BIO');

  BIO_free_all(bio_mem);
end;

var
  pemFile: String;
  certFile: PFile;
  cert: PX509;
  pubkey: PEVP_PKEY;
begin
  if ParamCount < 1 then
  begin
    WriteLn('Usage: ', ParamStr(0), ' <pem_file>');
    Exit;
  end;

  pemFile := ParamStr(1);
  certFile := fopen(PAnsiChar(AnsiString(pemFile)), 'r');
  if certFile = nil then
  begin
    WriteLn('Unable to open file');
    Exit;
  end;

  cert := PEM_read_X509(certFile, nil, nil, nil);
  if cert = nil then
  begin
    WriteLn('Unable to read certificate');
    fclose(certFile);
    Exit;
  end;
  fclose(certFile);

  pubkey := X509_get_pubkey(cert);
  if pubkey = nil then
  begin
    WriteLn('Unable to extract public key');
    X509_free(cert);
    Exit;
  end;

  PrintSSHKey(pubkey);

  EVP_PKEY_free(pubkey);
  X509_free(cert);
end.
