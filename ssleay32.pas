unit ssleay32;

{$mode delphi}{$H+}

interface

uses
    windows,sysutils,winsock,
    opensslutils,libeay32,
    utils;

var

 TLSv1_2_method:function():pointer;cdecl=nil;
 SSLv23_method:function():pointer;cdecl=nil;
 SSL_CTX_new:function(const method:pointer):pointer;cdecl=nil;
 SSL_new:function(ssl: pointer):pointer;cdecl=nil;
 SSL_set_fd:function(ssl:pointer;fd:integer):integer;cdecl=nil;
 SSL_connect:function(ssl: pointer):integer;cdecl=nil;
 SSL_get_peer_certificate:function(const ssl:pointer):px509;cdecl=nil;
 SSL_shutdown:function(ssl: pointer):integer;cdecl=nil;
 SSL_free:procedure(ssl: pointer);cdecl=nil;
 SSL_library_init:function():integer;cdecl=nil;

 procedure s_client(host:string);

implementation

function init_socket(host:string;port:dword;var sock_:tsocket):boolean;
var
wsadata:TWSADATA;
err:longint;
hostaddr:u_long;
sin:sockaddr_in;
HostEnt:PHostEnt;
begin
  result:=false;
  //
  err := WSAStartup(MAKEWORD(2, 0), wsadata);
  if(err <> 0) then raise exception.Create ('WSAStartup failed with error: '+inttostr(err));
  //
  hostaddr := inet_addr(pchar(host));
  //not an ip? lets try to resolve hostname
  if hostaddr = INADDR_NONE then
    begin
    HostEnt:=gethostbyname(pchar(host));
    if HostEnt <> nil then hostaddr:=Integer(Pointer(HostEnt^.h_addr^)^);
    end;
  //
  //
  sock_ := socket(AF_INET, SOCK_STREAM, 0);
  //
  sin.sin_family := AF_INET;
  sin.sin_port := htons(port);
  sin.sin_addr.s_addr := hostaddr;
  if connect(sock_, tsockaddr(sin), sizeof(sockaddr_in)) <> 0
     then raise exception.Create ('failed to connect');
  //
  result:=true;

end;

procedure s_client(host:string);
var
sock:tsocket;
err:cardinal;
ssl:pointer=nil; //PSSL;
ctx:pointer=nil;
server_cert:PX509=nil;
str:pchar;
name:pX509_NAME=nil;
begin

   log('SSL_library_init');
   SSL_library_init;

   //OpenSSL_add_all_algorithms();
   //SSL_load_error_strings();

   log('SSL_CTX_new');
   ctx:=SSL_CTX_new(TLSv1_2_method );
   if ctx=nil then exit;

   log('SSL_new');
   ssl := SSL_new (ctx);
   if ssl =nil then exit;

   log('init_socket');
   init_socket (host,443,sock);

   log('SSL_set_fd');
   SSL_set_fd (ssl, sock);

   log('SSL_connect');
   err := SSL_connect (ssl);
   //if (err < 0) ...
   //writeln ('SSL connection using ' + SSL_get_cipher (ssl));

   log('SSL_get_peer_certificate');
   server_cert := SSL_get_peer_certificate (ssl);

   //
     log('X509_get_subject_name');
     NAME:=X509_get_subject_name(server_cert);
     writeln('subject_name:'+getdn(name));
     //
     //
     log('X509_get_issuer_name');
     NAME:=X509_get_issuer_name(server_cert);
     writeln('issuer_name:'+getdn(name));
     //

     try
       log('X509_get_notBefore');
       writeln('notBefore:'+DateTimeToStr (getTime (X509_get_notBefore(server_cert))));
       log('X509_get_notAfter');
       writeln('notAfter:'+DateTimeToStr (getTime (X509_get_notAfter (server_cert))));
       except
       on e:exception do writeln(e.message);
       end;

     SSL_shutdown (ssl);
     SSL_free (ssl);
     closesocket (sock);
end;

function initAPI:boolean;
  var
  lib:hmodule=0;
  buffer:array[0..10] of byte;
  begin
  log('initapi');
  result:=false;
  try
  //lib:=0;
  if lib>0 then begin {log('lib<>0');} result:=true; exit;end;
      {$IFDEF win64}lib:=loadlibrary('ssleay32.dll');{$endif}
      {$IFDEF win32}lib:=loadlibrary('ssleay32.dll');{$endif}
  if lib<=0 then
    begin
    log('could not loadlibrary ssleay32.dll');
    exit;
    end;

 //log('GetProcAddress');
 TLSv1_2_method:=GetProcAddress(lib,'TLSv1_2_method');
 SSLv23_method:=GetProcAddress(lib,'SSLv23_method');
 SSL_CTX_new:=GetProcAddress(lib,'SSL_CTX_new');
 SSL_new:=GetProcAddress(lib,'SSL_new');
 SSL_set_fd:=GetProcAddress(lib,'SSL_set_fd');
 SSL_connect:=GetProcAddress(lib,'SSL_connect');
 SSL_get_peer_certificate:=GetProcAddress(lib,'SSL_get_peer_certificate');
 SSL_shutdown:=GetProcAddress(lib,'SSL_shutdown');
 SSL_free:=GetProcAddress(lib,'SSL_free');
 SSL_library_init:=GetProcAddress(lib,'SSL_library_init');

  result:=true;
  except
  //on e:exception do writeln('init error:'+e.message);
     log('init error');
  end;

  end;

initialization
initapi;



end.

