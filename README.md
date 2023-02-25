# TinySSL
<br/>
TinySSL, aka playing with openssl library (libeay32).<br/>
--genkey                generate rsa keys public.pem and private.pem<br/>
--encrypt               encrypt a file using public.pem<br/>
--decrypt               decrypt a file using private.pem<br/>
--mkcert                make a self sign root cert, read from privatekey (option) & write to ca.crt and ca.key<br/>
--mkreq                 make a certificate service request, read from request.key (if exist) & write to request.csr request.key<br/>
--signreq               make a certificate from a csr, read from a csr filename and a cert file<br/>
--selfsign              make a self sign cert, write to cert.crt cert.key<br/>
--p12topem              convert a pfx to pem, write to cert.crt and cert.key<br/>
--pemtop12              convert a pem to pfx, read from cert.crt and cert.key<br/>
<br/><br/>
Example : create a root ca (reusing a previous key), create a csr (reusing a previous key) and generate a certificate (that will work in latest chrome).<br/>
<br/><br/>
rem if you want to reuse an existing key and therefore renew instead of recreate<br/>
tinySSL.exe --mkcert --debug=true --privatekey=ca.key --password=password --filename=ca.crt<br/>
rem recreate, not renew<br/>
rem tinySSL.exe --mkcert --debug=true --filename=ca.crt<br/>
rem renew, not recreate<br/>
tinySSL.exe --mkreq --debug=true --filename=request.csr --privatekey=request.key<br/>
rem recreate, not renew<br/>
rem tinySSL.exe --mkreq --debug=true --filename=request.csr<br/>
tinySSL.exe --signreq --debug=true --alt="DNS:*.groupe.fr" --password=password --filename=request.csr --cert=ca.crt<br/>
