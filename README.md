# TinySSL

TinySSL, aka playsing with openssl library (libeay32).<br/>
--genkey                generate rsa keys public.pem and private.pem<br/>
--encrypt               encrypt a file using public.pem<br/>
--decrypt               decrypt a file using private.pem<br/>
--mkcert                make a self sign root cert, read from privatekey (option) & write to ca.crt and ca.key<br/>
--mkreq                 make a certificate service request, read from request.csr (if exist) & write to request.csr request.key<br/>
--signreq               make a certificate from a csr, read from request.csr ca.crt ca.key<br/>
--selfsign              make a self sign cert, write to cert.crt cert.key<br/>
--p12topem              convert a pfx to pem, write to cert.crt and cert.key<br/>
--pemtop12              convert a pem to pfx, read from cert.crt and cert.key<br/>
<br/><br/>
