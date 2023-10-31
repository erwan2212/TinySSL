# TinySSL
<br/>
TinySSL, aka playing with openssl library (libeay32).<br/>
<br/>
--cn=<string>           cn<br/>
--alt=<string>          alternate name<br/>
--ca=<string>           true|false (default: false)<br/>
--password=<string>     password<br/>
--privatekey=<string>   path to a privatekey file<br/>
--publickey=<string>    path to a publickey file, not needed if you have the privatekey<br/>
--cert=<string>         path to a certificate<br/>
--debug=<string>        true|false (default: false)<br/>
--filename=<string>     local filename<br/>
--print_cert            print cert details<br/>
--print_private         print cert details<br/>
--genkey                generate rsa keys public.pem and private.pem<br/>
--encrypt               encrypt a file using public.pem, read from filename<br/>
--decrypt               decrypt a file using private.pem, read from filename<br/>
--mkcert                make a self sign root cert, read from privatekey (option) & write to filename.crt and<br/>
                        filename.key<br/>
--mkreq                 make a certificate service request, read from privatekey & write to filename.csr<br/>
                        filename.key (if privatekey not specified)<br/>
--signreq               make a certificate from a csr, read from filename and cert, write to filename.crt<br/>
--dertopem              convert a binary/der private key or cert to base 64 pem format, read from cert or<br/>
                        privatekey, write to cert.crt or privatekey.key<br/>
--pemtoder              convert a base 64 pem format to binary/der private key or cert, read from cert or<br/>
                        privatekey, write to cert.der or privatekey.der<br/>
--p12topem              convert a pfx to pem, read from filename, write to filename.crt and filename.key<br/>
--pemtop12              convert a pem to pfx, read from cert and privatekey, write to filename<br/>
--p7topem               convert a p7b to pem, read from cert, write to cert.crt<br/>
--pemtop7               convert a pem to p7b, read from cert, write to cert.p7b<br/>
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
