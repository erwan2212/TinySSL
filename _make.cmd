rem if you want to reuse an existing key and therefore renew instead of recreate
tinySSL.exe --mkcert --debug=true --privatekey=ca.key --password=password --filename=ca.crt
rem recreate, not renew
rem tinySSL.exe --mkcert --debug=true --filename=ca.crt
rem renew, not recreate
tinySSL.exe --mkreq --debug=true --filename=request.csr --privatekey=request.key
rem recreate, not renew
rem tinySSL.exe --mkreq --debug=true --filename=request.csr
tinySSL.exe --signreq --debug=true --alt="DNS:*.groupe.fr" --password=password --filename=request.csr --cert=ca.crt