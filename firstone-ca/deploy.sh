#!/bin/bash
path=`pwd`

docker build -t chainmaker-ca:v2.2.0 .

echo "start mysql service..."
docker run -d \
    -p 13306:3306 \
    -e MYSQL_ROOT_PASSWORD=123456 \
    -e MYSQL_DATABASE=chainmaker_ca \
    --name ca-mysql \
    --restart always \
    mysql:8.0
echo "waiting for database initialization..."
sleep 20s
docker logs --tail=10 ca-mysql

echo "start ca services..."
docker run -d \
-p 8096:8090 \
-w /chainmaker-ca \
-v $path/src/conf:/chainmaker-ca/conf \
-v $path/log:/log \
-v $path/crypto-config:/crypto-config \
-v $path/sansec-pkcs11/pkcs11:/usr/local/lib64/pkcs11 \
-v $path/sansec-pkcs11/etc:/etc \
--name ca-server \
--restart always \
chainmaker-ca:v2.2.0 \
bash -c "./chainmaker-ca -config ./conf/config.yaml"
sleep 2s
docker logs ca-server
echo "chainmaker-ca server start!"
