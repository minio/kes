#!/bin/bash

go build ./cmd/kes/...

./kes identity new --key=admin.key --cert=admin.crt admin --force
./kes identity new --key=client.key --cert=client.crt client --force
./kes identity new --key private.key --cert public.crt --ip "127.0.0.1" localhost --force

export KES_UNSEAL_KEY=$(cat /dev/urandom | head -c 32 | base64)

echo "version: v1" > ./init.yml
echo "address: 0.0.0.0:7373" >> ./init.yml
echo "tls:" >> ./init.yml
echo "  key: private.key" >> ./init.yml
echo "  cert: public.crt" >> ./init.yml
echo "  client:" >> ./init.yml
echo "    verify_cert: false" >> ./init.yml
echo "system:" >> ./init.yml
echo "  admin:" >> ./init.yml
echo "    identity: $(./kes identity of admin.crt)" >> ./init.yml
echo "unseal:" >> ./init.yml
echo "  environment:" >> ./init.yml
echo "    name: KES_UNSEAL_KEY" >> ./init.yml
echo "enclave:" >> ./init.yml
echo "  default:" >> ./init.yml
echo "    admin:" >> ./init.yml
echo "      identity: $(./kes identity of client.crt)" >> ./init.yml
echo "    policy:" >> ./init.yml
echo "      minio:" >> ./init.yml
echo "        allow:" >> ./init.yml
echo "        - /v1/api" >> ./init.yml
echo "        - /v1/metrics" >> ./init.yml
echo "        - /v1/key/list/*" >> ./init.yml
echo "        - /v1/key/create/*" >> ./init.yml
echo "        - /v1/key/import/*" >> ./init.yml
echo "        - /v1/key/delete/*" >> ./init.yml
echo "        - /v1/key/generate/*" >> ./init.yml
echo "        - /v1/key/decrypt/*" >> ./init.yml
echo "        - /v1/policy/list/*" >> ./init.yml
echo "        - /v1/policy/assign/*" >> ./init.yml
echo "        - /v1/policy/write/*" >> ./init.yml
echo "        - /v1/policy/describe/*" >> ./init.yml
echo "        - /v1/policy/read/*" >> ./init.yml
echo "        - /v1/policy/delete/*" >> ./init.yml
echo "        - /v1/identity/list/*" >> ./init.yml
echo "        - /v1/identity/describe/*" >> ./init.yml
echo "        - /v1/identity/delete/*" >> ./init.yml

./kes init --config init.yml ./data --force
./kes server ./data --auth=off &
KES_PID=$!
./kes ui &
KES_UI_PID=$!

go test ./restapi/integration/...

rm kes admin.key admin.crt client.key client.crt private.key public.crt init.yml

kill -9 $KES_PID
kill -9 $KES_UI_PID
