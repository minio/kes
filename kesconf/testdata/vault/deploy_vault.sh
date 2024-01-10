#!/usr/bin/env bash

echo "${GITHUB_WORKSPACE=~/kes}"

function main() {
	# Initialize setup
	init_setup

	# Install HashiCorp vault
	install_vault

	# Install latest KES binary for cert etc
	install_kes

	# Setup vault
	setup_vault
}

function init_setup() {
	echo ""
	echo "Initialize setup....."
	echo ""
	apt update -y || sudo apt update -y
	apt upgrade -y || sudo apt upgrade -y
	apt install wget unzip || sudo apt install wget unzip
	sudo chmod a+x /usr/local/bin/yq
        wget https://releases.hashicorp.com/vault/1.15.2/vault_1.15.2_linux_amd64.zip

	rm -rf /vault/file || sudo rm -rf /vault/file
	pkill -9 vault || sudo pkill -9 vault
	rm -f client.crt client.key private.key public.crt vault.crt vault.key
}

function install_vault() {
	echo ""
	echo "Installing HashiCorp vault....."
	echo ""
	sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
        unzip vault_1.15.2_linux_amd64.zip
        chmod +x vault
        mv vault /usr/local/bin || sudo mv vault /usr/local/bin
        vault --version
	rm -f vault_1.15.2_linux_amd64.zip
}

function install_kes() {
	echo ""
	echo "Installing latest KES binary for certificate etc....."
	echo ""
	wget -O kes https://github.com/minio/kes/releases/latest/download/kes-linux-amd64
	chmod +x kes
	mv kes /usr/local/bin/kes || sudo mv kes /usr/local/bin/kes
	kes --version
}

function setup_vault() {
	# Create vault certs
	kes identity new --key vault.key --cert vault.crt --ip "127.0.0.1" localhost
	mkdir -p /vault/file

	# Start vaule server
	vault server -config "${GITHUB_WORKSPACE}"/kesconf/testdata/vault/vault-config.json &

	# Generate certs for KES
	kes identity new --ip "127.0.0.1" localhost --cert public.crt --key private.key

	# Generate certs for client application (to be used by test)
	kes identity new --key=client.key --cert=client.crt MyApp

	client_id=$(kes identity of client.crt | awk '{print $1}')
	id="${client_id}" yq e -i '.policy.my-app.identities += [strenv(id)] | ..style="double"' "${GITHUB_WORKSPACE}"/kesconf/testdata/vault/kes-config-vault.yml

	export VAULT_ADDR='https://127.0.0.1:8200'
	export VAULT_SKIP_VERIFY=true
	init_output=$(vault operator init)
	vault_token=$(echo "$init_output" | grep "Initial Root Token:" | awk -F":" '{print $2}' | xargs)
	unseal_key1=$(echo "$init_output" | grep "Unseal Key 1:" | awk -F":" '{print $2}' | xargs)
	unseal_key2=$(echo "$init_output" | grep "Unseal Key 2:" | awk -F":" '{print $2}' | xargs)
	unseal_key3=$(echo "$init_output" | grep "Unseal Key 3:" | awk -F":" '{print $2}' | xargs)
	export VAULT_TOKEN=${vault_token}
	vault operator unseal "${unseal_key1}"
	vault operator unseal "${unseal_key2}"
	vault operator unseal "${unseal_key3}"
	vault secrets enable -version=1 kv
	vault secrets enable transit
	vault write -f transit/keys/my-key
	vault policy write kes-policy kes-policy.hcl
	vault auth enable approle
	vault write auth/approle/role/kes-server token_num_uses=0 secret_id_num_uses=0 period=5m
	vault write auth/approle/role/kes-server policies=kes-policy
	roleid_output=$(vault read auth/approle/role/kes-server/role-id)
	role_id=$(echo "$roleid_output" | grep "role_id" | awk -F" " '{print $2}')
	secretid_output=$(vault write -f auth/approle/role/kes-server/secret-id)
	secret_id=$(echo "$secretid_output" | grep "secret_id " | awk -F" " '{print $2}')
	rlid="${role_id}" yq e -i '.keystore.vault.approle.id = strenv(rlid) | ..style="double"' "${GITHUB_WORKSPACE}"/kesconf/testdata/vault/kes-config-vault.yml
	sid="${secret_id}" yq e -i '.keystore.vault.approle.secret = strenv(sid) | ..style="double"' "${GITHUB_WORKSPACE}"/kesconf/testdata/vault/kes-config-vault.yml
	kes_private_key="${GITHUB_WORKSPACE}"/kesconf/testdata/vault/private.key
	kes_public_cert="${GITHUB_WORKSPACE}"/kesconf/testdata/vault/public.crt
	vault_public_cert="${GITHUB_WORKSPACE}"/kesconf/testdata/vault/vault.crt
	kes_key="${kes_private_key}" yq e -i '.tls.key = strenv(kes_key)' "${GITHUB_WORKSPACE}"/kesconf/testdata/vault/kes-config-vault.yml
	kes_cert="${kes_public_cert}" yq e -i '.tls.cert = strenv(kes_cert)' "${GITHUB_WORKSPACE}"/kesconf/testdata/vault/kes-config-vault.yml
	vault_cert="${vault_public_cert}" yq e -i '.keystore.vault.tls.ca = strenv(vault_cert)' "${GITHUB_WORKSPACE}"/kesconf/testdata/vault/kes-config-vault.yml
}

main "$@"
