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

	rm -rf /tmp/vault/file || sudo rm -rf /tmp/vault/file
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
	echo "==================================================================================="
	echo "Run: kes identity new --key vault.key --cert vault.crt --ip \"127.0.0.1\" localhost"
	echo ""
	kes identity new --key vault.key --cert vault.crt --ip "127.0.0.1" localhost
	realpath vault.key
	realpath vault.crt
	mkdir -p /tmp/vault/file || sudo mkdir -p /tmp/vault/file
	echo ""

	# Start vault server
	echo "========================="
	echo "Starting vault server...."
	echo "Run: vault server -config \"${GITHUB_WORKSPACE}\"/kesconf/testdata/vault/vault-config.json &"
	vault server -config "${GITHUB_WORKSPACE}"/kesconf/testdata/vault/vault-config.json &
	ps -ef | grep vault
	echo ""

	export VAULT_ADDR='https://127.0.0.1:8200'
	export VAULT_SKIP_VERIFY=true
	export KES_API_KEY=kes:v1:AP6gQlUXjWj5iY1WkqeXKIR0OXTpyoiHa81XTY7ISy3l
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
	export VAULT_APPROLE_ID="${role_id}"
	export VAULT_APPROLE_SECRET="${secret_id}"
	vault_public_cert="${GITHUB_WORKSPACE}"/vault.crt
	vault_cert="${vault_public_cert}" yq e -i '.keystore.vault.tls.ca = strenv(vault_cert)' "${GITHUB_WORKSPACE}"/kesconf/testdata/vault/kes-config-vault.yml

	echo "=============================================================================="
	echo "Content of \"${GITHUB_WORKSPACE}\"/kesconf/testdata/vault/kes-config-vault.yml"
	cat "${GITHUB_WORKSPACE}"/kesconf/testdata/vault/kes-config-vault.yml
	echo ""

	cat > env.sh <<EOF
#!/usr/bin/env bash

export KES_API_KEY=kes:v1:AP6gQlUXjWj5iY1WkqeXKIR0OXTpyoiHa81XTY7ISy3l
export VAULT_APPROLE_ID=${role_id}
export VAULT_APPROLE_SECRET=${secret_id}
EOF
	cat env.sh
}

main "$@"
