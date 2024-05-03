#!/bin/bash
RESOURCE_GROUP=minio-kes
SERVICE_PRINCIPAL=minio-kes
LOCATION=westus

AZ_SUBSCRIPTION_NAME=$(az account show -o tsv --query 'name')
AZ_SUBSCRIPTION_ID=$(az account show -o tsv --query 'id')
echo "Running in subscription '$AZ_SUBSCRIPTION_NAME' ($AZ_SUBSCRIPTION_ID)"

# Create the resource-group (if not exists)
AZ_RESOURCE_GROUP=$(az group show --resource-group $RESOURCE_GROUP 2>/dev/null || echo -n)
if [ -z "$AZ_RESOURCE_GROUP" ]; then
    echo "Creating resource group '$RESOURCE_GROUP'"
    AZ_RESOURCE_GROUP=$(az group create --resource-group $RESOURCE_GROUP -l $LOCATION || echo -n)
else
    echo "Using resource group '$RESOURCE_GROUP'"
fi

# Create a random key-vault-name (should be globally unique)
KEYVAULT_NAME=$(az keyvault list -g $RESOURCE_GROUP --query '[0].name' -o tsv 2>/dev/null || echo -n)
if [ -z "$KEYVAULT_NAME" ]; then
    KEYVAULT_NAME=minio-kes-$(tr -dc a-z </dev/urandom | head -c 6)
    echo "Creating key-vault '$KEYVAULT_NAME'"
    az keyvault create -g $RESOURCE_GROUP -l $LOCATION -n $KEYVAULT_NAME --enable-rbac-authorization true > /dev/null
else
    echo "Using existing key-vault '$KEYVAULT_NAME'"
fi

# Add admin privileges to the keyvault
IAM_ID=$(az ad signed-in-user show --query 'id' -o tsv)
VAULT_ID=$(az keyvault show -g $RESOURCE_GROUP -n $KEYVAULT_NAME --query 'id' -o tsv)
az role assignment create --role "Key Vault Administrator" --scope $VAULT_ID --assignee $IAM_ID > /dev/null

# Show command to run
VAULT_URI=$(az keyvault show -g $RESOURCE_GROUP -n $KEYVAULT_NAME --query 'properties.vaultUri' -o tsv)
echo "Run: EndPoint=$VAULT_URI go test ."
