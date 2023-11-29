path "transit/encrypt/my-key" {
   capabilities = [ "update" ]
}
path "transit/decrypt/my-key" {
   capabilities = [ "update" ]
}
path "kv/*" {
   capabilities = [ "create", "read", "delete", "list" ]
}
