# Release versioning

KES server is released with time based version tags, similar to MinIO server.

To get the release name in the appropriate format, run the following with the code checked out at the desired revision:

```shell
TZ=UTC0 git show --quiet --date='format-local:%Y-%m-%dT%H-%M-%SZ' --format="%cd"
```

# Making a release

Set the GITHUB_TOKEN environment variable to the token for the account making the release and run goreleaser:

```shell
export GITHUB_TOKEN=mytokenvalue
goreleaser --clean 

```



