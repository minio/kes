#!/bin/bash

binaryName="kes"
platforms=("linux/amd64" "linux/arm"  "windows/amd64" "darwin/amd64" )

version=$(git describe --exact-match --tags $(git log -n1 --pretty='%h') 2> /dev/null)
if [ $? -ne 0 ]; then
    version="0.0.0-$(git rev-parse --short HEAD)"
    echo "Warning: current HEAD has no tag. Therefore, using commit ID: $version as release version."
fi

for platform in "${platforms[@]}"
do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    release=$GOOS'-'$GOARCH

    name=$binaryName
    if [ $GOOS = "windows" ]; then
        name+='.exe'
    fi  
   
    echo "Building release $release..."
    env GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-X main.version=$version" -o $name && zip -r -q "$release.zip" $name
    if [ $? -ne 0 ]; then
        echo "Failed to build $output_name. Aborting the script execution..."
        exit 1
    fi
    rm $name
done

