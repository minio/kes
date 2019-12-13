#!/bin/bash

binaryName="key"
platforms=("linux/amd64" "linux/arm"  "windows/amd64" "darwin/amd64" )

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
    env GOOS=$GOOS GOARCH=$GOARCH go build -o $name && zip -r -q "$release.zip" $name
    if [ $? -ne 0 ]; then
        echo "Failed to build $output_name. Aborting the script execution..."
        exit 1
    fi
    rm $name
done

