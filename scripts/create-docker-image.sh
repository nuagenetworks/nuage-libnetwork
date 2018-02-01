#!/bin/bash

set -ex

if [ -z ${GOPATH} ]; then 
    echo "\"GOPATH\" environmental variable is not set";
    exit 1
fi

if [ -z ${version} ]; then 
    echo "\"version\" environmental variable is not set";
    exit 1
fi

#go build

docker build -t nuage-plugin:${version} -f Dockerfile .

docker save -o nuage_plugin.tar nuage-plugin:${version}

docker rmi nuage-plugin:${version}
