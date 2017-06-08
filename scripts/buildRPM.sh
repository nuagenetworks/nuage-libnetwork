#!/bin/bash

set -e

if [ -z ${GOPATH} ]; then 
    echo "\"GOPATH\" environmental variable is not set";
    exit 1
fi

if [ -z ${version} ]; then 
    echo "\"version\" environmental variable is not set";
    exit 1
fi

rm -rf ~/rpmbuild/BUILD/libnetwork*
rm -rf ~/rpmbuild/SOURCES/libnetwork*
rm -rf ~/rpmbuild/RPMS/x86_64/libnetwork*
rm -rf ~/rpmbuild/SRPMS/libnetwork*
rm -rf /tmp/nuage-libnetwork*

cd $GOPATH/src/github.com/nuagenetworks/nuage-libnetwork
go build

cd /tmp
cp -r $GOPATH/src/github.com/nuagenetworks/nuage-libnetwork nuage-libnetwork-${version}
tar -czvf $HOME/rpmbuild/SOURCES/nuage-libnetwork-${version}.tar.gz nuage-libnetwork-${version}
rpmbuild --nodeps -ba $GOPATH/src/github.com/nuagenetworks/nuage-libnetwork/rpmbuild/nuage-libnetwork.spec
