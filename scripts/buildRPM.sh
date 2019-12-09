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

rm -rf ~/rpmbuild/BUILD/nuage-libnetwork*
rm -rf ~/rpmbuild/SOURCES/nuage-libnetwork*
rm -rf ~/rpmbuild/RPMS/x86_64/nuage-libnetwork*
rm -rf ~/rpmbuild/SRPMS/nuage-libnetwork*
rm -rf /tmp/nuage-libnetwork*

for GPATH in ${GOPATH//:/ }; do
    if [ $(find $GPATH/src -name nuage-libnetwork -type d | wc -l)=="1" ];
    then
        cd $(find $GPATH/src -name nuage-libnetwork -type d)
        break
    fi
done;

go build

cd /tmp
cp -r $GOPATH/src/github.com/nuagenetworks/nuage-libnetwork nuage-libnetwork-${version}
tar -czvf $HOME/rpmbuild/SOURCES/nuage-libnetwork-${version}.tar.gz nuage-libnetwork-${version}
rpmbuild --nodeps -ba $GOPATH/src/github.com/nuagenetworks/nuage-libnetwork/rpmbuild/nuage-libnetwork.spec --define "version ${version}"
