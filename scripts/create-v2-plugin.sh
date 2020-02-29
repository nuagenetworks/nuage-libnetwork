#!/bin/bash

set -e

PLUGIN_NAME="$1"
if [ -z ${PLUGIN_NAME} ]; then 
    echo "\"PLUGIN_NAME\" is not set";
    echo "Usage: ${0} <name of the plugin>"
    exit 1
fi

# go build
TMPDIR=$(mktemp -d nuage.tmp.XXXXX)
mkdir -p $TMPDIR/rootfs

docker build -t rootfsimage .
id=$(docker create rootfsimage true)
docker export "$id" | tar -x -C $TMPDIR/rootfs
docker rm -vf "$id"
docker rmi rootfsimage

cat <<EOF > $TMPDIR/config.json
{
    "Description": "Docker 1.13 Remote Driver",
    "Documentation": "https://docs.docker.com/engine/extend/plugins/",
    "Entrypoint": [
        "/nuage-libnetwork", 
        "-config", 
        "/etc/default/nuage-libnetwork.yaml"
    ],
    "Network": {
        "type": "host"
    },
    "mounts": [
        {
            "destination": "/etc/default/",
            "source": "/etc/default/",
            "type": "bind",
            "options": ["rbind"]
        },
        {
            "destination": "/usr/bin/",
            "source": "/usr/bin/",
            "type": "bind",
            "options": ["rbind"]
        },
        {
            "destination": "/usr/lib64/",
            "source": "/usr/lib64/",
            "type": "bind",
            "options": ["rbind"]
        },
        {
            "destination": "/var/log/",
            "source": "/var/log/",
            "type": "bind",
            "options": ["rbind"]
        },
        {
            "destination": "/var/run/",
            "source": "/var/run/",
            "type": "bind",
            "options": ["rbind"]
        }
    ],
    "Interface" : {
        "types": [
            "docker.ipamdriver/1.0",
            "docker.networkdriver/1.0"
        ],
        "socket": "nuage.sock"
    },
    "linux": {
        "Capabilities": [
            "CAP_SYS_ADMIN",
            "CAP_NET_ADMIN"
        ]
    }
}
EOF

sudo docker plugin create ${PLUGIN_NAME} ${TMPDIR}
sudo docker plugin push ${PLUGIN_NAME}
sudo docker plugin rm ${PLUGIN_NAME}
sudo docker plugin install --alias nuage ${PLUGIN_NAME}
sudo rm -rf ${TMPDIR}
