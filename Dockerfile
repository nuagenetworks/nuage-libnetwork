FROM centos

# Copy the local package files to the container's workspace.
ADD nuage-libnetwork /libnetwork-nuage

# Create file that contains commands for both plugin and ipam
CMD /libnetwork-nuage -config /etc/default/libnetwork-nuage.yaml
