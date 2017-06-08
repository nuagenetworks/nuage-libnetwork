FROM centos

# Copy the local package files to the container's workspace.
ADD nuage-libnetwork /nuage-libnetwork

# Create file that contains commands for both plugin and ipam
CMD /nuage-libnetwork -config /etc/default/nuage-libnetwork.yaml
