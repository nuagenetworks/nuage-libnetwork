all: build_docker_image run_container
build_all: build_nuage_libnetwork

build_docker_image:
	  docker build -t registry.mv.nuagenetworks.net:5000/build/nuage-libnetwork -f Dockerfile.build .

run_container:
	./docker_build_script.sh build_nuage_libnetwork

build_nuage_libnetwork:
	./scripts/buildRPM.sh
	./scripts/create-docker-image.sh
	./scripts/create-v2-plugin.sh
