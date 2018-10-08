AMZ_LINUX_VERSION:=latest
current_dir := $(shell pwd)
container_dir := /opt/app

default:
#ifeq ($(bamboo_buildNumber),)
#	docker create -v $(container_dir) --name src alpine:3.4 /bin/true
#	docker cp $(current_dir)/. src:$(container_dir)
#	docker run --rm -ti \
#		--volumes-from src \
#		amazonlinux:$(AMZ_LINUX_VERSION) \
#		/bin/bash -c "cd $(container_dir) && ./build_lambda.sh"
#else
	docker run --rm -ti \
		-v $(current_dir):$(container_dir) \
		-w $(container_dir) \
		-e HTTP_PROXY=$(HTTP_PROXY) \
        -e HTTPS_PROXY=$(HTTPS_PROXY) \
        --net=host \
		amazonlinux:$(AMZ_LINUX_VERSION) \
		./build_lambda.sh
#endif
