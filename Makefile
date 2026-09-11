IMAGE ?= filestash-oidc

.PHONY: test image

test:
	docker build --target test --progress=plain .

image:
	docker build -t $(IMAGE) .
