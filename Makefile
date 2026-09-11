IMAGE ?= filestash-oidc
COMPOSE = docker compose -f e2e/compose.yaml

.PHONY: test image e2e e2e-up e2e-down

test:
	docker build --target test --progress=plain .

image:
	docker build -t $(IMAGE) .

e2e:
	$(COMPOSE) up --build --detach --wait filestash && $(COMPOSE) run --rm e2e; \
	status=$$?; $(COMPOSE) down -v; exit $$status

e2e-up:
	$(COMPOSE) up --build --detach --wait filestash

e2e-down:
	$(COMPOSE) down -v
