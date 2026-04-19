# spl — sol private link
# Top-level orchestrator. Per-component Makefiles live in solcf/, home/, ios/.

.PHONY: install test ci format clean \
        solcf-install solcf-test solcf-ci solcf-dev solcf-deploy \
        home-install home-test home-ci home-format

install: solcf-install home-install

test: solcf-test home-test

ci: solcf-ci home-ci

format: home-format
	$(MAKE) -C solcf format

clean:
	$(MAKE) -C solcf clean
	$(MAKE) -C home clean

# solcf (Cloudflare Worker + Durable Object)
solcf-install:
	$(MAKE) -C solcf install

solcf-test:
	$(MAKE) -C solcf test

solcf-ci:
	$(MAKE) -C solcf ci

solcf-dev:
	$(MAKE) -C solcf dev

solcf-deploy:
	$(MAKE) -C solcf deploy

# home (Python tunnel module)
home-install:
	$(MAKE) -C home install

home-test:
	$(MAKE) -C home test

home-ci:
	$(MAKE) -C home ci

home-format:
	$(MAKE) -C home format
