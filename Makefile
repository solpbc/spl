# spl — sol private link
# Top-level orchestrator. Per-component Makefiles live in relay/, home/, ios/.

.PHONY: install test ci format clean \
        relay-install relay-test relay-ci relay-dev relay-deploy \
        home-install home-test home-ci home-format

install: relay-install home-install

test: relay-test home-test

ci: relay-ci home-ci

format: home-format
	$(MAKE) -C relay format

clean:
	$(MAKE) -C relay clean
	$(MAKE) -C home clean

# spl-relay (Cloudflare Worker + Durable Object)
relay-install:
	$(MAKE) -C relay install

relay-test:
	$(MAKE) -C relay test

relay-ci:
	$(MAKE) -C relay ci

relay-dev:
	$(MAKE) -C relay dev

relay-deploy:
	$(MAKE) -C relay deploy

# home (Python tunnel module)
home-install:
	$(MAKE) -C home install

home-test:
	$(MAKE) -C home test

home-ci:
	$(MAKE) -C home ci

home-format:
	$(MAKE) -C home format
