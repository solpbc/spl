# spl — sol private link
# Top-level orchestrator. Per-component Makefiles live in relay/, home/,
# mobile/, and (eventually) ios/.

.PHONY: install test ci format clean integration-test \
        relay-install relay-test relay-ci relay-dev relay-deploy \
        home-install home-test home-ci home-format \
        mobile-install mobile-test mobile-ci mobile-format

install: relay-install home-install mobile-install

test: relay-test home-test mobile-test

ci: relay-ci home-ci mobile-ci

# End-to-end integration suite — runs the full pair → dial → test flow
# against a local Miniflare spl-relay and a live spl.home process. See
# tests/e2e/README.md for how it wires things up.
integration-test:
	cd tests/e2e && python run.py

format: home-format
	$(MAKE) -C relay format
	$(MAKE) -C mobile format

clean:
	$(MAKE) -C relay clean
	$(MAKE) -C home clean
	$(MAKE) -C mobile clean

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

# mobile (Bun/TypeScript CLI)
mobile-install:
	$(MAKE) -C mobile install

mobile-test:
	$(MAKE) -C mobile test

mobile-ci:
	$(MAKE) -C mobile ci

mobile-format:
	$(MAKE) -C mobile format
