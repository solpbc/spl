# spl — sol private link
# Top-level orchestrator. This repository holds the protocol definition and the
# relay. Client and home implementations live in their own repositories — see
# README.md § implementations.

.PHONY: install test ci format clean \
        definition-generate definition-ci \
        relay-install relay-test relay-ci relay-dev relay-deploy

install: relay-install

test: relay-test

ci: definition-ci relay-ci

# proto/definition — the machine-readable wire definition + conformance corpus.
definition-generate:
	python3 proto/definition/generate.py --write

definition-ci:
	python3 proto/definition/generate.py --check

format:
	$(MAKE) -C relay format

clean:
	$(MAKE) -C relay clean

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
