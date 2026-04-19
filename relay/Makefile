# spl-relay — CF Worker + Durable Object
# sol private link relay server

.PHONY: install test ci format clean dev deploy typecheck lint

install:
	npm install

test:
	npm test

# full pre-commit gate
ci: typecheck lint test

typecheck:
	npx tsc --noEmit

lint:
	npx biome check src/

format:
	npx biome format --write src/

# Local dev under Miniflare. `npx wrangler` is fine here — dev uses no
# persistent OAuth session and never touches a real CF account.
dev:
	npx wrangler dev

# Manual production deploy. Operator must be authenticated (`wrangler login`)
# against the *global* wrangler binary — `npx wrangler` loses the OAuth
# session and exhibits R2/D1 visibility bugs. See README.md prerequisites.
deploy:
	wrangler deploy

clean:
	rm -rf node_modules/ dist/ .wrangler/
