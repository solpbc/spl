# solcf — CF Worker + Durable Object
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

dev:
	npx wrangler dev

# Manual production deploy. Operator must be authenticated (`wrangler login`).
deploy:
	npx wrangler deploy

clean:
	rm -rf node_modules/ dist/ .wrangler/
