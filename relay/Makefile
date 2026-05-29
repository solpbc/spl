# spl-relay — CF Worker + Durable Object
# sol private link relay server
#
# Toolchain is bun (same as mobile/). bun's installer resolves the
# platform-specific prebuilt binaries that wrangler/miniflare pull in
# transitively (sharp, workerd, esbuild) cleanly; npm 11 fails to reify
# sharp's libc-tagged prebuilt as a nested-transitive optional dep and
# falls back to a source build that breaks on modern toolchains. The relay
# never uses sharp (it's miniflare's lazy Cloudflare-Images emulation, and a
# blind byte-relay binds no Images) — bun just installs the prebuilt and
# moves on. See the relay README and the spl decision log.

.PHONY: install test ci format clean dev deploy typecheck lint

install:
	bun install

test:
	bun run test

# full pre-commit gate
ci: typecheck lint test

typecheck:
	bun run tsc --noEmit

lint:
	bun run biome check src/ test/ test-integration/

format:
	bun run biome format --write src/ test/ test-integration/

# Local dev under Miniflare. The local `bun run wrangler` is fine here — dev
# uses no persistent OAuth session and never touches a real CF account.
dev:
	bun run wrangler dev

# Manual production deploy. Operator must be authenticated (`wrangler login`)
# against the *global* wrangler binary — running the project-local wrangler
# (`bun run wrangler` / `npx wrangler`) loses the OAuth session and exhibits
# R2/D1 visibility bugs. See README.md prerequisites.
deploy:
	wrangler deploy

clean:
	rm -rf node_modules/ dist/ .wrangler/ .bun-cache/
