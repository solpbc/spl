# spl/mobile — Bun/TypeScript example mobile client
# Standalone CLI. Not iOS — that's a downstream phase (see ../ios/).

.PHONY: install test ci format clean typecheck lint

install:
	bun install

test:
	bun test

ci: format-check lint typecheck test

typecheck:
	bun run tsc --noEmit

lint:
	bun run biome check src/ tests/

format:
	bun run biome format --write src/ tests/

format-check:
	bun run biome format src/ tests/

clean:
	rm -rf node_modules/ .bun-cache/
