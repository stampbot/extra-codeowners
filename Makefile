.DEFAULT_GOAL := help

.PHONY: bootstrap check coverage docs format helm help lint test

bootstrap: ## Install the locked development environment.
	uv sync --all-groups --frozen

format: ## Format Python source and test files.
	uv run ruff format .
	uv run ruff check --fix .

lint: ## Run source and repository linters.
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy extra_codeowners tests
	uv run yamllint .
	actionlint
	shellcheck .github/scripts/smoke-container.sh
	jq -e -f .github/scripts/validate-openvex.jq .openvex.json >/dev/null
	markdownlint-cli2 '**/*.md' '#site/**' '#.venv/**'

test: ## Run all locally available tests without enforcing coverage.
	uv run pytest --no-cov

coverage: ## Run the complete PostgreSQL suite and enforce branch coverage.
	@test -n "$$TEST_POSTGRES_URL" || { \
		echo "TEST_POSTGRES_URL must point to a disposable database whose name ends in _test." >&2; \
		exit 2; \
	}
	uv run pytest \
		--cov=extra_codeowners \
		--cov-branch \
		--cov-report=term-missing \
		--cov-report=xml \
		--cov-report=html \
		--cov-fail-under=85

docs: ## Build documentation with warnings treated as errors.
	uv run mkdocs build --strict

helm: ## Lint and render the Helm chart.
	cmp --silent LICENSE charts/extra-codeowners/LICENSE
	helm lint charts/extra-codeowners
	helm template extra-codeowners charts/extra-codeowners >/dev/null

check: lint test docs helm ## Run the local pull-request checks.

help: ## Show the available targets.
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
