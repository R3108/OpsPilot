.DEFAULT_GOAL := help
SHELL := /bin/bash

BACKEND := backend
FRONTEND := frontend
COMPOSE := docker compose
COMPOSE_PROD := docker compose -f docker-compose.yml -f docker-compose.prod.yml

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- setup
.PHONY: keys
keys: ## Generate SECRET_KEY and ENCRYPTION_KEY for your .env
	@cd $(BACKEND) && python -m app.cli keys

.PHONY: install
install: ## Install backend and frontend dependencies
	cd $(BACKEND) && python -m pip install -e ".[dev]"
	cd $(FRONTEND) && npm ci --no-audit --no-fund

.PHONY: env
env: ## Create .env from the template if it does not exist
	@test -f .env || (cp .env.example .env && echo "Created .env — run 'make keys' and paste the values in")

# ---------------------------------------------------------------- develop
.PHONY: dev
dev: ## Run the whole stack in Docker
	$(COMPOSE) up --build

.PHONY: dev-backend
dev-backend: ## Run the API locally with reload
	cd $(BACKEND) && uvicorn app.main:app --reload --port 8000

.PHONY: dev-worker
dev-worker: ## Run the investigation worker locally
	cd $(BACKEND) && arq app.workers.main.WorkerSettings

.PHONY: dev-frontend
dev-frontend: ## Run the web app locally
	cd $(FRONTEND) && npm run dev

# ---------------------------------------------------------------- database
.PHONY: migrate
migrate: ## Apply database migrations
	cd $(BACKEND) && alembic upgrade head

.PHONY: migration
migration: ## Create a migration:  make migration m="add widget table"
	cd $(BACKEND) && alembic revision --autogenerate -m "$(m)"

.PHONY: downgrade
downgrade: ## Roll back the most recent migration
	cd $(BACKEND) && alembic downgrade -1

.PHONY: seed
seed: ## Seed the demo organisation, integrations and incidents
	cd $(BACKEND) && python -m app.cli seed

.PHONY: reseed
reseed: ## Delete and recreate the demo organisation
	cd $(BACKEND) && python -m app.cli seed --reset

# ---------------------------------------------------------------- quality
.PHONY: test
test: ## Run the backend test suite
	cd $(BACKEND) && pytest -q

.PHONY: test-cov
test-cov: ## Run tests with a coverage report
	cd $(BACKEND) && pytest --cov=app --cov-report=term-missing --cov-report=html

.PHONY: eval
eval: ## Run the agent eval suite against the incident scenarios
	cd $(BACKEND) && python -m app.evals.runner

.PHONY: eval-live
eval-live: ## Run the eval suite against a real model (LLM_PROVIDER=anthropic|nvidia, plus that provider's key)
	cd $(BACKEND) && LLM_PROVIDER=$(or $(LLM_PROVIDER),anthropic) python -m app.evals.runner --json eval-live.json

.PHONY: lint
lint: ## Lint and typecheck everything
	cd $(BACKEND) && ruff check app tests && ruff format --check app tests
	cd $(FRONTEND) && npx tsc --noEmit

.PHONY: fmt
fmt: ## Auto-format and auto-fix
	cd $(BACKEND) && ruff check --fix app tests && ruff format app tests

.PHONY: catalog
catalog: ## Print the action catalog exactly as the agent sees it
	cd $(BACKEND) && python -m app.cli catalog

.PHONY: check
check: lint test eval ## Everything CI runs

# ---------------------------------------------------------------- operate
.PHONY: logs
logs: ## Tail the stack logs
	$(COMPOSE) logs -f api worker

.PHONY: shell
shell: ## Open a shell in the API container
	$(COMPOSE) exec api bash

.PHONY: psql
psql: ## Open psql against the dev database
	$(COMPOSE) exec postgres psql -U opspilot -d opspilot

.PHONY: down
down: ## Stop the stack
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and delete its volumes
	$(COMPOSE) down -v
	rm -rf $(BACKEND)/.pytest_cache $(BACKEND)/htmlcov $(BACKEND)/*.db
	find $(BACKEND) -type d -name __pycache__ -prune -exec rm -rf {} +

.PHONY: prod-up
prod-up: ## Start the production overlay (requires the full .env)
	$(COMPOSE_PROD) up -d --build

.PHONY: prod-logs
prod-logs: ## Tail production logs
	$(COMPOSE_PROD) logs -f
