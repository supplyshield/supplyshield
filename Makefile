PYTHON_EXE=python3
GRYPE_VERSION=v0.54.0
SYFT_VERSION=v0.60.3
CRANE_VERSION=v0.12.1
VENV=venv
ACTIVATE?=. ${VENV}/bin/activate
OS=Linux
ARCH=arm64

export FLASK_APP=libinv/api/app.py

dev: deps precommit

deps: python-deps-dev grype syft crane cdxgen

precommit:
	@echo "-> Setup precommit hook"
	@cp etc/pre-commit .git/hooks/pre-commit

grype:
	@echo "-> Install grype"
	@curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b etc/third_party ${GRYPE_VERSION}

syft:
	@echo "-> Install syft"
	@curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b etc/third_party ${SYFT_VERSION}

crane:
	@echo "-> Install crane"
	curl -sL https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_${OS}_${ARCH}.tar.gz \
		| tar xvzf - -C etc/third_party crane

python-deps-dev: virtualenv
	@echo "-> Upgrade pip/setuptools for Python 3.13"
	@${ACTIVATE}; python -m pip install --upgrade pip setuptools wheel

	@echo "-> Install python deps"
	@${ACTIVATE}; pip install -e .

cdxgen:
	@echo "-> Install cdxgen"
	npm install --prefix etc/third_party/ @cyclonedx/cdxgen@10.7.1
	npm install --prefix etc/third_party/ @cyclonedx/cdxgen-plugins-bin

virtualenv:
	@echo "-> Bootstrap venv using Python's built-in venv"
	@${PYTHON_EXE} -m venv ${VENV}

clean:
	rm etc/third_party/grype
	rm etc/third_party/syft
	rm etc/third_party/crane

valid: sort black

sort:
	@echo "-> Apply isort changes to ensure proper imports ordering"
	${VENV}/bin/isort .

black:
	@echo "-> Apply black code formatter"
	${VENV}/bin/black .

check:
	@echo "-> Run ruff isort imports ordering validation"
	@# @${ACTIVATE}; isort --check-only .
	ruff check --select I001,I002 .
	@echo "-> Run black validation"
	@${ACTIVATE}; black --check .

db:
	${ACTIVATE}; alembic upgrade head

init:
	sh init.sh

healthcheck:
	${ACTIVATE}; python3 -m http.server -d /app/libinv/api/templates/healthcheck &

run: 
	make init
	make healthcheck
	@${ACTIVATE}; libinv --debug --verbose daemon

runserver:
	@${ACTIVATE}; gunicorn -w 4 'libinv.api.app:app' --bind 0.0.0.0:5000

crons:
	make init
	make healthcheck
	@${ACTIVATE}; python3 libinv/cron_scheduler.py

coverage: tests
tests:
	@echo "-> Running tests (doctests + unit tests)"
	@${ACTIVATE}; coverage run -m pytest

integration-tests:
	@echo "-> Running integration tests (requires TEST_DATABASE_URL)"
	@${ACTIVATE}; python -m pytest tests/integration -v


install: virtualenv deps

docs:
	@${ACTIVATE}; cd docs; pip3 install sphinx_rtd_theme; make html

.PHONY: docs tests coverage integration-tests
