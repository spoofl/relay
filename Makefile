.PHONY: help run test

PY ?= python3
ARGS ?=

help:
	@echo "Targets:"
	@echo "  run       start ./run.sh (pass options with ARGS='...')"
	@echo "  test      run the test suite"

run:
	@PY="$(PY)" ./run.sh $(ARGS)

test:
	$(PY) -m unittest discover -s tests -v
