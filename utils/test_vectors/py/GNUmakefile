VENV ?= $(shell pwd)/venv
HOST_PYTHON ?= $(shell which python3)
export PYTHON = $(VENV)/bin/python3
export PIP = $(VENV)/bin/pip

run: deps
	@$(PYTHON) main.py

cli: deps
	$(PYTHON)

deps: .flag.requirements.txt
.flag.requirements%txt: requirements%txt | $(VENV)
	$(PIP) install -r $<
	@touch $@

$(VENV):
	$(HOST_PYTHON) -m venv $@

clean:
	rm -rf $(VENV) .flag.*

.PHONY: run cli
.PHONY: deps clean
