
VENV_BIN = venv/bin/activate
ENTER_VENV = . venv/bin/activate

PYTHON := python3

all:
	

run:
	$(ENTER_VENV); python main.py

init: $(VENV_BIN)
	$(ENTER_VENV); pip install -r requirements.txt
	$(ENTER_VENV); touch venv/installed

venv/installed: $(VENV_BIN)
	$(ENTER_VENV); pip install -r requirements.txt
	touch venv/installed

$(VENV_BIN):
	virtualenv -p $(PYTHON) venv --distribute
