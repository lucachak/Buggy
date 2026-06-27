.PHONY: install install-venv run test clean help

help:
	@echo "Buggy - Modular WebApp Exploiter"
	@echo ""
	@echo "Usage:"
	@echo "  make install       Install Buggy system-wide"
	@echo "  make install-venv  Install Buggy in virtual environment"
	@echo "  make run           Run Buggy with default target"
	@echo "  make test          Run tests"
	@echo "  make clean         Remove build artifacts"
	@echo ""

install:
	bash install.sh

install-venv:
	bash install.sh --venv

run:
	python Buggy.py -t http://localhost:8000 -m recon --skip-deps

test:
	python -m pytest tests/ -v

clean:
	rm -f buggy
	rm -rf output/ recon_output_*/
	rm -rf modules/Reconnaissance/Dirpy/DirGo
	rm -rf modules/Reconnaissance/DirGO/DirGo
	rm -rf __pycache__/ modules/*/__pycache__/
	rm -rf .venv/
	@echo "Cleaned."