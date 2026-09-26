.PHONY: help app test controls pairs paper clean

help:
	@echo "make app       launch the local web app (opens the browser)"
	@echo "make test      run the test suite"
	@echo "make controls  analyzer regression check (12/18 expected)"
	@echo "make pairs     four-way decomposition on the Python pairs"
	@echo "make paper     render paper/main.pdf"
	@echo "make clean     remove caches and generated artifacts"

app:
	./rewardaudit/scripts/rewardaudit-app

test:
	cd rewardaudit && PYTHONPATH=src python3 -m pytest -q

controls:
	cd rewardaudit && PYTHONPATH=src python3 -m rewardaudit.harness controls

pairs:
	cd rewardaudit && PYTHONPATH=src python3 -m rewardaudit.harness pairs

paper:
	./paper/build.sh

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf rewardaudit/.pytest_cache rewardaudit/runs rewardaudit/*.egg-info
