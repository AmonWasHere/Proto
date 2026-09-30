.PHONY: help app test controls pairs review paper e0 clean

help:
	@echo "make app       launch the local web app (opens the browser)"
	@echo "make test      run the test suite"
	@echo "make controls  analyzer regression check (12/18 expected)"
	@echo "make pairs     four-way decomposition on the Python pairs"
	@echo "make review    end-to-end review of the example app (offline)"
	@echo "make paper     render paper/main.pdf"
	@echo "make e0        repeatability run (needs a cloud model configured)"
	@echo "make clean     remove caches and generated artifacts"

app:
	./rewardaudit/scripts/rewardaudit-app

test:
	cd rewardaudit && PYTHONPATH=src python3 -m pytest -q

controls:
	cd rewardaudit && PYTHONPATH=src python3 -m rewardaudit.harness controls

pairs:
	cd rewardaudit && PYTHONPATH=src python3 -m rewardaudit.harness pairs

review:
	cd rewardaudit && PYTHONPATH=src python3 -m rewardaudit.harness review \
		--path ../examples/vulnerable-app --backend scripted

e0:
	cd rewardaudit && REWARDAUDIT_LLM_CACHE=off PYTHONPATH=src python3 -m rewardaudit.harness repeats \
		--dir datasets/javavfc_pairs --experiments e1,calibrate \
		--models deepseek-flash,deepseek-v4-pro --k 3 --json runs/e0.json

paper:
	./paper/build.sh

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf rewardaudit/.pytest_cache rewardaudit/runs rewardaudit/*.egg-info
