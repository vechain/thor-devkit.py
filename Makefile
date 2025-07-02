install:
	python3 -m venv .env
	pip3 install -r requirements.txt

test:
	python3 -m pytest --cov=thor_devkit --no-cov-on-fail --cov-report=term-missing -vv -s

publish: test
	rm -rf dist/*
    python3 setup.py sdist bdist_wheel
    python3 -m twine upload dist/*

# Thor solo
solo-up: #@ Start Thor solo
	docker compose up -d
solo-down: #@ Stop Thor solo
	docker compose down
