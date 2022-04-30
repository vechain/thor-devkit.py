install:
	python3 -m venv .env
	. .env/bin/activate \
		&& python3 -m pip install -r requirements.txt \
		&& python3 -m pip install -r dev_requirements.txt

test:
	. .env/bin/activate \
		&& python3 -m pytest --cov=thor_devkit --no-cov-on-fail --cov-report=term-missing -vv -s

publish: test
	rm -rf dist/*
	. .env/bin/activate && python3 setup.py sdist bdist_wheel
	. .env/bin/activate && python3 -m twine upload dist/*
