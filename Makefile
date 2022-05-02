install:
	python3 -m venv .env
	. .env/bin/activate && python3 -m pip install -e .

test:
	. .env/bin/activate && python3 -m pytest -vv -s

publish: test
	rm -rf dist/*
	. .env/bin/activate \
		&& python3 setup.py sdist bdist_wheel \
		&& python3 -m twine upload dist/*
