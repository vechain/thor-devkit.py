install:
	python3 -m venv .env
	. .env/bin/activate && pip3 install -r requirements.txt

test:
	. .env/bin/activate && python3 -m pytest -vv -s