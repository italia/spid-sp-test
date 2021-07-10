REPO=italia/spid-sp-test
VERSION=0.9.0

default: docker-build

docker-build:
	docker build --tag $(REPO):$(VERSION) .
