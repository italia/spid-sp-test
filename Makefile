REPO=italia/spid-sp-test
VERSION=0.5.6

default: docker-build

docker-build:
	docker build --tag $(REPO):$(VERSION) .
