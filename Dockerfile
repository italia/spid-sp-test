FROM python:3.8-slim-buster

LABEL maintainer="Giuseppe De Marco <giuseppe.demarco@teamdigitale.governo.it>"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        xmlsec1 \
        libxml2-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && adduser \
        --disabled-password \
        --home /spid \
        --quiet \
        spid

COPY . /tmp/src/
RUN pip install --no-cache-dir /tmp/src/ \
    && rm -fr /tmp/src

WORKDIR /spid
USER spid

ENTRYPOINT ["spid_sp_test"]
CMD ["--help"]
