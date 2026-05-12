FROM ghcr.io/gitguardian/wolfi/python:3.10-dev AS build

LABEL maintainer="GitGuardian SRE Team <support@gitguardian.com>"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONFAULTHANDLER=1
ENV PATH=/app/.venv/bin:$PATH

WORKDIR /app

RUN apk update \
    && apk upgrade --no-cache \
    && apk add --no-cache openssh-client \
    && rm -rf /var/cache/apk/*

COPY . .

RUN pip install .

WORKDIR /data
VOLUME [ "/data" ]

ENTRYPOINT []
CMD ["ggshield"]
