FROM debian:bookworm-slim

ENV COWRIE_HOME=/cowrie \
    COWRIE_USER=cowrie \
    COWRIE_GROUP=cowrie \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        libffi-dev \
        libssl-dev \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r ${COWRIE_GROUP} && \
    useradd -r -d ${COWRIE_HOME} -m -g ${COWRIE_GROUP} ${COWRIE_USER}

WORKDIR ${COWRIE_HOME}

COPY . ${COWRIE_HOME}

RUN chown -R ${COWRIE_USER}:${COWRIE_GROUP} ${COWRIE_HOME}

USER ${COWRIE_USER}

RUN python3 -m venv cowrie-env && \
    ${COWRIE_HOME}/cowrie-env/bin/pip install --upgrade pip setuptools wheel && \
    ${COWRIE_HOME}/cowrie-env/bin/pip install -r requirements.txt

ENV PATH=${COWRIE_HOME}/cowrie-env/bin:${PATH}
ENV PYTHONPATH=${COWRIE_HOME}/src

EXPOSE 2222

CMD ["cowrie-env/bin/twistd", "-n", "--umask=0022", "--pidfile=", "cowrie"]

