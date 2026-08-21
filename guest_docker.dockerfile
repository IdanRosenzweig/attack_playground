FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    bash \
    netcat-openbsd \
    python2 \
    python3 \
    python3-pip \
    gcc \
    g++ \
    make \
    git \
    vim \
    nano \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# create a symlink for "python" to python3
RUN ln -s /usr/bin/python3 /usr/bin/python || true

ENV SHELL=/bin/bash
CMD ["/bin/bash"]