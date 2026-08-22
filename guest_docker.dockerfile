FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    bash \
    coreutils \
    iputils-ping \
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

# Create the user
RUN useradd -m guestuser

USER guestuser
WORKDIR /home/guestuser

CMD ["console", "--", "/bin/bash"]
