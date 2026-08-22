# Stage 1: get the agent binary
FROM containerssh/agent:latest AS agent-binary

# Stage 2: your custom environment
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

# Create the user (with bash as shell)
RUN useradd -m -s /bin/bash guestuser

# Copy the agent binary from the official image
COPY --from=agent-binary /usr/bin/containerssh-agent /usr/bin/containerssh-agent

USER guestuser
WORKDIR /home/guestuser

# Set the agent as the container's entrypoint – it will spawn /bin/bash automatically
ENTRYPOINT ["/usr/bin/containerssh-agent"]
# No CMD needed; the agent reads the user's shell from /etc/passwd