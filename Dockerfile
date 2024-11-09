FROM python:3.10-buster

WORKDIR /app
# hadolint ignore=DL3008,DL4006
RUN curl -fsSL https://deb.nodesource.com/setup_current.x | bash -
RUN apt-get update && \
    apt-get install -y python3 \
    unzip \
    zip \
    python3-pip \
    python3-dev \
    default-libmysqlclient-dev \
    build-essential \
    ca-certificates \
    curl \
    wget \
    nodejs \
    gnupg \
    lsb-release \
    libpq-dev \
    git \
    postgresql-client \ 
    jq \
    wait-for-it \
    --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* && \
    npm install npm@latest -g
EXPOSE 8000
COPY . .
RUN make install && \
    make docs
CMD ["make","runserver"]
