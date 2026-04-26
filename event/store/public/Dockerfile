FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -d /home/chall -m -s /bin/bash pwner

WORKDIR /home/chall

COPY ./flag.txt .
COPY ./store .

RUN chown -R root:pwner /home/chall && \
    chmod -R 750 /home/chall

USER pwner
EXPOSE 1337

ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/chall/store,stderr"]