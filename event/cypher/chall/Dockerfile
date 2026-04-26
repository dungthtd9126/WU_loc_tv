FROM ubuntu:22.04

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/sh ctf

WORKDIR /home/ctf

COPY cipherbox flag.txt ./
RUN chmod +x cipherbox && chown ctf:ctf flag.txt && chmod 444 flag.txt

USER ctf

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./cipherbox,pty,rawer,echo=0
