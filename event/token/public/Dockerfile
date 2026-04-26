FROM ubuntu:24.04

RUN apt update && apt install -y socat

RUN useradd -m user

COPY ./flag /home/user/flag
COPY ./chall /home/user/chall

RUN chown user:user /home/user/flag /home/user/chall && \
    chmod 755 /home/user/chall && \
    chmod 444 /home/user/flag

WORKDIR /home/user
USER user

EXPOSE 8386
CMD socat TCP-LISTEN:8386,reuseaddr,fork EXEC:/home/user/chall