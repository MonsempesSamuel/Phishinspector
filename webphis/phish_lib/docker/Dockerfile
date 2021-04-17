FROM ubuntu:20.04

ENV TZ=Europe/Paris
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update && apt-get install -y apache2 libapache2-mod-php curl iproute2 tcpdump iputils-ping xxd

EXPOSE 80
