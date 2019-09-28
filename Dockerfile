FROM alpine

MAINTAINER Tejas Sheth "tejas_s@trendmicro.com"
FROM python:3.7

RUN pip install --upgrade pip
RUN mkdir -p /root/app

COPY ./requirements.txt /requirements.txt

WORKDIR /

RUN pip3 install -r requirements.txt

COPY . /

ENTRYPOINT [ "python3", "list-vulnerabilities-docker.py" ]