# syntax=docker/dockerfile:1
FROM python:3.12-rc-slim-buster

# Install prerequisite packages:
RUN apt-get update && apt-get -y upgrade
RUN pip3 install kubernetes

COPY url_watcher.py /home/ubuntu/url_watcher.py
CMD ["python3", "/home/ubuntu/url_watcher.py"]
