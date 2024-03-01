FROM python:3.12.2-slim-bullseye

WORKDIR /netchat

COPY ./server.py /netchat/server.py
COPY ./requirements.txt /netchat/requirements.txt
RUN /usr/local/bin/python -m pip install --upgrade pip

RUN pip3 install wheel && pip3 install -r requirements.txt -U

CMD ["python3", "-u", "/netchat/server.py"]