FROM python:3.7

WORKDIR /project
COPY project /project

RUN apt-get update && apt-get install -y libpq-dev python3-dev

RUN pip install -r requirements.txt

COPY cmd.sh /
CMD ["/cmd.sh"]