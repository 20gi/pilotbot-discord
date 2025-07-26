ARG BUILD_FROM
FROM ${BUILD_FROM}

WORKDIR /app

COPY bot/ .

RUN apk add --no-cache python3 py3-pip

RUN pip3 install -r bot/requirements.txt

COPY run.sh /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]