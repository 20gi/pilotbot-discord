ARG BUILD_FROM
FROM ${BUILD_FROM}

WORKDIR /app

COPY bot/ .

RUN apk add --no-cache python3 py3-pip

COPY bot/requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY run.sh /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]