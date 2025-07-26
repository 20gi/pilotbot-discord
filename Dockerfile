ARG BUILD_FROM
FROM ${BUILD_FROM}

WORKDIR /app

COPY bot/requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY bot/ .

COPY run.sh /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]