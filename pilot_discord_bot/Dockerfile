ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache build-base git nodejs npm

WORKDIR /app

COPY bot/requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY bot/ .

COPY run.sh /
RUN chmod a+x /run.sh

# Build Svelte web UI and copy static assets
COPY webui/package*.json /tmp/webui/
RUN cd /tmp/webui && npm ci
COPY webui/ /tmp/webui/
RUN cd /tmp/webui && npm run build
RUN mkdir -p /app/webui && cp -r /tmp/webui/dist /app/webui/ && rm -rf /tmp/webui

CMD [ "/run.sh" ]
