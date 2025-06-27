FROM ghcr.io/fission/python-fastapi-builder:1.34.2@sha256:326cf6dac394c6c9de1a2be372968488ec5af8afceda08698d0607ffc2915c15 AS builder

ENV DEPLOY_PKG=/deploypkg

RUN mkdir -p $DEPLOY_PKG
COPY ./requirements.txt $DEPLOY_PKG/requirements.txt
RUN pip install -r $DEPLOY_PKG/requirements.txt -t $DEPLOY_PKG

COPY ./src $DEPLOY_PKG


FROM ghcr.io/fission/python-fastapi-env:1.34.2@sha256:80f8f5e5a606d5e1837711c575d972ca60f67efbda5a6ef6b36c710bea45def9 AS app

ENV USERFUNCVOL=/deploypkg

COPY --from=builder /deploypkg $USERFUNCVOL

RUN printf '{"filepath": "%s/main.py", "functionName": "main"}' $USERFUNCVOL > $USERFUNCVOL/state.json

EXPOSE 8888
