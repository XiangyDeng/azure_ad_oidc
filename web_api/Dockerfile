FROM eu.gcr.io/gitpod-core-dev/build/server:commit-3dc879627eaea56210f02f26adb397f35081db0d
# RUN chmod 777 /home/developer

USER root

ADD ./user-controller.js /app/node_modules/@gitpod/server/dist/src/user

ADD ./generic-auth-provider.js /app/node_modules/@gitpod/server/dist/src/auth

WORKDIR /app/node_modules/@gitpod/server/dist/src/aad

ADD ./aad-urls.js /app/node_modules/@gitpod/server/dist/src/aad

