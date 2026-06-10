# Keycloak for OpenHost.
#
# Stage 1 pre-builds the Quarkus server image (kc.sh build) so container
# startup can use --optimized and stays well inside OpenHost's readiness
# window. Stage 2 is ubi9-minimal with the Keycloak tree copied in, plus
# python3 for the OpenHost SSO auth proxy and a dedicated unprivileged user.

FROM quay.io/keycloak/keycloak:26.3 AS builder

ENV KC_DB=dev-file
ENV KC_HEALTH_ENABLED=true
ENV KC_HTTP_RELATIVE_PATH=/

RUN /opt/keycloak/bin/kc.sh build

FROM registry.access.redhat.com/ubi9-minimal

RUN microdnf install -y java-21-openjdk-headless python3 shadow-utils util-linux \
    && microdnf clean all \
    && useradd --system --uid 1000 --create-home --home-dir /home/keycloak keycloak

COPY --from=builder --chown=keycloak:keycloak /opt/keycloak/ /opt/keycloak/

ENV JAVA_HOME=/usr/lib/jvm/jre-21
ENV PATH="/usr/lib/jvm/jre-21/bin:${PATH}"

COPY start.sh auth_proxy.py /opt/openhost/
RUN chmod 0755 /opt/openhost/start.sh /opt/openhost/auth_proxy.py

EXPOSE 8080

ENTRYPOINT ["/opt/openhost/start.sh"]
