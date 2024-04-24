# CentOS 7
FROM centos:7

# explicit reqs
RUN yum install -y \
    openldap \
    openldap-servers-sql \
    openldap-clients \
    openldap-devel \
    python-ldap \
    openldap-servers \
    python3 \
    python3-venv \
    python3-pip \
    which \
    psmisc \
    sudo \
    krb5-server-ldap \
    krb5-workstation \
    cyrus-sasl-gssapi \
    && yum clean all \
    && rm -rf /var/cache/yum


RUN python3 -m venv /var/venv && \
    /var/venv/bin/pip install --no-cache-dir ldif

# systemctl replacement
RUN curl -L https://raw.githubusercontent.com/gdraheim/docker-systemctl-replacement/master/files/docker/systemctl.py -o /bin/systemctl

RUN mkdir -p /app/schema
RUN mkdir -p /app/ldif_raw
RUN mkdir -p /app/ldif

COPY entrypoint.sh /app/entrypoint.sh
COPY scripts /app/scripts
COPY config /app/config

RUN chmod +x /app/entrypoint.sh \
     && echo "local4.debug		/var/log/slapd.log" >> /etc/syslog.conf

WORKDIR /app

ENTRYPOINT ["/app/entrypoint.sh"]
