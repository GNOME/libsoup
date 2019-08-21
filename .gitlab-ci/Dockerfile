FROM fedora:30

RUN dnf update -y \
    && dnf install -y 'dnf-command(builddep)' \
    && dnf builddep -y libsoup \
    && dnf install -y which \
                      gtk-doc \
                      libpsl-devel \
                      make \
                      httpd \
                      php \
                      php-xmlrpc \
                      mod_ssl \
                      redhat-rpm-config \
                      meson \
                      brotli-devel \
                      samba-winbind-clients \
    && dnf clean all

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
