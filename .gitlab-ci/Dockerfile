FROM fedora:31

RUN dnf update -y \
    && dnf install -y 'dnf-command(builddep)' \
    && dnf builddep -y libsoup \
    && dnf install -y brotli-devel \
                      git \
                      gtk-doc \
                      httpd \
                      lcov \
                      libpsl-devel \
                      make \
                      meson \
                      mod_ssl \
                      php \
                      php-xmlrpc \
                      redhat-rpm-config \
                      samba-winbind-clients \
                      which \
    && dnf clean all

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
