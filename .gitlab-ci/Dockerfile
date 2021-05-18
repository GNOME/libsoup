FROM fedora-minimal:34

RUN microdnf update -y \
    && microdnf install -y autoconf-archive \
                      brotli-devel \
                      clang-analyzer \
                      git \
                      glib2-doc \
                      gnutls-devel \
                      gobject-introspection-devel \
                      gtk-doc \
                      httpd \
                      krb5-devel \
                      lcov \
                      libasan \
                      libpsl-devel \
                      libnghttp2-devel \
                      lsof \
                      make \
                      meson \
                      mod_ssl \
                      python2.7 \
                      redhat-rpm-config \
                      samba-winbind-clients \
                      sqlite-devel \
                      sysprof-devel \
                      valgrind \
                      which \
    && python2.7 -m ensurepip \
    && pip2.7 install virtualenv autobahntestsuite \
    && pip3 install quart \
    && microdnf install -y fedora-repos-rawhide \
    && microdnf install --enablerepo=rawhide -y vala \
    && microdnf clean all

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
