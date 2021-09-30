FROM fedora:35

RUN dnf update -y \
    && dnf install -y \
                      autoconf-archive \
                      brotli-devel.{x86_64,i686} \
                      clang-analyzer \
                      'dnf-command(builddep)' \
                      git \
                      glib2-doc \
                      glib2-devel.{x86_64,i686} \
                      glib-networking.{x86_64,i686} \
                      gnutls-devel.{x86_64,i686} \
                      gobject-introspection-devel \
                      gtk-doc \
                      httpd \
                      krb5-devel \
                      lcov \
                      libasan \
                      libpsl-devel.{x86_64,i686} \
                      libnghttp2-devel.{x86_64,i686} \
                      lsof \
                      make \
                      meson \
                      mod_ssl \
                      python2.7 \
                      python3-pip \
                      redhat-rpm-config \
                      samba-winbind-clients \
                      sqlite-devel.{x86_64,i686} \
                      sysprof-capture-devel.{x86_64,i686} \
                      vala \
                      valgrind \
                      which \
                      {pkgconf-pkg-config,glib-networking}.i686 \
                      {glib2,elfutils-libelf}.i686 \
                      {glibc,zlib,libselinux,libmount,libblkid,pcre,pcre2}-devel.i686 \
    && dnf download glib2-devel.i686 libsoup-doc \
    && rpm -i libsoup-doc*.rpm \
    && rm *.rpm \
    && dnf clean all \
    && python2.7 -m ensurepip \
    && pip2.7 install virtualenv autobahntestsuite \
    && pip3 install quart

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
