FROM fedora:34

RUN dnf update -y \
    && dnf install -y \
                      brotli-devel \
                      clang-analyzer \
                      'dnf-command(builddep)' \
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
    && dnf builddep -y glib2 \
    && dnf install --releasever=35 -y vala \
    && dnf clean all \
    && python2.7 -m ensurepip \
    && pip2.7 install virtualenv autobahntestsuite \
    && pip3 install quart

RUN git clone https://gitlab.gnome.org/GNOME/glib.git \
    && pushd glib \
    && git checkout 2.69.1 \
    && meson _build --prefix=/usr \
    && ninja -C _build install \
    && popd \
    && rm -rf glib

RUN git clone https://gitlab.gnome.org/GNOME/glib-networking.git \
    && pushd glib-networking \
    && git checkout f7b3250d3e3fce4ea02b00610d9f2148ade4a6ce \
    && meson _build --prefix=/usr \
    && ninja -C _build install \
    && popd \
    && rm -rf glib-networking

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
