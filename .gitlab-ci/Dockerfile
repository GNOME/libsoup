FROM fedora:36

# NOTE: We set tsflags to empty so docs actually install...
RUN dnf update -y \
    && dnf install --setopt=tsflags='' -y \
                      brotli-devel \
                      clang-analyzer \
                      'dnf-command(builddep)' \
                      gcovr \
                      git \
                      gi-docgen \
                      glib2-doc \
                      gnutls-devel \
                      gobject-introspection-devel \
                      gtk-doc \
                      httpd \
                      krb5-devel \
                      lcov \
                      libasan \
                      libnghttp2-devel \
                      libpsl-devel \
                      libsoup-doc \
                      lsof \
                      meson \
                      mod_ssl \
                      python2.7 \
                      redhat-rpm-config \
                      samba-winbind-clients \
                      sqlite-devel \
                      sysprof-devel \
                      vala \
                      valgrind \
                      which \
    && dnf builddep -y nghttp2 \
    && dnf clean all \
    && python2.7 -m ensurepip \
    && pip2.7 install --upgrade pip \
    && pip2.7 install virtualenv wsaccel==0.6.3 autobahntestsuite

# Update libnghttp2 for do_invalid_header_rfc9113_received_test()
RUN git clone https://github.com/nghttp2/nghttp2.git \
    && pushd nghttp2 \
    && git checkout v1.50.0 \
    && autoreconf --install --symlink \
    && ./configure --prefix=/usr --disable-static --disable-examples \
    && make -j $(nproc) install \
    && popd \
    && rm -rf nghttp2

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
