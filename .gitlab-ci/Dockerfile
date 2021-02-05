FROM fedora:33

RUN dnf update -y \
    && dnf install -y 'dnf-command(builddep)' \
    && dnf builddep -y libsoup glib2 gobject-introspection vala \
    && dnf install -y autoconf-archive \
                      brotli-devel \
                      clang-analyzer \
                      git \
                      glib2-doc \
                      gtk-doc \
                      httpd \
                      lcov \
                      libasan \
                      libpsl-devel \
                      lsof \
                      make \
                      meson \
                      mod_ssl \
                      python2.7.x86_64 \
                      redhat-rpm-config \
                      samba-winbind-clients \
                      sysprof-devel \
                      valgrind \
                      which \
    && dnf clean all \
    && git clone https://gitlab.gnome.org/GNOME/glib.git \
    && pushd glib \
    && meson _build --prefix=/usr -Dgtk_doc=true \
    && meson install -C _build \
    && popd \
    && git clone https://gitlab.gnome.org/GNOME/gobject-introspection.git \
    && pushd gobject-introspection \
    && meson _build --prefix=/usr \
    && meson install -C _build \
    && popd \
    && git clone https://gitlab.gnome.org/GNOME/vala.git \
    && pushd vala \
    && ./autogen.sh --prefix=/usr \
    && make install \
    && popd \
    && rm -rf glib gobject-introspection vala \
    && python2.7 -m ensurepip \
    && pip2.7 install virtualenv autobahntestsuite

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
