FROM fedora:33

RUN dnf update -y \
    && dnf install -y 'dnf-command(builddep)' \
    && dnf builddep -y libsoup glib2 gobject-introspection vala \
    && dnf install -y brotli-devel \
                      git \
                      gtk-doc \
                      glib2-doc \
                      httpd \
                      lcov \
                      libpsl-devel \
                      make \
                      meson \
                      mod_ssl \
                      redhat-rpm-config \
                      samba-winbind-clients \
                      which \
                      clang-analyzer \
                      valgrind \
                      libasan \
                      sysprof-devel \
                      autoconf-archive \
    && dnf clean all \
    && git clone https://gitlab.gnome.org/GNOME/glib.git \
    && pushd glib \
    && meson _build --prefix=/usr \
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
    && rm -rf glib gobject-introspection vala

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
