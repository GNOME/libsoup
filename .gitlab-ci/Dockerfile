FROM fedora:31

RUN dnf update -y \
    && dnf install -y 'dnf-command(builddep)' \
    && dnf builddep -y libsoup glib2 \
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
    && dnf clean all \
    && git clone https://gitlab.gnome.org/GNOME/glib.git \
    && pushd glib \
    && meson _build --prefix=/usr \
    && meson install -C _build \
    && popd \
    && rm -rf glib

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
