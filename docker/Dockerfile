FROM centos:7

# Allow customization of build user ID and name
ARG BUILD_USER=build
ARG BUILD_USER_UID=501

RUN echo "include_only=.garr.it,.cern.ch" >> /etc/yum/pluginconf.d/fastestmirror.conf && \
  yum clean all && \
  yum install -y hostname epel-release && \
  yum -y update && \
  yum -y install which wget tar sudo file && \
  yum -y install which wget tar sudo file && \
  echo '%wheel ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
  adduser --uid ${BUILD_USER_UID} ${BUILD_USER} && \
  usermod -a -G wheel ${BUILD_USER} && \
  yum -y install \
  gdb git expat-devel autoconf automake make libtool pkgconfig openssl-devel gsoap-devel \
  mysql-devel libxslt docbook-style-xsl doxygen bison gcc-c++ gcc && \
  yum clean all && \
  rm -rf /var/cache/yum

ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]


USER $BUILD_USER
WORKDIR /home/$BUILD_USER
