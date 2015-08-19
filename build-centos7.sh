#!/bin/bash
#
#
# This script bootstraps a new CentOS 7 server for image processing

# The domain name of the site hosting the img processing server
SITE_NAME="img.streamboat.tv"

yum check-update
yum update -y
yum install -y epel-release
yum groupinstall -y "Development Tools"
yum install -y cmake GraphicsMagick-devel lua pcre-devel openssl-devel \
  gd-devel curl-devel nasm iptables-services


# OpenResty
groupadd -r openresty
useradd -r -g openresty -s /sbin/nologin -d /opt/openresty -c "openresty user" openresty
mkdir -p /opt/openresty/cache/${SITE_NAME}
chown openresty.openresty /opt/openresty/cache/${SITE_NAME}
cd /usr/src
wget -O- https://openresty.org/download/ngx_openresty-1.9.3.1.tar.gz | tar zxv
cd ngx_openresty-1.9.3.1
./configure --prefix=/opt/openresty \
  --sbin-path=/opt/openresty/sbin/nginx \
  --conf-path=/opt/openresty/etc/nginx.conf \
  --error-log-path=/opt/openresty/log/error.log \
  --http-log-path=/opt/openresty/log/access.log \
  --pid-path=/opt/openresty/run/nginx.pid \
  --lock-path=/opt/openresty/run/nginx.lock \
  --http-client-body-temp-path=/opt/openresty/cache/client_temp \
  --http-proxy-temp-path=/opt/openresty/cache/proxy_temp \
  --http-fastcgi-temp-path=/opt/openresty/cache/fastcgi_temp \
  --http-uwsgi-temp-path=/opt/openresty/cache/uwsgi_temp \
  --http-scgi-temp-path=/opt/openresty/cache/scgi_temp \
  --user=openresty \
  --group=openresty \
  --with-http_addition_module \
  --with-http_ssl_module \
  --with-http_realip_module \
  --with-http_addition_module \
  --with-http_sub_module \
  --with-http_dav_module \
  --with-http_flv_module \
  --with-http_mp4_module \
  --with-http_gunzip_module \
  --with-http_gzip_static_module \
  --with-http_random_index_module \
  --with-http_secure_link_module \
  --with-http_stub_status_module \
  --with-http_auth_request_module \
  --with-http_image_filter_module \
  --with-pcre-jit \
  --with-file-aio \
  --with-ipv6 \
  --with-http_spdy_module \
  --with-luajit \
  --with-lua51=/usr \
  --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic' \
  -j2
make -j2

# Luarocks
cd /usr/src
wget -O- https://github.com/keplerproject/luarocks/archive/v2.2.2.tar.gz | tar zxv
cd luarocks-2.2.2
./configure --prefix=/opt/openresty/luajit \
  --with-lua=/opt/openresty/luajit/ \
  --lua-suffix=jit-2.1.0-alpha \
  --with-lua-include=/opt/openresty/luajit/include/luajit-2.1
make
make install
make bootstrap

# Gifsicle
cd /usr/src
git clone -b master https://github.com/kohler/gifsicle.git gifsicle-master
cd gifsicle-master
./bootstrap.sh
./configure --prefix=/opt/openresty \
  --disable-gifview \
  --disable-gifdiff
make
make install

# Mozjpeg
cd /usr/src
wget -O- https://github.com/mozilla/mozjpeg/releases/download/v3.1/mozjpeg-3.1-release-source.tar.gz | tar zxv
cd mozjpeg
./configure --prefix=/opt/openresty
make
make install

# Leanify
cd /usr/src
git clone -b master https://github.com/JayXon/Leanify.git leanify-master
cd leanify-master
make
cp leanify /opt/openresty/bin/

# Lua libs
LUAROCKS=/opt/openresty/luajit/bin/luarocks
$LUAROCKS install graphicsmagick --server=https://raw.github.com/torch/rocks/master
$LUAROCKS install image --server=https://raw.github.com/torch/rocks/master
$LUAROCKS install Lua-cURL --server=https://rocks.moonscript.org/dev
$LUAROCKS install lua-resty-readurl
$LUAROCKS install luafilesystem
$LUAROCKS install lua-path
$LUAROCKS install xml
$LUAROCKS install https://raw.githubusercontent.com/phpb-com/neturl/master/rockspec/net-url-scm-1.rockspec


# OpenResty service
cat << "EOF" > /usr/lib/systemd/system/openresty.service
[Unit]
Description=openresty-nginx - high performance web application server
Documentation=http://openresty.org
After=network.target remote-fs.target nss-lookup.target
 
[Service]
Type=forking
PIDFile=/opt/openresty/run/nginx.pid
ExecStartPre=/opt/openresty/sbin/nginx -t -c /opt/openresty/etc/nginx.conf
ExecStart=/opt/openresty/sbin/nginx -c /opt/openresty/etc/nginx.conf
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true
 
[Install]
WantedBy=multi-user.target
EOF
systemctl enable openresty.service

# Logs
cat <<- "EOF" > /etc/logrotate.d/openresty
/opt/openresty/log/*.log {
  daily
  missingok
  rotate 366
  compress
  delaycompress
  notifempty
  create 640 openresty adm
  sharedscripts
  postrotate
    [ -f /opt/openresty/run/nginx.pid ] && kill -USR1 `cat /opt/openresty/run/nginx.pid`
  endscript
}
EOF

# Firewall
cat << "EOF" > /etc/sysconfig/iptables
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT -m comment --comment "ssh"
-A INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT -m comment --comment "http"
-A INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT -m comment --comment "https"
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF

systemctl stop firewalld
systemctl mask firewalld
systemctl enable iptables
systemctl restart iptables













rpm -Uvh http://dl.atrpms.net/all/atrpms-repo-7-7.el7.x86_64.rpm
rpm --import http://www.percona.com/redir/downloads/percona-release/RPM-GPG-KEY-percona
rpm -Uvh http://www.percona.com/redir/downloads/percona-release/percona-release-0.0-1.x86_64.rpm
yum install -y epel-release
yum install -y yum-protectbase gcc zlib-devel bzip2-devel readline-devel sqlite-devel \
  pcre-devel openssl-devel GeoIP-devel libjpeg-turbo-devel freetype-devel xfsprogs \
  fontconfig-devel nc nano screen Percona-Server-server-56 Percona-Server-devel-56 \
  Percona-Server-client-56 syslog-ng syslog-ng-libdbi mailx ntp varnish haproxy git ImageMagick-devel \
  giflib-devel libpng-devel ruby rubygems httpd-tools bind-utils nginx redis \
  frei0r-plugins-devel opencv-devel rtmpdump rtmpdump-devel libvpx-devel xavs-devel faac-devel iftop \
  libmicrohttpd-devel libnice-devel jansson-devel libini_config-devel libwebp-devel libsrtp-devel \
  cmake gengetopt opus-devel iptables-services
yum-builddep -y ffmpeg

# We just want the init script from the rpm version of nginx
cp /usr/lib/systemd/system/nginx.service /tmp/nginx.service
yum remove -y nginx

gem install foreman

# WebP
cd /usr/src
wget -O- http://downloads.webmproject.org/releases/webp/libwebp-0.4.3.tar.gz | tar zxv
cd libwebp-0.4.3
./configure --enable-experimental \
  --enable-libwebpmux --enable-libwebpdemux \
  --enable-libwebpdecoder
make
make install

# Compile nginx with rtmp module
cd /usr/src
wget -O- http://nginx.org/download/nginx-1.8.0.tar.gz | tar zxv
wget -O- https://github.com/arut/nginx-rtmp-module/archive/v1.1.7.tar.gz | tar zxv
wget -O- https://github.com/wandenberg/nginx-push-stream-module/archive/0.5.1.tar.gz | tar zxv
git clone https://github.com/perusio/nginx-auth-request-module.git
wget -O- https://github.com/kaltura/nginx-vod-module/archive/1.2.tar.gz | tar zxv
cd nginx-1.8.0
 CFLAGS="-Wno-deprecated-declarations" ./configure \
  --prefix=/usr \
  --sbin-path=/usr/sbin/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --pid-path=/var/run/nginx.pid \
  --lock-path=/var/lock/subsys/nginx \
  --user=nginx \
  --group=nginx \
  --with-file-aio \
  --with-http_ssl_module \
  --with-http_flv_module \
  --with-http_mp4_module \
  --with-http_secure_link_module \
  --with-http_stub_status_module \
  --add-module=../nginx-rtmp-module-1.1.7 \
  --add-module=../nginx-push-stream-module-0.5.1 \
  --add-module=../nginx-auth-request-module \
  --add-module=../nginx-vod-module-1.2
make
make install
mv /tmp/nginx.init /etc/init.d/nginx
chmod +x /etc/init.d/nginx
chkconfig --add nginx

# fdk-aac
cd /usr/src
wget -O- http://downloads.sourceforge.net/project/opencore-amr/fdk-aac/fdk-aac-0.1.4.tar.gz | tar zxv
cd fdk-aac-0.1.4
./configure --prefix=/usr --libdir=/usr/lib64
make
make install

# ffmpeg
cd /usr/src
wget -O- http://ffmpeg.org/releases/ffmpeg-2.6.2.tar.bz2 | tar jxv
cd ffmpeg-2.6.2
./configure \
  --prefix=/usr --libdir=/usr/lib64 --shlibdir=/usr/lib64 \
  --mandir=/usr/share/man --enable-shared --enable-runtime-cpudetect \
  --enable-gpl --enable-version3 --enable-postproc --enable-avfilter \
  --enable-pthreads --enable-x11grab --enable-vdpau --disable-avisynth \
  --enable-frei0r --enable-libopencv --enable-libdc1394 --enable-libgsm \
  --enable-libmp3lame --enable-libnut --enable-libopencore-amrnb \
  --enable-libopencore-amrwb --enable-libopenjpeg --enable-librtmp \
  --enable-libspeex --enable-libtheora --enable-libvorbis --enable-libvpx \
  --enable-libx264 --enable-libxavs --enable-libxvid \
  --extra-cflags='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic -fPIC' \
  --disable-stripping \
  --enable-libfaac --enable-libfdk-aac --enable-nonfree
make
make install

# Compile nginx with rtmp module
cd /usr/src
wget -O- http://nginx.org/download/nginx-1.8.0.tar.gz | tar zxv
wget -O- https://github.com/arut/nginx-rtmp-module/archive/v1.1.7.tar.gz | tar zxv
wget -O- https://github.com/wandenberg/nginx-push-stream-module/archive/0.5.1.tar.gz | tar zxv
git clone https://github.com/perusio/nginx-auth-request-module.git
wget -O- https://github.com/kaltura/nginx-vod-module/archive/1.2.tar.gz | tar zxv
cd nginx-1.8.0
 CFLAGS="-Wno-deprecated-declarations" ./configure \
  --prefix=/usr \
  --sbin-path=/usr/sbin/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --pid-path=/var/run/nginx.pid \
  --lock-path=/var/lock/subsys/nginx \
  --user=nginx \
  --group=nginx \
  --with-file-aio \
  --with-http_ssl_module \
  --with-http_flv_module \
  --with-http_mp4_module \
  --with-http_secure_link_module \
  --with-http_stub_status_module \
  --add-module=../nginx-rtmp-module-1.1.7 \
  --add-module=../nginx-push-stream-module-0.5.1 \
  --add-module=../nginx-auth-request-module \
  --add-module=../nginx-vod-module-1.2
make
make install
mv /tmp/nginx.service  /usr/lib/systemd/system/

# Sophia SIP
cd /usr/src
wget -O- 'http://downloads.sourceforge.net/project/sofia-sip/sofia-sip/1.12.11/sofia-sip-1.12.11.tar.gz?use_mirror=tcpdiag' | tar zxv
cd sofia-sip-1.12.11
./configure --prefix=/usr/local
make
make install


# libwebsockets
cd /usr/src
git clone git://git.libwebsockets.org/libwebsockets
cd libwebsockets
mkdir build
cd build
cmake ..
make
make install

# libusrsctp
cd /usr/src
svn co http://sctp-refimpl.googlecode.com/svn/trunk/KERN/usrsctp usrsctp
cd usrsctp
./bootstrap
./configure --prefix=/usr/local
make
make install

# Janus WebRTC Gateway
cd /usr/src
wget -O- https://github.com/meetecho/janus-gateway/archive/v0.0.9.tar.gz | tar zxv
cd janus-gateway-0.0.9
bash autogen.sh
PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure \
  --prefix=/usr/local --enable-post-processing \
  --disable-rabbitmq --disable-docs
make
make install


# Firewall
cat <<- "EOF" > /etc/sysconfig/iptables
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT -m comment --comment "ssh"
-A INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT -m comment --comment "http"
-A INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT -m comment --comment "https"
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF

systemctl stop firewalld
systemctl mask firewalld
systemctl enable iptables
systemctl restart iptables

# Increase max file descriptors
cat << EOF >> /etc/security/limits.conf
apps soft nofile 131072
apps hard nofile 131072
nginx soft nofile 131072
nginx hard nofile 131072
haproxy soft nofile 131072
haproxy hard nofile 131072
varnish soft nofile 131072
varnish hard nofile 131072
EOF

# Set the system timezone
ln -sf /usr/share/zoneinfo/US/Eastern /etc/localtime

# users
echo "%wheel ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sed -i 's:^Defaults.*requiretty:# Defaults requiretty:' /etc/sudoers
useradd apps
dd if=/dev/urandom count=50 | md5sum | passwd --stdin apps
passwd -l apps
echo 'export PATH=/usr/local/bin:$PATH' >> /home/apps/.bashrc
echo 'export PATH=/usr/local/bin:$PATH' >> /root/.bashrc

mkdir -p /var/www/html/{flvpreviews,previews}
chown nginx.nginx /var/www/html/flvpreviews
chown apps.apps /var/www/html/previews

cat <<- "EOF" >> /etc/rc.local
chfn -f $(hostname) root
chfn -f $(hostname) apps
EOF
chmod +x /etc/rc.d/rc.local

# Python
cd /usr/src
wget -O- https://www.python.org/ftp/python/2.7.10/Python-2.7.10.tgz | tar zxv
cd Python-2.7.10
./configure --prefix=/usr/local
make
make install
wget -O- https://bootstrap.pypa.io/get-pip.py | /usr/local/bin/python2.7
/usr/local/bin/pip2.7 install virtualenv

systemctl disable rsyslog
systemctl enable syslog-ng
systemctl enable nginx
systemctl enable ntpd
systemctl enable haproxy
systemctl enable redis

yum clean all
rm -rf /tmp/*

# Config files
cat <<- "EOF" > /etc/nginx/conf.d/default.conf
server {
  listen 8080 default_server;
  server_name _;
  location /health {
      return 200 "OK";
      add_header Content-Type text/plain;
      add_header Cache-Control no-cache;
      expires -1d;
  }
  location / {
    root /usr/share/nginx/html;
    index index.html index.htm;
  }
  error_page 500 502 503 504 /50x.html;
  location = /50x.html {
    root /usr/share/nginx/html;
  }
}
EOF

mkdir /etc/nginx/conf.d/rtmp
cat << "EOF" > /etc/nginx/nginx.conf
user nginx;
worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    log_format main '$remote_addr - $remote_user [$time_local] "$http_x_forwarded_proto" '
                    '"$http_host" "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" "$request_time"';
    access_log /var/log/nginx/access.log main;
    client_max_body_size 10m;
    sendfile on;
    #tcp_nopush on;
    keepalive_timeout 65;
    #gzip on;
    include /etc/nginx/conf.d/*.conf;
}
rtmp {
  include /etc/nginx/conf.d/rtmp/*.conf;
}
EOF

cat << "EOF" > /etc/haproxy/haproxy.cfg
global
    log         127.0.0.1 local2
    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon
    stats socket /var/lib/haproxy/stats level admin

defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option                  http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    option                  allbackups
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 3000

frontend fe_http *:80
    stats enable
    stats uri /haproxy/stats
    stats realm HAProxy\ Stats
    stats auth hastats:h@Pr0xY!
    default_backend be_http

backend be_http
    server local-http 127.0.0.1:8888
EOF

sed -i 's:^#compress:compress:' /etc/logrotate.conf
cat << EOF > /etc/logrotate.d/apps
/var/log/apps/*/*log {
        daily
        missingok
        rotate 7
        compress
        delaycompress
        notifempty
        create 640 apps apps
        sharedscripts
}
EOF

cat << "EOF" > /etc/syslog-ng/syslog-ng.conf
@version:3.2
options {
  flush_lines (0);
  time_reopen (10);
  log_fifo_size (1000);
  long_hostnames (off);
  use_dns (no);
  use_fqdn (no);
  create_dirs (no);
  keep_hostname (yes);
};
source s_sys {
  file ("/proc/kmsg" program_override("kernel: "));
  unix-stream ("/dev/log");
  internal();
  udp(ip(127.0.0.1) port(514));
};
destination d_cons { file("/dev/console"); };
destination d_mesg { file("/var/log/messages"); };
destination d_auth { file("/var/log/secure"); };
destination d_mail { file("/var/log/maillog" flush_lines(10)); };
destination d_spol { file("/var/log/spooler"); };
destination d_boot { file("/var/log/boot.log"); };
destination d_cron { file("/var/log/cron"); };
destination d_kern { file("/var/log/kern"); };
destination d_mlal { usertty("*"); };
destination d_haproxy { file("/var/log/haproxy.log"); };
filter f_kernel     { facility(kern); };
filter f_default    { level(info..emerg) and
                        not (facility(mail)
                        or facility(authpriv) 
                        or facility(cron)
                        or facility(local2)); };
filter f_auth       { facility(authpriv); };
filter f_mail       { facility(mail); };
filter f_emergency  { level(emerg); };
filter f_news       { facility(uucp) or
                        (facility(news) 
                        and level(crit..emerg)); };
filter f_boot   { facility(local7); };
filter f_cron   { facility(cron); };
filter f_haproxy   { facility(local2); };
log { source(s_sys); filter(f_kernel); destination(d_kern); };
log { source(s_sys); filter(f_default); destination(d_mesg); };
log { source(s_sys); filter(f_auth); destination(d_auth); };
log { source(s_sys); filter(f_mail); destination(d_mail); };
log { source(s_sys); filter(f_emergency); destination(d_mlal); };
log { source(s_sys); filter(f_news); destination(d_spol); };
log { source(s_sys); filter(f_boot); destination(d_boot); };
log { source(s_sys); filter(f_cron); destination(d_cron); };
log { source(s_sys); filter(f_haproxy); destination(d_haproxy); };
EOF

mkdir -p /etc/foreman/templates/upstart
cat << "EOF" > /etc/foreman/templates/upstart/process.conf.erb
start on starting <%= app %>-<%= name %>
stop on stopping <%= app %>-<%= name %>
respawn

env PORT=<%= port %>
<% engine.env.each do |name,value| -%>
env <%= name.upcase %>='<%= value.gsub(/'/, "'\"'\"'") %>'
<% end -%>

# setuid isnt supported in our version
# of upstart.  we run with su -c instead.
# setuid <%= user %>

chdir <%= engine.root %>

script
test -d virtual && source virtual/bin/activate
exec su -c "<%= process.command %>" <%= user %>
end script
EOF
