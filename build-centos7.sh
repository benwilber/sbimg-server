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

