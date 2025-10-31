#!/bin/bash
RC=0
export DEBIAN_FRONTEND=noninteractive

# Avoid sysvinit errors
cat > /usr/sbin/policy-rc.d <<EOF
#!/bin/bash
exit 101
EOF
chmod +x /usr/sbin/policy-rc.d
dpkg-divert --local --rename --add /sbin/initctl

# Update system
apt-get -y update && apt-get -y install --no-install-recommends locales
sed -i -e 's/^[[:blank:]]*#[[:blank:]]*en_US.UTF-8[[:blank:]]*UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
printf "LANG=en_US.UTF-8\nLANGUAGE=en_US.UTF-8\n" > /etc/default/locale
dpkg-reconfigure locales && update-locale LANG=en_US.UTF-8 || let RC+=1

# Install more test depedencies

apt-get -y install --no-install-recommends rsyslog bc vim lsof sqlite3 haproxy postgresql-$PGVER \
           postgresql-client-common isag jq git html2text \
           debconf-utils zsh htop python-is-python3 \
           parallel netcat-openbsd wget lsb-release gnupg ca-certificates || let RC+=1
apt-get -y install ssl-cert || let RC+=1
apt-get -y autoremove

# Configure rsyslog
sed -i 's/^[[:blank:]]*#\([[:blank:]]*.*imudp.*\)/\1/' /etc/rsyslog.conf
rm /etc/rsyslog.d/*haproxy*conf
printf "local2.*    /var/log/haproxy.log\n& ~\n" > /etc/rsyslog.d/haproxy.conf
printf "local0.*    /var/log/postgres.log\n& ~\n" > /etc/rsyslog.d/postgres.conf

# Clean up APT when done.
apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

exit $RC
