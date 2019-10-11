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

sed -i -e 's/^[[:blank:]]*#[[:blank:]]*en_US.UTF-8[[:blank:]]*UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
printf "LANG=en_US.UTF-8\nLANGUAGE=en_US.UTF-8\n" > /etc/default/locale
dpkg-reconfigure locales && update-locale LANG=en_US.UTF-8 || let RC+=1

# Configure rsyslog
sed -i 's/^[[:blank:]]*#\([[:blank:]]*.*imudp.*\)/\1/' /etc/rsyslog.conf
rm /etc/rsyslog.d/*haproxy*conf
printf "local2.*    /var/log/haproxy.log\n& ~\n" > /etc/rsyslog.d/haproxy.conf

# Use python2, not 3
sudo ln -s /usr/bin/python2.7 /usr/local/bin/python && sudo chmod 777 /usr/local/bin/python || let RC+=1

exit $RC
