#!/bin/bash
# Developed by Dmitry Bakhanko [https://t.me/bokhanych, https://www.linkedin.com/in/bokhanych/]
clear
echo "# # # # # # # # # # # # # # # # # # # # #"
echo "#  v7 16.03.2023  by Dmitry admin       #"
echo "#  For new forwarders with settings     #"
echo "#  Ubuntu Server 18.04 - 22.04          #"
echo "# # # # # # # # # # # # # # # # # # # # #"

# VARIABLES
echo -n "ENTER PFSENSE WAN IP [Example: 62.10.8.8]: "; read PFS_IP;
echo -n "ENTER PFSENSE VPN SERVER UDP PORT [Example: 2022]: "; read VPN_PORT;
echo -n "ENTER SERVER ROOT PASSWORD [Example: p@ssw0rd]: "; read PASSWORD;
echo -n "ENTER SERVER SSH PORT [or press <Enter> to generate]: "; read SSH_PORT;
echo -n "ENTER ZABBIX TLS ID [Example: 1500]: "; read ZAB_ID;
echo -n "ENTER ZABBIX PSK [or press <Enter> to generate]: "; read ZAB_PSK;
echo -n "ENTER CLIENT NAME [Example: RND]: "; read CLIENT_NAME;
INET_IFACE=$(ip route get 8.8.8.8 | awk '/dev/ {f=NR} f&&NR-1==f' RS=" ");
EXTERNAL_IP=$(hostname  -I | cut -f1 -d' ');
PROVIDER=$(hostname | sed 's/[0-9].*//')
if [ "$SSH_PORT" = "" ] 
then
SSH_PORT=$(shuf -i 30000-40000 -n 1);
fi

# CHECK
echo "";
echo "$PFS_IP - PFSENSE WAN IP";
echo "$VPN_PORT - PFSENSE VPN SERVER UDP PORT";
echo "$EXTERNAL_IP - SERVER EXTERNAL IP";
echo "$INET_IFACE - SERVER INET INTERFACE NAME";
echo "$SSH_PORT - SERVER SSH PORT";
echo "$PASSWORD" - SERVER ROOT PASSWORD;
echo "$PROVIDER - PROVIDER NAME";
echo "$ZAB_ID - ZABBIX TLS ID";
echo "$ZAB_PSK - ZABBIX PSK";
echo "$CLIENT_NAME - CLIENT NAME";
echo "";
echo -n "Is it ok? [Press <Enter> to continue, or any key to exit]: "; read OK;
if [ "$OK" = "" ] 
then

# DATE and USERS
timedatectl set-timezone Europe/Moscow;
adduser <USER> --gecos "" --disabled-password;
usermod -aG sudo <USER>;
echo <USER>:$PASSWORD|chpasswd;

# UPDATE and SOFT
DEBIAN_FRONTEND=noninteractive apt-get -y update;
apt-get -y update;
DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical apt install ssh openssl openssh-server dialog htop iptables-persistent fail2ban net-tools unattended-upgrades apt-listchanges -y -q;
dpkg-reconfigure -f noninteractive unattended-upgrades;

# SYSCTL
mv /etc/sysctl.conf /etc/sysctl.conf.bak;
cat << EOF > /etc/sysctl.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
vm.swappiness = 10
vm.vfs_cache_pressure = 50
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_window_scaling = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_max_orphans = 60000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.wmem_default = 262144
net.core.rmem_default = 262144
net.ipv4.udp_rmem_min = 4096
net.ipv4.udp_wmem_min = 4096
net.ipv4.udp_mem = 4096 786432 4194304
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_workaround_signed_windows = 1
net.core.somaxconn = 1024
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_reordering = 3
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.route.flush = 1
EOF

# FAIL2BAN
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.bak;
sed -i "s%port    = ssh%port    = $SSH_PORT%g" /etc/fail2ban/jail.conf;
systemctl enable fail2ban

# IPTABLES
mv /etc/iptables/rules.v4 /etc/iptables/rules.v4.bak
mv /etc/iptables/rules.v6 /etc/iptables/rules.v6.bak
cat << EOF > /etc/iptables/rules.v4
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 0/0 -o eth0 -j SNAT --to-source AAA_VPS_EXT_IP
-A PREROUTING -s 0/0 -p tcp -m tcp --dport 443 -j DNAT --to-destination DDD_REM_IP:443
-A PREROUTING -s 0/0 -p udp -m udp --dport BBB_VPS_LOC_PORT -j DNAT --to-destination DDD_REM_IP:CCC_REM_PORT
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport EEE_SSH_PORT -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 11 -m limit --limit 1/sec -j ACCEPT
-A INPUT -s <SERVER_IP>/26 -p icmp -m icmp --icmp-type 8 -m limit --limit 1/sec -j ACCEPT
-A INPUT -s <SERVER_IP>/29 -p icmp -m icmp --icmp-type 8 -m limit --limit 1/sec -j ACCEPT
-A INPUT -s <SERVER_IP>/26 -p icmp -m icmp --icmp-type 8 -m limit --limit 1/sec -j ACCEPT
-A INPUT -s <SERVER_IP>/27 -p icmp -m icmp --icmp-type 8 -m limit --limit 1/sec -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 3 -m limit --limit 1/sec -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 0 -m limit --limit 1/sec -j ACCEPT
-A INPUT -s 224.0.0.0/8 -j DROP
-A INPUT -d 224.0.0.0/8 -j DROP
-A INPUT -s 255.255.255.255/32 -j DROP
-A INPUT -d 0.0.0.0/32 -j DROP
-A INPUT -p tcp -m multiport --dports 80,1443,3389,1947,5060,8088,67,68,135,137,138,139,445,631,1025 -j DROP
-A INPUT -p udp -m multiport --dports 80,1443,3389,1947,5060,8088,67,68,135,137,138,139,445,631,1025 -j DROP
-A INPUT -p tcp -m multiport --dports 21,22,23,110,4899,475,8080,8081,5913,123,53,1433 -j DROP
-A INPUT -p udp -m multiport --dports 21,22,23,110,4899,475,8080,8081,5913,123,53,1433 -j DROP
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m state --state INVALID -j DROP
-A INPUT -j LOG
-A FORWARD -s 0/0 -d DDD_REM_IP/32 -i eth0 -p tcp -m tcp --dport 443 -j ACCEPT
-A FORWARD -s 0/0 -d DDD_REM_IP/32 -i eth0 -p udp -m udp --dport CCC_REM_PORT -j ACCEPT
-A FORWARD -s DDD_REM_IP/32 -o eth0 -j ACCEPT
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -m state --state INVALID -j DROP
COMMIT
EOF
cat << EOF > /etc/iptables/rules.v6
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
EOF
sed -i "s%eth0%$INET_IFACE%g" /etc/iptables/rules.v4;
sed -i "s%AAA_VPS_EXT_IP%$EXTERNAL_IP%g" /etc/iptables/rules.v4;
sed -i "s%DDD_REM_IP%$PFS_IP%g" /etc/iptables/rules.v4;
sed -i "s%BBB_VPS_LOC_PORT%$VPN_PORT%g" /etc/iptables/rules.v4;
sed -i "s%CCC_REM_PORT%$VPN_PORT%g" /etc/iptables/rules.v4;
sed -i "s%EEE_SSH_PORT%$SSH_PORT%g" /etc/iptables/rules.v4;

# SSHD
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak;
cat << EOF > /etc/ssh/sshd_config
Port SSHPORT
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 20
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 3
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
X11Forwarding no
X11DisplayOffset 10
PrintMotd no
PrintLastLog no
TCPKeepAlive yes
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
Banner none
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
UseDNS no
ClientAliveInterval 3600
ClientAliveCountMax 0
AllowUsers <USER> root@<REMOTE_SERVER>
EOF
sed -i "s%SSHPORT%$SSH_PORT%g" /etc/ssh/sshd_config;
sed -i "s%port    = ssh%port    = $SSH_PORT%g" /etc/fail2ban/jail.conf;

# ZABBIX 
sudo DEBIAN_FRONTEND=noninteractive apt install zabbix-agent -y;
mv /etc/zabbix/zabbix_agentd.conf /etc/zabbix/zabbix_agentd.conf.bak
cat << EOF > /etc/zabbix/zabbix_agentd.conf
PidFile=/run/zabbix/zabbix_agentd.pid
LogFile=/var/log/zabbix-agent/zabbix_agentd.log
LogFileSize=1
AllowKey=system.run[*]
StartAgents=1
RefreshActiveChecks=3600
Include=/etc/zabbix/zabbix_agentd.conf.d/*.conf   
Timeout=30
Server=<ZABBIX_SERVER_IP>
ListenPort=10150
ServerActive=<ZABBIX_SERVER_IP>:<ZABBIX_SERVER_PORT>
TLSConnect=psk
TLSAccept=psk
TLSPSKFile=/etc/zabbix/zabbix_agentd.psk
EOF
sed -i "12iHostname=$HOSTNAME" /etc/zabbix/zabbix_agentd.conf;
sed -i '24izabbix ALL=(root) NOPASSWD: /usr/bin/fail2ban-client' /etc/sudoers;
sed -i "14iTLSPSKIdentity=ID$ZAB_ID" /etc/zabbix/zabbix_agentd.conf;
> /etc/zabbix/zabbix_agentd.psk;
if [ "$ZAB_PSK" = "" ]
then
openssl rand -hex 32 | tee -a /etc/zabbix/zabbix_agentd.psk;
else echo $ZAB_PSK > /etc/zabbix/zabbix_agentd.psk;
fi
chmod 400 /etc/zabbix/zabbix_agentd.psk;
chown zabbix:zabbix /etc/zabbix/zabbix_agentd.psk;

# CONNECT TO ANSIBLE
mkdir /root/.ssh/
echo "ssh-rsa <RSA_KEY>" > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# UPGRADE
sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" dist-upgrade -y;
apt autoremove -y;

# FINISH
clear
echo "Remote Desktop Manager:"
echo "$CLIENT_NAME $HOSTNAME $EXTERNAL_IP:$SSH_PORT <USER> $PASSWORD"
echo ""
echo "Ansible:"
echo -e "$CLIENT_NAME\t$PROVIDER\t$HOSTNAME ansible_host=$EXTERNAL_IP ansible_port=$SSH_PORT"
echo ""
echo "Zabbix:"
echo "$HOSTNAME $EXTERNAL_IP ID$ZAB_ID $ZAB_PSK"
echo ""
echo ""
echo -n "ALL DONE! Press <Enter> to reboot: "; read REBOOT;
if [ "$REBOOT" = "" ]
then
shutdown -r;
fi
fi
