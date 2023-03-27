#!/bin/bash
# Developed by Dmitry Bakhanko [https://t.me/bokhanych, https://www.linkedin.com/in/bokhanych/]
clear
echo "# # # # # # # # # # # # # # # # # # # # #"
echo "#  v7 16.03.2023  by Dmitry admin       #"
echo "#  For new openvpn server with settings #"
echo "#  Ubuntu Server 18.04 - 22.04          #"
echo "# # # # # # # # # # # # # # # # # # # # #"

# VARIABLES
echo -n "ENTER SERVER HOSTNAME [Example: ovpnserver]: "; read NEWHOSTNAME;
echo -n "ENTER SERVER SSH PORT [or press <Enter> to generate]: "; read SSH_PORT;
echo -n "ENTER SERVER ROOT PASSWORD [Example: password]: "; read PASSWORD;
echo -n "ENTER CLIENT NAME [Example: CLIENT]: "; read CLIENT_NAME;
PROVIDER="reg.ru"
EXTERNAL_IP=$(hostname  -I | cut -f1 -d' ');
RND_NUMBER=$(echo $((10 + $RANDOM % 200)))
VPN_LAN="10.$RND_NUMBER.$RND_NUMBER.0"
VPN_PORT=$(shuf -i 40000-50000 -n 1);
INET_IFACE=$(ip route get 8.8.8.8 | awk '/dev/ {f=NR} f&&NR-1==f' RS=" ");
if [ "$SSH_PORT" = "" ] 
then
SSH_PORT=$(shuf -i 30000-40000 -n 1);
fi

# CHECK
echo "";
echo "$NEWHOSTNAME - SERVER HOSTNAME";
echo "$EXTERNAL_IP - SERVER EXTERNAL IP";
echo "$INET_IFACE - SERVER INET INTERFACE NAME";
echo "$SSH_PORT - SERVER SSH PORT";
echo "$VPN_PORT - SERVER VPN PORT";
echo "$VPN_LAN - VPN LAN";
echo "$PASSWORD - SERVER ROOT PASSWORD";
echo "$PROVIDER - PROVIDER NAME";
echo "$CLIENT_NAME - CLIENT NAME";
echo "";
echo -n "Is it ok? [Press <Enter> to continue, or any key to exit]: "; read OK;
if [ "$OK" = "" ] 
then

# HOSTNAME and DATE
echo 127.0.0.1 localhost > /etc/hosts;
echo 127.0.0.1 $NEWHOSTNAME >> /etc/hosts;
echo $NEWHOSTNAME > /etc/hostname;
timedatectl set-timezone Europe/Moscow;

# USERS
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

# IPTABLES
mv /etc/iptables/rules.v4 /etc/iptables/rules.v4.bak
mv /etc/iptables/rules.v6 /etc/iptables/rules.v6.bak
cat << EOF > /etc/iptables/rules.v4
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport SSH_PORT -j ACCEPT
-A INPUT -p udp -m udp --dport VPN_PORT -j ACCEPT

-A INPUT -p icmp -m icmp --icmp-type 11 -m limit --limit 1/sec -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -m limit --limit 1/sec -j ACCEPT
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

-A FORWARD -s VPN_LAN/24 -o eth0 -j ACCEPT
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -m state --state INVALID -j DROP
COMMIT

*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s VPN_LAN/24 -o eth0 -j SNAT --to-source EXTERNAL_IP
COMMIT
EOF
cat << EOF > /etc/iptables/rules.v6
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
EOF
sed -i "s%VPN_LAN%$VPN_LAN%g" /etc/iptables/rules.v4;
sed -i "s%EXTERNAL_IP%$EXTERNAL_IP%g" /etc/iptables/rules.v4;
sed -i "s%SSH_PORT%$SSH_PORT%g" /etc/iptables/rules.v4;
sed -i "s%VPN_PORT%$VPN_PORT%g" /etc/iptables/rules.v4;
sed -i "s%eth0%$INET_IFACE%g" /etc/iptables/rules.v4;

# CONNECT TO ANSIBLE
mkdir /root/.ssh/
echo "ssh-rsa <RSA_KEY>" > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# OPENVPN SERVER
apt install -y -q openvpn;
wget -P /tmp/ https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.1/EasyRSA-3.1.1.tgz
tar -C /tmp/ -xvf /tmp/EasyRSA-3.1.1.tgz
mv /tmp/EasyRSA-3.1.1 /etc/openvpn/easy-rsa
# [Server block]
cat << EOF > /etc/openvpn/easy-rsa/vars
set_var EASYRSA_REQ_COUNTRY "RU"
set_var EASYRSA_REQ_PROVINCE "Moscow"
set_var EASYRSA_REQ_CITY "Moscow"
set_var EASYRSA_REQ_ORG "HOSTNAME"
set_var EASYRSA_REQ_EMAIL "HOSTNAME"
set_var EASYRSA_REQ_OU "HOSTNAME"
set_var EASYRSA_ALGO "ec"
set_var EASYRSA_DIGEST "sha512"
set_var EASYRSA_CERT_EXPIRE    3650
EOF
sed -i "s%HOSTNAME%$NEWHOSTNAME%g" /etc/openvpn/easy-rsa/vars;
export EASYRSA_BATCH=1
cd /etc/openvpn/easy-rsa
/etc/openvpn/easy-rsa/easyrsa init-pki
/etc/openvpn/easy-rsa/easyrsa build-ca nopass;
/etc/openvpn/easy-rsa/easyrsa gen-dh
/etc/openvpn/easy-rsa/easyrsa gen-req $NEWHOSTNAME nopass
/etc/openvpn/easy-rsa/easyrsa sign-req server $NEWHOSTNAME
openvpn --genkey --secret pki/ta.key

mkdir /etc/openvpn/$NEWHOSTNAME;
mkdir /etc/openvpn/tmp
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/$NEWHOSTNAME;
cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/$NEWHOSTNAME;
cp /etc/openvpn/easy-rsa/pki/private/$NEWHOSTNAME.key /etc/openvpn/$NEWHOSTNAME/;
cp /etc/openvpn/easy-rsa/pki/reqs/$NEWHOSTNAME.req /etc/openvpn/$NEWHOSTNAME/;
cp /etc/openvpn/easy-rsa/pki/issued/$NEWHOSTNAME.crt /etc/openvpn/$NEWHOSTNAME/;
cp /etc/openvpn/easy-rsa/pki/ta.key  /etc/openvpn/$NEWHOSTNAME/;

cat << EOF > /etc/openvpn/$NEWHOSTNAME.conf
port VPN_PORT
proto udp
dev tun0
ca VPNSERVERNAME/ca.crt
cert VPNSERVERNAME/VPNSERVERNAME.crt
key VPNSERVERNAME/VPNSERVERNAME.key
dh VPNSERVERNAME/dh.pem
server VPN_LAN 255.255.255.0
ifconfig-pool-persist VPNSERVERNAME/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
tls-auth VPNSERVERNAME/ta.key 0
cipher AES-256-GCM
auth SHA256
user nobody
group nogroup
chroot /etc/openvpn
persist-key
persist-tun
status VPNSERVERNAME/openvpn-status.log
log-append VPNSERVERNAME/openvpn.log
verb 2
mute 20
explicit-exit-notify 1
EOF
sed -i "s%VPN_PORT%$VPN_PORT%g" /etc/openvpn/$NEWHOSTNAME.conf;
sed -i "s%VPNSERVERNAME%$NEWHOSTNAME%g" /etc/openvpn/$NEWHOSTNAME.conf;
sed -i "s%VPN_LAN%$VPN_LAN%g" /etc/openvpn/$NEWHOSTNAME.conf;

# [Client block]
mkdir /etc/openvpn/client
mv /etc/openvpn/client /etc/openvpn/clients
cat << EOF >  /etc/openvpn/clients/client1.conf
client
dev tun
proto udp
remote EXTERNAL_IP VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
data-ciphers-fallback AES-256-GCM
auth SHA256
auth-nocache
verb 2
mute 20
keepalive 10 120
key-direction 1
EOF
sed -i "s%EXTERNAL_IP%$EXTERNAL_IP%g" /etc/openvpn/clients/client1.conf;
sed -i "s%VPN_PORT%$VPN_PORT%g" /etc/openvpn/clients/client1.conf;

cp /etc/openvpn/$NEWHOSTNAME/ta.key /etc/openvpn/clients/;
cp /etc/openvpn/$NEWHOSTNAME/ca.crt /etc/openvpn/clients/;
cp /etc/openvpn/$NEWHOSTNAME/dh.pem /etc/openvpn/clients/;

for i in {1..10}
do
cd /etc/openvpn/easy-rsa/
/etc/openvpn/easy-rsa/easyrsa gen-req client$i nopass
/etc/openvpn/easy-rsa/easyrsa sign-req client client$i

cp /etc/openvpn/easy-rsa/pki/issued/client$i.crt /etc/openvpn/clients/;
cp /etc/openvpn/easy-rsa/pki/private/client$i.key /etc/openvpn/clients/;
cp /etc/openvpn/easy-rsa/pki/reqs/client$i.req /etc/openvpn/clients/;

cd /etc/openvpn/clients/
mkdir /etc/openvpn/clients/client$i

sed s/client1/client$i/ < client1.conf > client$i/client$i.ovpn;
echo "<ca>" >> client$i/client$i.ovpn;
cat ca.crt >> client$i/client$i.ovpn;
echo "</ca>" >> client$i/client$i.ovpn;
echo "<cert>" >> client$i/client$i.ovpn;
cat client$i.crt >> client$i/client$i.ovpn;
echo "</cert>" >> client$i/client$i.ovpn;
echo "<key>" >> client$i/client$i.ovpn;
cat client$i.key >> client$i/client$i.ovpn;
echo "</key>" >> client$i/client$i.ovpn;
echo "<tls-auth>" >> client$i/client$i.ovpn;
cat ta.key >> client$i/client$i.ovpn;
echo "</tls-auth>" >> client$i/client$i.ovpn;
done
cd ~
rm /etc/openvpn/clients/*.crt;
rm /etc/openvpn/clients/*.key;
rm /etc/openvpn/clients/*.pem;
rm /etc/openvpn/clients/*.req;
rm /etc/openvpn/clients/client1.conf
mkdir /tmp/$NEWHOSTNAME
cp -r /etc/openvpn/clients/* /tmp/$NEWHOSTNAME/

# FINISH
clear
echo "Remote Desktop Manager:"
echo "$CLIENT_NAME $NEWHOSTNAME $EXTERNAL_IP:$SSH_PORT <USER> $PASSWORD"
echo ""
echo "Ansible:"
echo -e "$CLIENT_NAME\t$PROVIDER\t$NEWHOSTNAME ansible_host=$EXTERNAL_IP ansible_port=$SSH_PORT"
echo ""
echo ""
echo -n "ALL DONE! Press <Enter> to upload configs and reboot: "; read CONTINUE;
if [ "$CONTINUE" = "" ]
then
echo "Enter SFTP-INTERNAL password: "
scp -r -c aes256-cbc -P <SSH_PORT> /tmp/$NEWHOSTNAME <USER>@<SERVER_IP>:~/<PATH>

# CLEAR
sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" dist-upgrade -y;
apt autoremove -y;
shutdown -r;
fi
fi
