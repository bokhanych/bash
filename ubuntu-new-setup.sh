#!/bin/bash
# Developed by Dmitry Bakhanko [https://t.me/bokhanych, https://www.linkedin.com/in/bokhanych/]

# RUN:
# bash /tmp/!ubuntu-new-setup.sh srv 22 Y Y Y
#                                  | |  | | |--Install docker? <Y/any>
#                                  | |  | |--Install zabbix-agent? <Y/any>
#                                  | |  |--Enable vcenter fixes? <Y/any>
#                                  | |--SSH port <22 [or 49152-49999]>
#                                  |--New hostname 

# VARIABLES
USER="YOUR_SSH_USER"
PASSWORD='YOUR_SSH_PASSWORD'
SERVER_IP=$(hostname  -I | cut -f1 -d' ')
HOSTNAME=$1
if [ -z "$HOSTNAME" ]; then
    HOSTNAME=$HOSTNAME
fi
SSH_PORT=$2
if [ -z "$SSH_PORT" ]; then
    SSH_PORT="22"
fi
VCENTER_FIX=$3
if [ -z "$VCENTER_FIX" ]; then
    VCENTER_FIX="Y"
fi
ZABBIX_INSTALL=$4
if [ -z "$ZABBIX_INSTALL" ]; then
    ZABBIX_INSTALL="N"
fi
DOCKER_INSTALL=$5
if [ -z "$DOCKER_INSTALL" ]; then
    DOCKER_INSTALL="N"
fi

# CHECK IN:
clear
echo "CHECK IN: "
echo ""
echo "IP address:            "[$SERVER_IP]
echo "New hostname:          "[$HOSTNAME]
echo "SSH port:              "[$SSH_PORT]
echo "Enable vcenter fixes?: "[$VCENTER_FIX]
echo "Install zabbix-agent?: "[$ZABBIX_INSTALL]
echo "Install docker?:       "[$DOCKER_INSTALL]
echo "---"
sleep 8

# VCENTER FIX
if [ "$VCENTER_FIX" = "Y" ] || [ "$VCENTER_FIX" = "y" ]; then
    # DISABLE IPv6
    cp /etc/default/grub /etc/default/grub.bakapa
    GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"
    sed -i "s%GRUB_CMDLINE_LINUX_DEFAULT=""%GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"%g" /etc/default/grub
    update-grub
    # FIX cc_final_message.py[WARNING]: Used fallback datasource
    touch /etc/cloud/cloud-init.disabled
    # DISK EXTEND
    echo -e "d\n3\nn\n3\n\n\n\nw\n" | fdisk /dev/sda
    partprobe
    pvresize /dev/sda3
    lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
    resize2fs /dev/ubuntu-vg/ubuntu-lv
    # LOCAL MIRROR
    cp /etc/apt/sources.list /etc/apt/sources.list.bakapa
    . /etc/os-release && echo $UBUNTU_CODENAME
    echo "deb https://YOUR_LOCAL_MIRROR_ADDRESS/ubuntu $UBUNTU_CODENAME main restricted universe multiverse" > /etc/apt/sources.list
    echo "deb https://YOUR_LOCAL_MIRROR_ADDRESS/ubuntu $UBUNTU_CODENAME-updates main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb https://YOUR_LOCAL_MIRROR_ADDRESS/ubuntu $UBUNTU_CODENAME-security main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb https://YOUR_LOCAL_MIRROR_ADDRESS/ubuntu $UBUNTU_CODENAME-backports main restricted universe multiverse" >> /etc/apt/sources.list
fi

# HOSTNAME, DATE and HISTORY FORMAT
echo 127.0.0.1 localhost > /etc/hosts
echo 127.0.1.1 $HOSTNAME >> /etc/hosts
echo $HOSTNAME > /etc/hostname
timedatectl set-timezone Europe/Minsk
echo 'HISTTIMEFORMAT="%F "' >> ~/.bashrc

# USER
adduser $USER --gecos "" --disabled-password
usermod -aG sudo $USER
echo $USER:$PASSWORD|chpasswd
echo root:$PASSWORD|chpasswd
echo '%sudo   ALL=(ALL:ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudo_nopasswd_all
chmod 440 /etc/sudoers.d/sudo_nopasswd_all

# UPDATE & SOFT
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q && apt-get install net-tools iptables-persistent -y -q
dpkg-reconfigure -f noninteractive unattended-upgrades

# PAM SECURITY
apt-get install libpam-pwquality libpwquality-tools -y -q
cp /etc/pam.d/common-password /etc/pam.d/common-password.bakapa
cat << EOF > /etc/pam.d/common-password
password        requisite                       pam_pwquality.so retry=10 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass yescrypt
password        requisite                       pam_deny.so
password        required                        pam_permit.so
EOF
cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bakapa
cat << EOF > /etc/pam.d/common-auth
auth    required                        pam_faillock.so preauth audit
auth    [success=1 default=ignore]      pam_unix.so
auth    [default=die]                   pam_faillock.so authfail audit deny=6 unlock_time=600
auth    sufficient                      pam_faillock.so authsucc audit deny=6 unlock_time=600
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
EOF
# UNLOCK USER "test": faillock --user test && faillock --user test --reset

# FAIL2BAN
apt-get install fail2ban -y -q
if [[ "$SSH_PORT" != "22" ]]; then
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.bakapa
sed -i "s%port    = ssh%port    = $SSH_PORT%g" /etc/fail2ban/jail.conf
fi
systemctl enable fail2ban

# IPTABLES
cp /etc/iptables/rules.v4 /etc/iptables/rules.v4.bakapa
cp /etc/iptables/rules.v6 /etc/iptables/rules.v6.bakapa
cat << EOF > /etc/iptables/rules.v4
*mangle
:PREROUTING ACCEPT [915:64761]
:INPUT ACCEPT [910:63925]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [797:116043]
:POSTROUTING ACCEPT [797:116043]
COMMIT
*filter
:INPUT DROP [37:3819]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [637:103243]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport SSH_PORT -j ACCEPT
-A INPUT -p icmp -m limit --limit 1/sec -j ACCEPT
#-A INPUT -p tcp -m multiport --dports TCP_PORT1,TCP_PORT2,TCP_PORT3 -j ACCEPT
-A INPUT -m state --state INVALID -j DROP
COMMIT
*nat
:PREROUTING ACCEPT [43:4707]
:INPUT ACCEPT [1:52]
:OUTPUT ACCEPT [28:1913]
:POSTROUTING ACCEPT [28:1913]
COMMIT

# RELOAD IPTABLES:
# /etc/init.d/netfilter-persistent reload && systemctl restart fail2ban
EOF
cat << EOF > /etc/iptables/rules.v6
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
EOF
sed -i "s%SSH_PORT%$SSH_PORT%g" /etc/iptables/rules.v4

# SSHD
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bakapa
cat << EOF > /etc/ssh/sshd_config
Port SSH_PORT
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
LoginGraceTime 20
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
Subsystem sftp /usr/lib/openssh/sftp-server
Banner yes
UsePAM yes
UseDNS no
ClientAliveInterval 7200
ClientAliveCountMax 3
Match User root
PasswordAuthentication no
EOF
sed -i "s%SSH_PORT%$SSH_PORT%g" /etc/ssh/sshd_config
sed -i "s%port    = ssh%port    = $SSH_PORT%g" /etc/fail2ban/jail.conf

# CONNECT TO ANSIBLE
[ -d /root/.ssh ] || mkdir -p /root/.ssh
[ -f /root/.ssh/authorized_keys ] || touch /root/.ssh/authorized_keys
echo "" >> /root/.ssh/authorized_keys
echo -n "YOUR_SSH_KEY" >> /root/.ssh/authorized_keys
echo "" >> /root/.ssh/authorized_keys

# ZABBIX AGENT INSTALL
if [ "$ZABBIX_INSTALL" = "Y" ] || [ "$ZABBIX_INSTALL" = "y" ]; then
    UBUNTU_VERSION=$(awk -F '=' '/DISTRIB_RELEASE/ {print $2}' /etc/lsb-release)
    UBUNTU_VERSION="$UBUNTU_VERSION"_all.deb
    wget https://repo.zabbix.com/zabbix/6.5/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.5-1+ubuntu$UBUNTU_VERSION
    dpkg -i zabbix-release_*.deb
    apt-get -y update && apt-get install zabbix-agent2 -y && systemctl enable zabbix-agent2
    rm -f zabbix-release_*.deb
    openssl rand -hex 32 | tee -a /etc/zabbix/zabbix_agent2.psk;
    chmod 400 /etc/zabbix/zabbix_agent2.psk;
    chown zabbix:zabbix /etc/zabbix/zabbix_agent2.psk
cat << EOF > /etc/zabbix/zabbix_agent2.conf
PidFile=/var/run/zabbix/zabbix_agent2.pid
LogFile=/var/log/zabbix/zabbix_agent2.log
Server=YOUR_ZABBIX_SERVER_IP
Hostname=HOSTNAME
Include=/etc/zabbix/zabbix_agent2.d/*.conf
Timeout=30

#TLSConnect=psk
#TLSAccept=psk
#TLSPSKIdentity=HOSTNAME
#TLSPSKFile=/etc/zabbix/zabbix_agent2.psk

# ZABBIX LOGS AND RESTART:
# tail -fn 20 /var/log/zabbix/zabbix_agent2.log
# systemctl restart zabbix-agent2 && systemctl status zabbix-agent2
EOF
sed -i "s%HOSTNAME%$HOSTNAME%g" /etc/zabbix/zabbix_agent2.conf
fi

# DOCKER INSTALL
if [ "$DOCKER_INSTALL" = "Y" ] || [ "$DOCKER_INSTALL" = "y" ]; then
    curl -sSL https://get.docker.com/ | CHANNEL=stable sh
    systemctl enable --now docker
    if [ "$ZABBIX_INSTALL" = "Y" ] || [ "$ZABBIX_INSTALL" = "y" ]; then
        usermod -aG docker zabbix
    fi
fi

# UPGRADE & REBOOT
apt-get -f -y upgrade && apt-get autoremove -y && reboot