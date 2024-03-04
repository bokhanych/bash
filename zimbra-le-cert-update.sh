#!/bin/bash

sed -i "s%#-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT%-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT%g" /etc/iptables/rules.v4;
systemctl restart netfilter-persistent && systemctl restart fail2ban
DATE=$(date "+%d%m%Y")
mkdir -p /opt/zimbra/ssl/letsencrypt/$DATE
certbot renew --standalone --force-renewal --preferred-chain "ISRG Root X1"
cp /etc/letsencrypt/live/$HOSTNAME/* /opt/zimbra/ssl/letsencrypt/$DATE
wget https://letsencrypt.org/certs/isrgrootx1.pem.txt -P /opt/zimbra/ssl/letsencrypt/$DATE
cd /opt/zimbra/ssl/letsencrypt/$DATE
cp isrgrootx1.pem.txt zimbra_chain.pem
cat chain.pem >> zimbra_chain.pem
sudo chown -R zimbra:zimbra /opt/zimbra/ssl/letsencrypt/$DATE
su - zimbra -c "DATE=$(date "+%d%m%Y")"
su - zimbra -c "/opt/zimbra/bin/zmcertmgr verifycrt comm /opt/zimbra/ssl/letsencrypt/$DATE/privkey.pem /opt/zimbra/ssl/letsencrypt/$DATE/cert.pem /opt/zimbra/ssl/letsencrypt/$DATE/zimbra_chain.pem"
cp /opt/zimbra/ssl/letsencrypt/$DATE/cert.pem /opt/zimbra/ssl/zimbra/commercial/commercial.crt
cp /opt/zimbra/ssl/letsencrypt/$DATE/privkey.pem /opt/zimbra/ssl/zimbra/commercial/commercial.key
cp /opt/zimbra/ssl/letsencrypt/$DATE/zimbra_chain.pem /opt/zimbra/ssl/zimbra/commercial/commercial_ca.crt
sudo chown zimbra:zimbra -R /opt/zimbra/ssl/zimbra/commercial
su - zimbra -c "cd /opt/zimbra/ssl/zimbra/commercial && /opt/zimbra/bin/zmcertmgr deploycrt comm commercial.crt commercial_ca.crt"
su - zimbra -c "cd /opt/zimbra/ssl/letsencrypt/$DATE"
su - zimbra -c "ls -la /opt/zimbra/ssl/letsencrypt/$DATE"
su - zimbra -c "zmcontrol restart"
sleep 5
su - zimbra -c "zmcontrol status"
rm -r /opt/zimbra/ssl/letsencrypt/$DATE
sed -i "s%-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT%#-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT%g" /etc/iptables/rules.v4;
systemctl restart netfilter-persistent && systemctl restart fail2ban