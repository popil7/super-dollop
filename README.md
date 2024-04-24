Модуль 1
1. имена
HQ-R
hostnamectl set-hostname hq-r(на BR-R, ISP аналогично)
HQ-SRV
hostnamectl set-hostname hq-srv.domain.work(на BR-SRV, CLI аналогтчно)
exec bash
ip
HQ-SRV - IP 192.168.100.2/26 192.168.100.1 VMNET5
HQ-R - IP 192.168.100.1/26 VMNET5, IP 172.15.10.2/30 VMNET2
BR-SRV - IP 192.168.200.2/28 192.168.200.1 VMNET6
BR-R - IP 192.168.200.1/28 VMNET6, 172.15.20.2/30 VMNET3
ISP - IP 172.15.10.1/30 VMNET2, 172.15.20.1/30 VMNET3, 172.15.30.1/30 VMNET4
CLI - IP 172.15.30.2/30 172.15.30.1 VMNET4

![image](https://github.com/popil7/super-dollop/assets/167972537/63f3892c-63fe-4824-9fb1-637c1864f6b9)
серверы DNS на всех машинах, Поисковой домен на CLI и BR-SRV
2.frr
dnf install frr
HQ-R
nano /etc/frr/daemons(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/960a38ba-949d-4fb1-a44f-1ba4adfa1320)
systemctl enable frr
systemctl start frr
vtysh
HQ-R# conf t
HQ-R(config)# route ospf
HQ-R(config-router)# router-id 1.1.1.1
HQ-R(config-router)# network 192.168.100.0/26 area 1
HQ-R(config-router)# ex
HQ-R(config)# ip forwarding
HQ-R(config)# ex
HQ-R# copy running-config startup-config
HQ-R# ex
systemctl restart frr
nano /etc/sysctl.conf(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/4be5f3de-84f5-4911-ae08-cfd802f6ea00)
sysctl -p
на BR-R аналогично

NAT
HQ-R и BR-R
nano /etc/nftables/hq-r.nft(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/57a6538a-2f24-4a48-b107-426d0be90dd3)
nano /etc/sysconfig/nftables.conf(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/ffe6a6e3-aab1-4cc8-b175-ff9c340276e0)
systemctl restart nftables
systemctl enable nftables
ISP
nano /etc/sysctl.conf(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/acecc3f9-c5b1-4515-9522-0a0dac742e1c)
sysctl -p
gre tunnel между hq-r и br-r
HQ-R
nano /etc/gre.up(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/fb54649a-796f-4335-ab2a-89480471f633)
chmod +x /etc/gre.up
nano /etc/crontab(скрин)

![image](https://github.com/popil7/super-dollop/assets/167972537/78bd85ab-f427-42a4-8bf6-e7220d2f3aed)
sh /etc/gre.up
vtysh
HQ-R# conf t
HQ-R(config)# route ospf
HQ-R(config-router)# network 172.16.1.0/30 area 1
HQ-R(config-router)# ex
HQ-R(config)# ex
HQ-R# copy running-config startup-config
HQ-R# ex
systemctl restart frr
gre tunnel между hq-r и cli
на BR-R аналогично

HQ-R
nano /etc/gre.up(скрин)

![image](https://github.com/popil7/super-dollop/assets/167972537/b15efe0d-b1c6-46bc-b894-1386135ebcee)
chmod +x /etc/gre.up
sh /etc/gre.up
vtysh
HQ-R# conf t
HQ-R(config)# route ospf
HQ-R(config-router)# network 172.16.2.0/30 area 1
HQ-R(config-router)# ex
HQ-R(config)# ex
HQ-R# copy running-config startup-config
HQ-R# ex
systemctl restart frr

CLI
nano /etc/gre.up(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/fb2da575-86cc-4880-8f97-88047c89b6a4)
chmod +x /etc/gre.up
nano /etc/crontab(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/ca130a54-e4fc-4d38-add7-112e249f96e8)
sh /etc/gre.up

3.dhcp
HQ-R
dnf install dhcp
nano /etc/dhcp/dhcpd.conf(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/15ea8130-ea7b-4fd9-b2ce-8ea5a9f64cab)
systemctl restart dhcpd
systemctl enable dhcpd
4. учётные записи
CLI, HQ-SRV, HQ-R                        BR-SRV BR-R                        
useradd -с “Admin” admin -U                useradd -с “Branch admin” branch_admin -U
passwd admin                                passwd branch_admin                
пароль: P@ssw0rd                        пароль: P@ssw0rd                

HQ-R BR-R BR-SRV
useradd -с “Network admin” network_admin -U
passwd network_admin
пароль: P@ssw0rd

5.iperf 3
dnf install iperf3
ISP
iperf3 -s
HQ-R
iperf3 -c 172.15.10.1
(скрин)

![image](https://github.com/popil7/super-dollop/assets/167972537/01aa0bb5-3a54-4e08-b9ac-ac21f55878d4)
6.backup
HQ-R
mkdir /var/{backup,backup-script}
nano /var/backup-script/backup.sh(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/8f09ad02-2aea-43a9-a948-5f518b6fc5a5)

chmod +x /var/backup-script/backup.sh
/var/backup-script/backup.sh

BR-R
mkdir /var/{backup,backup-script}
scp user@172.16.1.1:/var/backup-script/backup.sh /var/backup-script/
chmod +x /var/backup-script/backup.sh
/var/backup-script/backup.sh

7.ssh
HQ-SRV
apt install ssh
nano /etc/ssh/sshd_config(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/da0d7c0b-41c5-45c7-a86b-c0e6468e34f9)

systemctl restart sshd
HQ-R
nano /etc/nftables/hq-r.nft(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/1d061394-8be6-4ec3-be6a-1b709e4e35f1)

systemctl restart nftables

8.Настройте контроль доступа до HQ-SRV по SSH со всех устройств, кроме CLI.
nano /etc/hosts.deny(скрин)
HQ-SRV
![image](https://github.com/popil7/super-dollop/assets/167972537/849c78d9-0ab4-4501-8404-c87a6ce5be0d)
systemctl restart sshd

Модуль 2

1.dns
HQ-SRV
apt install bind9
nano /etc/bind/named.conf.local(скрин)

![image](https://github.com/popil7/super-dollop/assets/167972537/a0c0b247-1c78-44c1-9a45-8637d4cef8cc)
cd /etc/bind
mkdir zones
cp db.local zones/db.hq.work                cp db.local zones/db.branch.work
cp db.127 zones/db.100.168.192        cp db.127 zones/db.200.168.192
nano zones/db.hq.work(скрин)        nano zones/db.branch.work(скрин)
nano zones/db.100.168.192(скрин)        nano zones/db.200.168.192(скрин)

![image](https://github.com/popil7/super-dollop/assets/167972537/94300f68-5ab3-4e0f-841d-9ad5f3be96bc)

![image](https://github.com/popil7/super-dollop/assets/167972537/641a34b1-434b-48b3-a410-92eaa391b750)
nano /etc/resolv.conf(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/a7e23d37-d2d6-4d12-a88d-ec90319bb126)

systemctl restart bind9
ping www.hq.work                www.ping branch.work        
HQ-R
nano /etc/resolv.conf(скрин)
так же на BR-R и BR-SRV

2.chrony
apt install chrony
HQ-R
nano /etc/chrony.conf(скрин)

![image](https://github.com/popil7/super-dollop/assets/167972537/dcda345c-8b78-437e-99d1-a00d5fdf08f1)
systemctl restart chronyd
chronyc clients
![image](https://github.com/popil7/super-dollop/assets/167972537/453f2de7-ebde-4b8c-a30e-187021c101e9)
На клиентах
nano /etc/chrony.conf(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/2e0ee69a-e67d-4a39-9871-1f183cdcb8eb)
systemctl restart chronyd
chronyc makestep
chronyc sources -v


3.Domen
HQ-SRV
nano /etc/resolv.conf(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/d05a2340-6a8a-4f6c-95ef-87840fef7413)
nano /etc/hosts(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/e18a896f-d41f-4c13-9212-dbd198cab912)
apt install samba winbind libpam-winbind libnss-winbind libpam-krb5 krb5-config krb5-user krb5-kdc
systemctl stop winbind smbd nmbd krb5-kdc
systemctl mask winbind smbd nmbd krb5-kdc
rm /etc/samba/smb.conf
samba-tool domain provision --use-rfc2307 –-interactive(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/df5b9b27-a746-46e9-ac76-a5d5ab31e7f1)

Password: P@ssw0rd
systemctl unmask samba-ad-dc
systemctl enable samba-ad-dc
nano /etc/bind/named.conf(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/35e63bee-cc32-4397-9d9a-7561d02290d6)
nano /var/lib/samba/bind-dns/named.conf
![image](https://github.com/popil7/super-dollop/assets/167972537/c86f4b09-ce37-4cfc-8611-079857d91cba)
systemctl restart bind9
cp -b /var/lib/samba/private/krb5.conf /etc/krb5.conf
systemctl start samba-ad-dc
reboot
CLI
apt install fly-admin-ad-client
nano /etc/resolv.conf(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/2405e06b-f7a0-4939-8015-582b1a806759)
fly-admin-ad-client(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/36697e0a-ca45-4ca7-a0ad-6a248f5b66c6)
BR-SRV
так же как CLI
fly-admin-ad-client(этого нету, смотри скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/edb2c62e-58b6-4653-a74c-ba3c1f0d367e)
ДРУГОЙ ВАРИАНТ НАСТРОЙКИ DNS и DOMEN ЧЕРЕЗ FREEIPA
HQ-SRV
apt install astra-freeipa-server
nano /etc/hosts(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/a5b2c7bc-7f12-40f0-887b-604e5075fdaf)
astra-freeipa-server -o --ssl
![image](https://github.com/popil7/super-dollop/assets/167972537/9769b9bc-d53e-4bac-a5cc-3d578c0b0148)
![image](https://github.com/popil7/super-dollop/assets/167972537/6394bdcc-e315-4744-a3ac-35c54b4c52d0)
branch аналогично
CLI
apt install fly-admin-freeipa-client
fly-admin-freeipa-clien
![image](https://github.com/popil7/super-dollop/assets/167972537/b43a01e4-c9ae-4adf-a530-c6f6a2beecdf)
BR-SRV
nano /usr/lib/python3.8/site-packages/ipalib/constants.py(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/ab86539f-228b-4b7e-b080-09061824d454)
В NAME_REGEX добавили \-
![image](https://github.com/popil7/super-dollop/assets/167972537/ea883940-eef7-4e8c-97bb-f9a7233d9293)

4.NFS
HQ-SRV
apt install nfs-server
systemctl enable nfs-server
useradd -с “Branch admin” branch_admin -U
passwd branch_admin                
useradd -с “Network admin” network_admin -U
passwd network_admin
mkdir /var/nfs
mkdir /var/nfs/Admin_Files, mkdir /var/nfs/Network, mkdir /var/nfs/Branch_Files
chown admin:admin /var/nfs/Admin_Files        
chown network_admin:network_admin /var/nfs/Network        
chown branch_admin:branch_admin /var/nfs/Branch_Files
usermod -u 1111 admin, usermod -u 1110 network_admin, usermod -u 1100 branch_admin
groupmod -g 1111admin,groupmod -g 1110 network_admin,groupmod -g 1100 branch_admin
(такие же id на других машинах в соответствии с пользователями)
nano /etc/exports(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/299fee8f-a4b4-4f6f-8f10-ada333bab8cb)
exportfs -a
HQ-R
mount 192.168.100.2:/var/nfs/Admin_Files/ /mnt/
mount 192.168.100.2:/var/nfs/Network/ /mnt/
nano /etc/crontab(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/2de97291-dbe7-4ff9-8d21-e4d347b2e24b)
На других машинах также в соответствии с пользователями которых создали
CLI
apt install nfs-client
mount 192.168.100.2:/var/nfs/Admin_Files/ /mnt/
nano /etc/crontab(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/88ed0c0e-a687-4a69-8125-0f3fa2d954b6)
На других машинах также в соответствии с пользователями которых создали

6.Docker
HQ-SRV
apt install docker-compose
docker pull mediawiki
nano wiki.yml(скрин)
![image](https://github.com/popil7/super-dollop/assets/167972537/28953c3a-5faf-4ef6-9274-cda0e5a65668)
docker-compose -f wiki.yml up
![image](https://github.com/popil7/super-dollop/assets/167972537/e558c813-fb16-4573-96d0-d500bea337ad)
![image](https://github.com/popil7/super-dollop/assets/167972537/bf3502d4-3561-4b62-9269-813abdafaeda)
![image](https://github.com/popil7/super-dollop/assets/167972537/8b32574a-7d3d-41bd-9655-ecef87cd6588)
![image](https://github.com/popil7/super-dollop/assets/167972537/7607d1ed-454c-4f76-8710-33461dc41cfc)
![image](https://github.com/popil7/super-dollop/assets/167972537/aeeec0ca-163a-4387-836c-52a4c9be2078)
cp Загрузки/LocalSettings.php ./
![image](https://github.com/popil7/super-dollop/assets/167972537/cb343e2a-5658-409c-9dbd-55725c53229d)
(Раскомментировали)
docker-compose -f wiki.yml up
![image](https://github.com/popil7/super-dollop/assets/167972537/5901f24d-d3c6-44c4-937f-c66d5a091430)





# DEMO2024-APRIL
## Модуль 1
1. Выполните базовую настройку всех устройств:
   - a. Присвоить имена в соответствии с топологией
   - b. Рассчитайте IP-адресацию IPv4. Необходимо заполнить таблицу №1, чтобы эксперты могли проверить ваше рабочее место.
   - c. Пул адресов для сети офиса BRANCH - не более 16
   - d. Пул адресов для сети офиса HQ - не более 64
2. Настройте внутреннюю динамическую маршрутизацию по средствам FRR. Выберите и обоснуйте выбор протокола динамической маршрутизации из расчёта, что в дальнейшем сеть будет масштабироваться.
   - a. Составьте топологию сети L3.
3. Настройте автоматическое распределение IP-адресов на роутере HQ-R.
   - a. Учтите, что у сервера должен быть зарезервирован адрес. 
4. Настройте локальные учётные записи на всех устройствах в соответствии с таблицей 2.
5. Измерьте пропускную способность сети между двумя узлами HQ-R-ISP по средствам утилиты iperf 3. Предоставьте описание пропускной способности канала со скриншотами.
6. Составьте backup скрипты для сохранения конфигурации сетевых устройств, а именно HQ-R BR-R. Продемонстрируйте их работу.
7. Настройте подключение по SSH для удалённого конфигурирования устройства HQ-SRV по порту 2222. Учтите, что вам необходимо перенаправить трафик на этот порт по средствам контролирования трафика.
8. Настройте контроль доступа до HQ-SRV по SSH со всех устройств, кроме CLI.

Топология сети

![КОД 09 02](https://github.com/ItzVektor/DEMO2023-DECEMBER-NEW/assets/47023804/8ce4e027-2508-48fa-8cb9-7fa8c3665c1f)

Таблица № 1 (готовая и отредактированная)

| Имя устройства  | IP | Маска    | Шлюз        | IPv6 + префикс  | Шлюз IPv6       | VMnet  | Примечание |
| ------ | ----------- | -------- | ----------- | --------------- | --------------- | ------ | ---------- |
| ISP    | 2.2.2.1     | .252 /30 |             | 2024:2::1/64    |                 | VMnet2 | |
|        | 3.3.3.1     | .252 /30 |             | 2024:3::1/64    |                 | VMnet3 | |
|        | 4.4.4.1     | .252 /30 |             | 2024:4::1/64    |                 | VMnet4 | |
| HQ-R   | 2.2.2.2     | .252 /30 | 2.2.2.1     | 2024:2::2/64    | 2024:2::1/64    | VMnet2 | |
|        | 192.168.0.1 | .192 /26 |             | FD24:192::1/122 |                 | VMnet5 | |
|        | 10.0.0.1    | .252 /30 |             | FD24:10::1/64   |                 | tun1   | |
|        | 5.5.5.1     | .252 /30 |             | 2024:5::1/64    |                 | VMnet7 | Временная |
| HQ-SRV | 192.168.0.2 | .192 /26 | 192.168.0.1 | FD24:192::2/122 | FD24:192::1/122 | VMnet5 | DHCP |
| BR-R   | 3.3.3.2     | .252 /30 | 3.3.3.1     | 2024:3::2/64    | 2024:3::1/64    | VMnet3 | |
|        | 172.16.0.1  | .240 /28 |             | FD24:172::1/124 |                 | VMnet6 | |
|        | 10.0.0.2    | .252 /30 |             | FD24:10::2/64   |                 | tun1   | |
| BR-SRV | 172.16.0.2  | .240 /28 | 172.16.0.1  | FD24:172::2/124 | FD24:172::1/124 | VMnet6 | |
| CLI    | 4.4.4.2     | .252 /30 | 4.4.4.1     | 2024:4::2/64    | 2024:4::1/64    | VMnet4 | |
|        | 5.5.5.2     | .252 /30 | 5.5.5.1     | 2024:5::2/64    | 2024:5::1/64    | VMnet7 | Временная |


Таблица №2

| Учётная запись | Пароль   | Примечание       |
| -------------- | -------- | ---------------- |
| Admin          | P@ssw0rd | CLI HQ-SRV HQ-R  |
| Branch admin   | P@ssw0rd | BR-SRV BR-R      |
| Network admin  | P@ssw0rd | HQ-R BR-R BR-SRV |


### 1. Выполните базовую настройку всех устройств:
### a. Присвоить имена в соответствии с топологией
#### ALL
```
hostnamectl set-hostname ISP / HQ-R / BR-R / BR-SRV / HQ-SRV / CLI
exec bash
```

b. Рассчитайте IP-адресацию IPv4. 

Необходимо заполнить таблицу №1, чтобы эксперты могли проверить ваше рабочее место.

c. Пул адресов для сети офиса BRANCH - не более 16

d. Пул адресов для сети офиса HQ - не более 64 

Настраиваем через nmtui или NetworkManager по таблице (На HQ-SRV задаём только IPv6 адрес)

### 1.1 Настройка NAT с помощью встроенного nftables.

#### HQ-R и BR-R
```![Uploading image.png…]()

nano /etc/nftables/isp.nft
----
table inet my_nat {
        chain my_masquerade {
        type nat hook postrouting priority srcnat;
        oifname "ens33" masquerade
        }
}
----
nano /etc/sysconfig/nftables.conf
----
include "/etc/nftables/isp.nft"
----
systemctl enable --now nftables
```

### 2. Настройте внутреннюю динамическую маршрутизацию по средствам FRR. Выберите и обоснуйте выбор протокола динамической маршрутизации из расчёта, что в дальнейшем сеть будет масштабироваться.

> Сначала настраиваем GRE-туннель для связи HQ и BRANCH

> Настраиваем через nmtui (т.к. там есть галочка "Подключаться автоматически")

#### HQ-R

![image](https://github.com/ItzVektor/DEMO2024-APRIL/assets/47023804/e9bcbe3f-6d47-4f60-8a2e-e9745234b114)
![image](https://github.com/ItzVektor/DEMO2024-APRIL/assets/47023804/7b63bbee-346e-495b-9323-a966866dcf8a)

```
nmcli connection modify tun1 ip-tunnel.ttl 64
```

#### BR-R

> Аналогично, но с обратными IP-адресами.

> Далее идёт основная настройка маршрутизации по OSPFv2 и OSPFv3

#### ISP, HQ-R и BR-R

```
nano /etc/sysctl.conf
----
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
----
sysctl -p
```

#### HQ-R
```
su
dnf install -y frr

nano /etc/frr/daemons
----
ospfd=yes
ospf6d=yes
----
systemctl enable --now frr
vtysh

conf t
router ospf
router-id 2.2.2.2
network 10.0.0.0/30 area 0
network 192.168.0.0/26 area 0
exit

router ospf6
ospf6 router-id 2.2.2.2
exit
int tun1
ipv6 ospf6 area 0
exit
int ens34
ipv6 ospf6 area 0
CTRL + Z

copy ru st
exit

systemctl restart frr
```
#### BR-R
```
su
dnf install -y frr

nano /etc/frr/daemons
----
ospfd=yes
ospf6d=yes
----
systemctl enable --now frr
vtysh
conf t
router ospf
router-id 3.3.3.3
network 10.0.0.0/30 area 0
network 172.16.0.0/28 area 0
exit

router ospf6
ospf6 router-id 3.3.3.3
exit
int tun1
ipv6 ospf6 area 0
exit
int ens34
ipv6 ospf6 area 0
CTRL + Z

copy ru st
exit

systemctl restart frr
```

### 3. Настройте автоматическое распределение IP-адресов на роутере HQ-R.
   - a. Учтите, что у сервера должен быть зарезервирован адрес. 

#### HQ-R
```
su
dnf install -y dhcp
nano /etc/dhcp/dhcpd.conf
----
subnet 192.168.0.0 netmask 255.255.255.192 {
        range 192.168.0.3 192.168.0.62;
        option domain-name-servers 192.168.0.2;
        option routers 192.168.0.1;
}
host hq-srv {
	hardware ethernet 00:0c:29:e3:00:37;
	fixed-address 192.168.0.2;
}
----
systemctl enable --now dhcpd
На HQ-SRV меняем /etc/hosts
Также там должен быть IPv4 адрес по DHCP, а IPv6 по статике. Иначе никак.
```

### 4. Настройте локальные учётные записи на всех устройствах в соответствии с таблицей 2.

#### CLI и HQ-SRV (Astra Linux)
```
sudo su
adduser Admin --force-badname
P@ssw0rd
P@ssw0rd
usermod -aG sudo Admin

passwd root
toor
toor
reboot
```

#### HQ-R
```
su
adduser Admin
passwd Admin
P@ssw0rd
P@ssw0rd
usermod -aG wheel Admin

adduser Network_admin
passwd Network_admin
P@ssw0rd
P@ssw0rd
usermod -aG wheel Network_admin
```

#### BR-R и BR-SRV
```
su
adduser Branch_admin
passwd Branch_admin
P@ssw0rd
P@ssw0rd
usermod -aG wheel Branch_admin

adduser Network_admin
passwd Network_admin
P@ssw0rd
P@ssw0rd
usermod -aG wheel Network_admin
reboot
```

### 5. Измерьте пропускную способность сети между двумя узлами HQ-R-ISP по средствам утилиты iperf 3. Предоставьте описание пропускной способности канала со скриншотами.

#### ISP
```
dnf install iperf -y
iperf3 -s
```
#### HQ-R
```
dnf install iperf -y
iperf3 -c 2.2.2.1
ждём
iperf3 -s
```
#### ISP
```
CTRL+C
iperf3 -c 2.2.2.2
```
Скриншотим, закидываем в отчёт.

### 6. Составьте backup скрипты для сохранения конфигурации сетевых устройств, а именно HQ-R BR-R. Продемонстрируйте их работу.

#### HQ-R
```
mkdir /var/{backup,backup-script}
cd /var/backup-script
nano backup.sh
----
#!/bin/bash

data=$(date +%d.%m.%y-%H:%M:%S)
mkdir /var/backup/$data
cp -r /etc/frr /var/backup/$data
cp -r /etc/nftables /var/backup/$data
cp -r /etc/NetworkManager/system-connections /var/backup/$data
cp -r /etc/dhcp /var/backup/$data
cd /var/backup
tar czfv "./$data.tar.gz" ./$data
rm -r /var/backup/$data
----
chmod +x backup.sh
./backup.sh
```

#### BR-R
```
mkdir /var/{backup,backup-script}
scp user@10.0.0.1:/var/backup-script/backup.sh /var/backup-script
cd /var/backup-script
chmod +x backup.sh
./backup.sh
```
В отчёт пишем путь до скрипта.

### 7. Настройте подключение по SSH для удалённого конфигурирования устройства HQ-SRV по порту 2222. Учтите, что вам необходимо перенаправить трафик на этот порт по средствам контролирования трафика.

#### HQ-SRV
```
nano /etc/ssh/sshd_config
----
Port 2222
----
```

### 8. Настройте контроль доступа до HQ-SRV по SSH со всех устройств, кроме CLI.

#### HQ-SRV
```
nano /etc/hosts.deny
----
sshd: 4.4.4.1, 10.0.0.6
----
systemctl restart sshd
```

## Модуль 2: Организация сетевого администрирования
Задание модуля 2
1. Настройте DNS-сервер на сервере HQ-SRV:
   - a. На DNS сервере необходимо настроить 2 зоны

Зона hq.work, также не забудьте настроить обратную зону.

|Имя                 |Тип записи    |Адрес     |
|  ----------------- |  ----------- |  ------- |
|hq-r.hq.work        |A, PTR        |IP-адрес  |
|hq-srv.hq.work      |A, PTR        |IP-адрес  |

Зона branch.work

|Имя                 |Тип записи    |Адрес     |
|  ----------------- |  ----------- |  ------- |
|br-r.branch.work    |A, PTR        |IP-адрес  |
|br-srv.branch.work  |A             |IP-адрес  |

2. Настройте синхронизацию времени между сетевыми устройствами по протоколу NTP. 
   - a. В качестве сервера должен выступать роутер HQ-R со стратумом 5
   - b. Используйте Loopback интерфейс на HQ-R, как источник сервера времени
   - c. Все остальные устройства и сервера должны синхронизировать свое время с роутером HQ-R
   - d. Все устройства и сервера настроены на московский часовой пояс (UTC +3)
3. Настройте сервер домена выбор, его типа обоснуйте, на базе HQ-SRV через web интерфейс, выбор технологий обоснуйте.
   - a. Введите машины BR-SRV и CLI в данный домен
   - b. Организуйте отслеживание подключения к домену
4. Реализуйте файловый SMB или NFS (выбор обоснуйте) сервер на базе сервера HQ-SRV.
   - a. Должны быть опубликованы общие папки по названиям:
      - i. Branch_Files - только для пользователя Branch admin;
      - ii. Network - только для пользователя Network admin;
      - iii. Admin_Files - только для пользователя Admin;
b. Каждая папка должна монтироваться на всех серверах в папку /mnt/<name_folder> (например, /mnt/All_files) автоматически при входе доменного пользователя в систему и отключаться при его выходе из сессии. Монтироваться должны только доступные пользователю каталоги.
5. Сконфигурируйте веб-сервер LMS Apache на сервере BR-SRV:
   - a. На главной странице должен отражаться номер места
   - b. Используйте базу данных mySQL
   - c. Создайте пользователей в соответствии с таблицей, пароли у всех пользователей «P@ssw0rd»

| Пользователь | Группа  |
| ------------ | ------- |
| Admin        | Admin   |
| Manager1     | Manager |
| Manager2     | Manager |
| Manager3     | Manager |
| User1        | WS      |
| User2        | WS      |
| User3        | WS      |
| User4        | WS      |
| User5        | TEAM    |
| User6        | TEAM    |
| User7        | TEAM    |

6. Запустите сервис MediaWiki используя docker на сервере HQ-SRV.
   - a. Установите Docker и Docker Compose.
   - b. Создайте в домашней директории пользователя файл wiki.yml для приложения MediaWiki:
      - i. Средствами docker compose должен создаваться стек контейнеров с приложением MediaWiki и базой данных
      - ii. Используйте два сервиса;
      - iii. Основной контейнер MediaWiki должен называться wiki и использовать образ mediawiki;
      - iv. Файл LocalSettings.php с корректными настройками должен находиться в домашней папке пользователя и автоматически монтироваться в образ;
      - v. Контейнер с базой данных должен называться db и использовать образ mysql;
      - vi. Он должен создавать базу с названием mediawiki, доступную по стандартному порту, для пользователя wiki с паролем DEP@ssw0rd;
      - vii. База должна храниться в отдельном volume с названием dbvolume.

MediaWiki должна быть доступна извне через порт 8080.



### 1. Настройте DNS-сервер на сервере HQ-SRV:
   - a. На DNS сервере необходимо настроить 2 зоны

#### HQ-SRV
Через веб-интерфейс FreeIPA настраиваем записи по таблице
(создаём зоны hq.work, branch.work, две обратные зоны, записи к ним)
```
Тестирование
host br-r.branch.work
nslookup br-r.branch.work
nslookup 172.16.0.2
```

### 2. Настройте синхронизацию времени между сетевыми устройствами по протоколу NTP. 
   - a. В качестве сервера должен выступать роутер HQ-R со стратумом 5
   - b. Используйте Loopback интерфейс на HQ-R, как источник сервера времени
   - c. Все остальные устройства и сервера должны синхронизировать свое время с роутером HQ-R
   - d. Все устройства и сервера настроены на московский часовой пояс (UTC +3)

#### HQ-R
```
dnf install -y chrony

nano /etc/chrony.conf
(комментируем все server и пишем свой)
----
server 1oopback iburst

# Allow NTP client access from local network.
allow 0.0.0.0/0
allow ::/0

# Serve time even if not synchronized to a time source.
local stratum 5
----
systemctl enable --now chronyd
На HQ-R проверяем работу после подключений устройств
chronyc serverstats
chronyc tracking
```

#### BR-R, BR-SRV, HQ-SRV, CLI
```
timedatectl set-timezone Europe/Moscow
nano /etc/chrony.conf (на HQ-SRV и CLI путь /etc/chrony/chrony.conf)
----
server 192.168.0.1 iburst
----
systemctl enable --now chronyd
systemctl restart chronyd
chronyc tracking
```

### 3. Настройте сервер домена выбор, его типа обоснуйте, на базе HQ-SRV через web интерфейс, выбор технологий обоснуйте.

#### HQ-SRV

> Настройка домена FreeIPA

```
apt install fly-admin-freeipa-server astra-freeipa-server
apt install libastraevents
```
```
nano /etc/hosts
----
127.0.0.1       localhost
#127.0.1.1      HQ-SRV
192.168.0.2     DC.domain.work      DC
----
nano /etc/resolv.conf
----
search domain.work
nameserver 192.168.0.2
----
hostnamectl set-hostname dc.domain.work
systemctl disable docker
reboot
```
```
astra-freeipa-server -o --ssl
----
Домен - domain.work
Имя - dc
Админ - admin
Пароль - P@ssw0rd
----
Готово. Заходим внутрь по ссылке и настраиваем DNS.
```

#### BR-SRV
```
На RedOS нужно поправить конфиги.
nano /usr/lib/python3.8/site-packages/ipalib/constants.py 
----
Меняем строку ниже
NAME_REGEX = r'^[a-z][_a-z0-9\-]*[a-z0-9]$|^[a-z]$'
(только добавляем \-)
----
Далее входим в домен.
Пуск -> Системные -> Ввод ПК в домен
Домен Windows/IPA -> ОК
Имя домена - domain.work
Имя компьютера - HQ-R
Имя админстратора - Administrator
Пароль администратора - P@ssw0rd
```

#### CLI
```
apt install fly-admin-freeipa-client
apt install astra-freeipa-client

hostnamectl set-hostname cli.domain.work
fly-admin-freeipa-client
----
Контроллер домена - dc.domain.work
Имя домена - domain.work
Администратор домена - admin
Пароль - P@ssw0rd
----
Если у вас ошибка и появляется кнопка "Отключиться" - вы в домене.
```

### 4. Реализуйте файловый SMB или NFS (выбор обоснуйте) сервер на базе сервера HQ-SRV.
- a. Должны быть опубликованы общие папки по названиям:
   - i. Branch_Files - только для пользователя Branch admin;
   - ii. Network - только для пользователя Network admin;
   - iii. Admin_Files - только для пользователя Admin;
- b. Каждая папка должна монтироваться на всех серверах в папку /mnt/<name_folder> (например, /mnt/All_files) автоматически при входе доменного пользователя в систему и отключаться при его выходе из сессии. Монтироваться должны только доступные пользователю каталоги.

#### HQ-SRV
```
apt install nfs-server -y
systemctl enable --now nfs-server

mkdir -p /nfs/{Branch_Files,Network,Admin_Files}
cd /nfs

chown -R branch_admin:branch_admin /nfs/Branch_Files
chown -R network_admin:network_admin /nfs/Network
chown -R admin:admins /nfs/Admin_Files/
chmod -R 700 /nfs/

nano /etc/exports
----
/nfs/Branch_Files *(rw,sync,no_subtree_check)
/nfs/Network *(rw,sync,no_subtree_check)
/nfs/Admin_Files *(rw,sync,no_subtree_check)
----

exportfs -ra
```
#### BR-SRV
```
mkdir -p /mnt/{Branch_Files,Network,Admin_Files}
nano /home/branch_admin/.bash_profile
----
echo toor | su root -c "mount 192.168.0.2:/nfs/Branch_Files /mnt/Branch_Files"
----
nano /home/network_admin/.bash_profile
----
echo toor | su root -c "mount 192.168.0.2:/nfs/Network /mnt/Network"
----
nano /home/admin/.bash_profile
----
echo toor | su root -c "mount 192.168.0.2:/nfs/Admin_Files /mnt/Admin_Files"
----
```

### 5. Сконфигурируйте веб-сервер LMS Apache на сервере BR-SRV:
   - a. На главной странице должен отражаться номер места
   - b. Используйте базу данных mySQL
   - c. Создайте пользователей в соответствии с таблицей, пароли у всех пользователей «P@ssw0rd»

| Пользователь | Группа  |
| ------------ | ------- |
| Admin        | Admin   |
| Manager1     | Manager |
| Manager2     | Manager |
| Manager3     | Manager |
| User1        | WS      |
| User2        | WS      |
| User3        | WS      |
| User4        | WS      |
| User5        | TEAM    |
| User6        | TEAM    |
| User7        | TEAM    |

#### BR-SRV
```
nano /etc/selinux/config
----
setenforce 0
----
dnf install httpd
dnf install php81-release
dnf clean all
dnf makecache
dnf update php*
dnf install php php-mysqlnd php-pdo php-gd php-mbstring php-zip php-intl php-soap
nano /etc/php.ini
----
max_input_vars=6000
----
systemctl enable --now httpd
dnf install mariadb-server mariadb
systemctl enable mariadb --now
mysql -u root -p

CREATE DATABASE moodledb DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;
CREATE USER moodleuser@localhost IDENTIFIED BY 'P@ssw0rd';
GRANT ALL ON moodledb.* TO moodleuser@localhost;
flush privileges;
quit;

systemctl restart mariadb

wget https://packaging.moodle.org/stable403/moodle-latest-403.tgz -P /home
tar -xzf /home/moodle-latest-403.tgz -C /var/www/html
chmod -R 0755 /var/www/html/moodle
chmod -R apache:apache /var/www/html/moodle
mkdir /var/moodledata
chown -R 0755 /var/moodledata
chmod -R apache:apache /var/moodledata
Далее настройка по адресу http://172.16.0.2/moodle
```
```
Фактически нужно только сменить путь к папке, запомнить порт 3306 и всё
После установки создаём юзеров по заданию и всё
```


### 6. Запустите сервис MediaWiki используя docker на сервере HQ-SRV.
   - a. Установите Docker и Docker Compose.
   - b. Создайте в домашней директории пользователя файл wiki.yml для приложения MediaWiki:
      - i. Средствами docker compose должен создаваться стек контейнеров с приложением MediaWiki и базой данных
      - ii. Используйте два сервиса;
      - iii. Основной контейнер MediaWiki должен называться wiki и использовать образ mediawiki;
      - iv. Файл LocalSettings.php с корректными настройками должен находиться в домашней папке пользователя и автоматически монтироваться в образ;
      - v. Контейнер с базой данных должен называться db и использовать образ mysql;
      - vi. Он должен создавать базу с названием mediawiki, доступную по стандартному порту, для пользователя wiki с паролем DEP@ssw0rd;
      - vii. База должна храниться в отдельном volume с названием dbvolume.

MediaWiki должна быть доступна извне через порт 8080.

#### HQ-SRV
```
sudo su
apt install docker docker-compose -y
docker pull mediawiki
docker pull mysql
cd /home/Admin
nano wiki.yml
```
```
----
version: '3'
services:
  wiki:
    image: mediawiki
    restart: always
    ports:
      - 8080:80
    links:
      - db
    volumes:
      - images:/var/www/html/images
      #- ./LocalSettings.php:/var/www/html/LocalSettings.php
  db:
    image: mysql
    restart: always
    environment:
      MYSQL_DATABASE: mediawiki
      MYSQL_USER: wiki
      MYSQL_PASSWORD: DEP@ssw0rd
      MYSQL_RANDOM_ROOT_PASSWORD: 'yes'
    volumes:
      - dbvolume:/var/lib/mysql

volumes:
  images:
  dbvolume:
----
--- Имеем в виду, что строчка с LocalSettings закомментирована! ---
docker-compose -f wiki.yml up
Терминал не закрываем!
```
```
Подключаемся в браузере 192.168.0.2:8080, проверяем запуск и ошибку LocalSettings.php not found.
Нажимаем Set up the wiki
Далее -> Далее (лицензия)
----
Хост базы данных: db (т.е. название сервиса базы данных в файле yml, по заданию)
Имя базы данных: mediawiki (по заданию, в файле yml это MYSQL_DATABASE)
Префикс не указываем
Имя пользователя базы данных: wiki (по заданию, MYSQL_USER)
Пароль базы данных: DEP@ssw0rd (по заданию, MYSQL_PASSWORD)
----
Далее (оставляем галку на учетке для бд)
Задаём любое название
Вписываем свои данные учетки с прошлого шага
Вместо "Произвести тонкую настройку" ставим галку на "Хватит, установить вики"
Далее -> Далее -> Далее
Установка завершена, дальше окончательная настройка
У нас скачался файл LocalSettings.php, скидываем его в home по заданию (хрен знает какого юзера)
cp /home/Admin/Загрузки/LocalSettings.php /home/Admin/
nano /home/Admin/comp.yml
здесь мы убираем комментирование строки LocalSettings.php выше
Сохраняем, готово
Закрываем docker командой ctrl+c и запускаем снова
Должна отобразиться заглавная страница
```
