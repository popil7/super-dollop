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
```
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
