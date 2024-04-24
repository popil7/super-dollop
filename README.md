# Модуль 1
## 1. Выполните базовую настройку всех устройств:
```
hostnamectl set-hostname dc.domain.work
```
Раздать адреса всем, проверить сетевки.
Включаем ip_forward:
```
nano /etc/sysctl.conf
```
Пишу туда строчку:
```
net.ipv4.ip_forward = 1
```
Применение настройки.
```
sysctl -p
```
#### GRE TUNNEL
Настройка GRE осуществляется с помощью скрипта на bash. Создаю nano /etc/gre.up.
Наполнение файла(HQ-R):
```
#!/bin/bash
ip tunnel add tun1 mode gre local 2.2.2.2 remote 3.3.3.2 ttl 255
ip link set tun1 up
ip addr add 172.16.1.1/30 dev tun1
```
```
chmod +x /etc/gre.up
```
Редактирую файл nano /etc/crontab. Туда вношу наш скрипт:
```
@reboot root /etc/gre.up
```
Запускаем скрипт:
```
sh /etc/gre.up
```
Наполнение файла(CLI):
```
#!/bin/bash
ip tunnel add tun2 mode gre local 1.1.1.2 remote 2.2.2.2 ttl 255
ip link set tun2 up
ip addr add 172.16.2.2/30 dev tun2
ip route add 192.168.100.0/26 via 172.16.2.1
```
## 2. FRR
```
dnf install frr
systemctl start frr
systemctl enable frr
```
В файле заменяем no на yes у нужного протокола.
```
nano /etc/frr/daemons
```
Обязательный перезапуск после.
```
systemctl restart frr
```
Чтоб попасть в режим настройки пишу vtysh
Вот такие настройки надо указать:
#### HQ-R
```
router ospf
router-id 1.1.1.1
network 192.168.100.0/26 area 0
network 172.16.1.0/30 area 0
network 172.16.2.0/30 area 0
exit
copy ru st
```
```
systemctl restart frr
```
> [!WARNING]
> Проверить в sh ru наличие данных строк:
```
interface tun1
ip ospf network broadcast
```
Без этой команды на каждом tun1 работать не будет, может сама появится.
```
systemctl restart frr
```
#### NAT
```
nano /etc/nftables/new_nat.nft
```
```
table inet new_nat {
        chain my_masquerade {
        type nat hook postrouting priority srcnat;
        oifname "ens33" masquerade
        }
}
```
```
nano /etc/sysconfig/nftables.conf
```
```
include "/etc/nftables/new_nat.nft"
```
```
systemctl enable nftables
systemctl start nftables
```
## 3. Нужно создать DHCP сервер на HQ-R
> [!WARNING]
> Отключить на всех машинах лишние интерфейсы, чтоб они не получили данные адреса.
Устанавливаем DCHP:
```
dnf install dhcp
systemctl start dhcpd
systemctl enable dhcpd
```
```
nano /etc/dhcp/dhcpd.conf
```
Содержание файла:
```
subnet 192.168.100.0 netmask 255.255.255.192 {
        range 192.168.100.3 192.168.100.62;
        option routers 192.168.100.1;
        option domain-name "domain.work";
        option domain-name-servers 192.168.100.2;
}

host hq-srv {
        hardware ethernet 00:0C:29:D9:9F:40;
        fixed-address 192.168.100.2;
}
```
Перезапускаем службу
```
systemctl restart dhcpd
```
## 4. Настройка учетных записей.
Процедура настройки
```
adduser admin
passwd admin
usermod -aG sudo/wheel admin
```
Смена учетной записи
```
su название учетки
```
## 5. IPERF3
```
dnf install iperf3
```
Pапускаем на стороне сервера (ISP)
```
iperf3 -s 
```
После запускаем на стороне клиента
```
iperf3 -c 2.2.2.1
```
## 6. Backup
Создание директории для хранения криптов. Создание самого крипта.
```
mkdir /etc/backups
nano /etc/backup
```
Содержание скрипта:
```
!/bin/bash
cp /etc/frr/frr.conf /etc/backups/frr_config.txt
```
```
chmod +x /etc/backup
```
## 7-8. SSH смена порта, перенаправления трафика, CLI отрезан.
Для начала на всех маших создаем публичный ключ и копируем его на HQ-SRV.
```
ssh-keygen
ssh-copy-id admin@192.168.100.2 
```
После этого выключаем авторизацию по паролю и меняем port на 2222:
```
nano /etc/ssh/sshd_config
Port 2222
PasswordAuthentication no
```
```
systemctl restart sshd
```
# Модуль 2
## 1. DNS на HQ-SRV
```
cd /etc/bind
cp db.local hq
cp db.local br
cp db.127 hq-rev
cp db.127 br-rev
```
Далее либо заполняем зоны либо файл /etc/bind/named.conf.local
```
nano /etc/bind/named.conf.local
zone "hq.work" {
        type master;
        file "/etc/bind/hq";
};

zone "100.168.192.in-addr.arpa" {
        type master;
        file "/etc/bind/hq-rev";
};

zone "branch.work" {
        type master;
        file "/etc/bind/br";
};

zone "200.168.192.in-addr.arpa" {
        type master;
        file "/etc/bind/br-rev";
};
```
Дальше зоны заполняем по таблице. Обязательны точки после любого доменного имени. Пишу короткие имена www, hq-srv, hq-r.
## 2. CHRONYD на HQ-R
Захожу в конфиг /etc/chrony.conf убираю все лишние сервера # комментируя строки. Нужно изменить такие строки:
```
server 127.0.0.1 iburst
allow 192.168.0.0/16
allow 172.16.0.0/16
local stratum 5
```
Обязательно рестарт службы:
```
systemctl restart chronyd
```
На клиентах заходим в /etc/chrony.conf и оставляет только строчку:
```
server 192.168.100.1 iburst
```
Обязательно рестарт службы:
```
systemctl restart chronyd
```
Проверка работы:
```
chronyc tracking
```
## 3. DOMAIN на HQ-SRV
> [!WARNING]
> На HQ-SRV, чтоб не сломать домен нужно заранее отключить докер: systemctl stop docker; systemctl disable docker.
Проверяю файл nano /etc/hosts комментирую строку с astra. Дописываю строку:
```
192.168.100.2 dc.domain.work dc
```
Устанавливаем пакеты:
```
apt install samba winbind libpam-winbind libnss-winbind libpam-krb5 krb5-config krb5-user krb5-kdc
```
Останавливаем лишние службы:
```
systemctl stop winbind smbd nmbd krb5-kdc
systemctl mask winbind smbd nmbd krb5-kdc
```
Удаляем стандартный конфиг самбы, его можно удалить если произошла поломка в конфигурации:
```
rm /etc/samba/smb.conf
```
Команда конфигурации самбы все значения по стандарту, кроме BIND9_DLZ:
```
samba-tool domain provision --use-rfc2307 --interactive
```
Убираем маску и запускаем:
```
systemctl unmask samba-ad-dc
systemctl enable samba-ad-dc
```
Добавляем в named.conf библиотеку днс самбы:
```
nano /etc/bind/named.conf
include "/var/lib/samba/bind-dns/named.conf";
```
```
systemctl restart bind9
```
Проверяю на наличие базы данных:
```
nano /var/lib/samba/bind-dns/named.conf
```
Копирую конфиг krb5 в /etc/:
```
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
```
Запускаем службу AD-DC:
```
systemctl start samba-ad-dc
reboot
```
### CLI 
```
apt install fly-admin-ad-client
nano /etc/resolv.conf
fly-admin-ad-client
```
### BR-SRV
Добавляю в домен утилитой Ввод в домен.
## 4. NFS сервер на HQ-SRV (ДОПОЛНИТЬ и ИСПРАВИТЬ)
Включаю в автозапуск NFS сервер на всякий случай:
```
systemctl enable nfs-server
```
Создаю каталог для хранения папок и создаем все требующиеся папки:
```
mkdir -p /var/nfs/Network
mkdir -p /var/nfs/Admin_Files
mkdir -p /var/nfs/Branch_Files
```
Теперь когда имеем эти каталоги нужно соблюсти одинаковых пользователей их gid uid и чтоб они являлись владельцами файлов.
```
usermod -u 1010 admin
groupmod -g 1010 admin
chown admin:admin /var/nfs/Admin_Files
```
Чтоб узнать учетные запяси можно прописать
```
id admin
```
Дальше настраиваем /etc/exports
```
/var/nfs/Admin_Files *(rw,sync,no_subtree_check,anonuid=1010,anongid=1010)
```
Применяем настройки
```
exportfs -a
```
Захожу в директорию и создаю там файл:
```
cd /var/nfs/Admin_Files
touch 123.txt 
```
На клиентах создаем такого же абсолютно пользователя лучше везде писать всех с маленькой буквы создавать.
```
usermod -u 1010 admin
groupmod -g 1010 admin
mount 192.168.100.2:/var/nfs/Admin_Files /mnt/
cd /mnt/
ls -a
```
## 5. LMS Apache
