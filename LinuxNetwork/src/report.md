# Linux NetWork


## 1. Инструмент ipcalc
### 1.1. Сети и маски
1. Адрес сети 192.167.38.54/13 =  `192.160.0.0`

2. Перевод маски 255.255.255.0 в префиксную и двоичную запись:
    - префиксная: /24
    - двоичная: 11111111.11111111.11111111.00000000
- Перевод маски /15 в обычную и двоичную: 
    - обычная: 255.254.0.0
    - двоичная: 11111111.11111110.00000000.00000000
- Перевод маски 11111111.11111111.11111111.11110000 в обычную и префиксную:
    - обычная: 255.255.255.240
    - перфиксная: /28
    
3. Минимальный и максимальный хост в сети 12.167.38.4 при масках: /8, 11111111.11111111.00000000.00000000, 255.255.254.0 и /4:
    - /8: 
        - min: 12.0.0.1
        - max: 12.255.255.254
    - 11111111.11111111.00000000.00000000: 
        - min: 12.167.0.1
        - max: 12.167.255.254
    - 255.255.254.0: 
        - min: 12.167.38.1
        - max: 12.167.39.254
    - /4: 
        - min: 0.0.0.1
        - max: 15.255.255.254
### 1.2. localhost
- Определить и записать в отчёт, можно ли обратиться к приложению, работающему на localhost, со следующими IP: 194.34.23.100, 127.0.0.2, 127.1.0.1, 128.0.0.1
    - 194.34.23.100: нельзя
    - 127.0.0.2: можно
    - 127.1.0.1: можно
    - 128.0.0.1: нельзя 
### 1.3. Диапазоны и сегменты сетей
1. Какие из перечисленных IP можно использовать в качестве публичного, а какие только в качестве частных: 10.0.0.45, 134.43.0.2, 192.168.4.2, 172.20.250.4, 172.0.2.1, 192.172.0.1, 172.68.0.2, 172.16.255.255, 10.10.10.10, 192.169.168.1:
    - 10.0.0.45 - частные
    - 134.43.0.2 - публичные
    - 192.168.4.2 - частные
    - 172.20.250.4 - частные
    - 172.0.2.1 - частные
    - 192.172.0.1 - публичные
    - 172.68.0.2 - публичные
    - 172.16.255.255 - частные
    - 10.10.10.10 - частные
    - 192.169.168.1 - публичные

2. Какие из перечисленных IP адресов шлюза возможны у сети 10.10.0.0/18: 10.0.0.1, 10.10.0.2, 10.10.10.10, 10.10.100.1, 10.10.1.255
    - 10.0.0.1 - не может, не попадает под маску;
    - 10.10.0.2 - вообщем может, но в основном выделяется хост номер 1;
    - 10.10.10.10 - вообщем может, но в основном выделяется хост номер 1;
    - 10.10.100.1 - не может, не попадает под маску;
    - 10.10.1.255 - может;

## 2. Статическая маршрутизация между двумя машинами
1. С помощью команды `ip a` посмотреть существующие сетевые интерфейсы: \
![interfaces](../misc/images/screen%20network/ip_a.png)

2. Описать сетевой интерфейс, соответствующий внутренней сети, на обеих машинах и задать следующие адреса и маски: ws1 - 192.168.100.10, маска /16, ws2 - 172.24.116.8, маска /12:
    - ws1: \
    ![3 interfaces ws1](../misc/images/screen%20network/ws1ipYaml.png)

    - ws2: \
    ![3 interfaces ws2](../misc/images/screen%20network/ws2ipYaml.png)


3. Выполнить команду netplan apply для перезапуска сервиса сети:
    - ws1 command `netplan apply`: \
    ![netpla apply ws1](../misc/images/screen%20network/netplaapllytws1.png)

    - ws2 command `netplan apply`: \
    ![netplan apply ws2](../misc/images/screen%20network/ws2netplanapply.png)

### 2.1. Добавление статического маршрута вручную
1. Добавить статический маршрут от одной машины до другой и обратно при помощи команды вида ip r add:
    - ws1: \
    ![netplan apply ws2](../misc/images/screen%20network/ip_r_add_ws1_ws2.png)

    - ws2: \
    ![netplan apply ws2](../misc/images/screen%20network/ip_r_add_ws2_ws1.png)

    - `ip r add [добовляемый] via [в тот который добавляем]`
    - `netplan apply`

2. Пропинговать соединение между машинами:
    - ws1 ping: \
    ![ping ws1](../misc/images/screen%20network/pingWs1.png)

    - ws2 ping: \
    ![ping ws1](../misc/images/screen%20network/pingWs2.png)

### 2.2. Добавление статического маршрута с сохранением
1. Перезапустить машины: `reboot`

2. Добавить статический маршрут от одной машины до другой с помощью файла etc/netplan/00-installer-config.yaml:
    - ws1: \
    ![yaml ws1](../misc/images/screen%20network/2yamlWs1.png)

    - ws2: \
    ![yaml ws1](../misc/images/screen%20network/2yamlWs2.png)

3. Пропинговать соединение между машинами:
    - ws1: \
    ![ping 2 ws1](../misc/images/screen%20network/2pingWs1.png)

    - ws2: \
    ![ping 2 ws2](../misc/images/screen%20network/2pingWs2.png)

## 3. Утилита iperf3
### 3.1. Скорость соединения
1. Перевести и записать в отчёт: 8 Mbps в MB/s, 100 MB/s в Kbps, 1 Gbps в Mbps:
    - 8 Mbps в MB/s: `1MB/s`
    - 100 MB/s в Kbps: `819200 kbps`
    - 1 Gbps в Mbps: `1024 Mbps`

### 3.2. Утилита iperf3
1. Измерить скорость соединения между ws1 и ws2:
    - ws1: \
    ![ipref3 ws1](../misc/images/screen%20network/ipref3Ws1.png)

    - ws2: \
    ![ipref3 ws2](../misc/images/screen%20network/ipref3Ws2.png)

## 4. Сетевой экран
### 4.1. Утилита iptables
1. Создать файл /etc/firewall.sh, имитирующий фаерволл, на ws1 и ws2:
    - ws1: \
    ![firewall ws1](../misc/images/screen%20network/firewallWs1.png)

    - ws2: \
    ![firewall ws2](../misc/images/screen%20network/firewallWs2.png)


2. Запустить файлы на обеих машинах командами chmod +x /etc/firewall.sh и /etc/firewall.sh:
    - ws1: \
    ![firewall start ws1](../misc/images/screen%20network/startFirewallWs1.png)

    - ws2: \
    ![firewall start ws2](../misc/images/screen%20network/startFirewallWs1.png)

    - Описать разницу между стратегиями, применёнными в первом и втором файлах:
        - ws1: Приходит пакет с пингом попадает таблицу фильтр смотрит первое правило (пинг не пускать). И первое правило его дропает и никуда не пускает,соотвественно на второе правило этот пакет не попадает
        - ws2 (Первое правило разрешено, а второе правило запрещено): летит пакет с пингом попадает в таблицу, смотрит первое правило (пинг - пропустить). И полетел пакет дальше. Так как ему разрешено, он уже не заходит во второе правило.

### 4.2. Утилита nmap
1. Командой ping найти машину, которая не "пингуется", после чего утилитой nmap показать, что хост машины запущен:
    - `ping`
        - ws1: \
        ![ping nmap ws1](../misc/images/screen%20network/nmapPingWs1.png)

        - ws2: \
        ![ping nmap ws2](../misc/images/screen%20network/nmapPingWs2.png)

    - `nmap`: \
    ![nmap host up](../misc/images/screen%20network/nmapHostUp.png)

## 5. Статическая маршрутизация сети
### 5.1. Настройка адресов машин
1. Настроить конфигурации машин в etc/netplan/00-installer-config.yaml согласно сети на рисунке:
    - ws11: \
    ![config ws11](../misc/images/screen%20network/config_ws11.png)

    - r1: \
    ![config r1](../misc/images/screen%20network/config_r1.png)

    - r2: \
    ![config r2](../misc/images/screen%20network/config_r2.png)

    - ws21: \
    ![config ws21](../misc/images/screen%20network/config_ws21.png)

    - ws22: \
    ![config ws21](../misc/images/screen%20network/config_ws22.png)

2. Перезапустить сервис сети. Если ошибок нет, то командой ip -4 a проверить, что адрес машины задан верно. Также пропинговать ws22 с ws21. Аналогично пропинговать r1 с ws11:
    - ip ws22: \
    ![ip ws22](../misc/images/screen%20network/ip_4_a.png)

    - netplan ws22: \
    ![ping r1](../misc/images/screen%20network/sudo_netplan_apply_ws22.png)

    - ping ws22 c ws21: \
    ![ping ws22](../misc/images/screen%20network/first_ping_ws21_ws22.png)

    - ip r1: \
    ![ip r1](../misc/images/screen%20network/ip_4_a_r1.png)

    - netplan r1: \
    ![ping r1](../misc/images/screen%20network/sudo_netplan_apply_r1.png)

    - ping r1 c ws11: \
    ![ping r1](../misc/images/screen%20network/new_ping_ws11_r1.png)


### 5.2. Включение переадресации IP-адресов.
1. Для включения переадресации IP, выполните команду на роутерах:
    - r1: \
    ![forwarding r1](../misc/images/screen%20network/forwardingR1.png)

    - r2: \
    ![forwarding r2](../misc/images/screen%20network/forwardingR2.png)

2. Откройте файл /etc/sysctl.conf и добавьте в него следующую строку:
    - r1: \
    ![forwarding config r1](../misc/images/screen%20network/forwardingR1const.png)

    - r2: \
    ![forwarding config r2](../misc/images/screen%20network/forwardingR1const.png)

### 5.3. Установка маршрута по-умолчанию
1. Настроить маршрут по-умолчанию (шлюз) для рабочих станций. Для этого добавить gateway4 [ip роутера] в файле конфигураций:
    - ws11: \
    ![config ws11](../misc/images/screen%20network/config_ws11.png)

    - ws21: \
    ![config ws21](../misc/images/screen%20network/config_ws21.png)

    - ws22: \
    ![config ws21](../misc/images/screen%20network/config_ws22.png)


2. Вызвать ip r и показать, что добавился маршрут в таблицу маршрутизации: \
![default gateway4](../misc/images/screen%20network/defaultgatewayWs11.png)

3. Пропинговать с ws11 роутер r2 и показать на r2, что пинг доходит. Для этого использовать команду:
-`tcpdump -tn -i eth1`: \
![default gateway4](../misc/images/screen%20network/pingWs11R2.png)

- ping: \
![default gateway4](../misc/images/screen%20network/pingWs11_R2.png)

### 5.4. Добавление статических маршрутов
1. Добавить в роутеры r1 и r2 статические маршруты в файле конфигураций. Пример для r1 маршрута в сетку 10.20.0.0/26:
    - r1: \
    ![static r1](../misc/images/screen%20network/staticR1.png)

    - r2: \
    ![static r2](../misc/images/screen%20network/staticR2.png)

2. Вызвать ip r и показать таблицы с маршрутами на обоих роутерах:
    - r1: \
    ![config r1](../misc/images/screen%20network/config_r1.png)

    - r2: \
    ![config r2](../misc/images/screen%20network/config_r2.png)

3. Запустить команды `ip r list 10.10.0.0/[маска сети]` и `ip r list 0.0.0.0/0` на ws11: \
    ![list ws1](../misc/images/screen%20network/listWs11.png)

    - `В отчёте объяснить, почему для адреса 10.10.0.0/[порт сети] был выбран маршрут, отличный от 0.0.0.0/0, хотя он попадает под маршрут по-умолчанию:`
    маршрутизатор выбирает маршрут с самой длинной маской, так как это самое точное решение. И другие маршруты не будут выбраны если есть альтернативные.
### 5.5. Построение списка маршрутизаторов
1.  `tcpdum`: \
![tcpdum](../misc/images/screen%20network/dumpR1_ws11_ws21.png)

2. `traceroute`: \
![traceroute](../misc/images/screen%20network/traceroute_ws11_ws21.png)

3. `Traceroute` - делает трассировку маршрута до указанного узла, отправляя серию пакетов, это может быть UDP по умолчанию, TCP, ICMP-пакеты, увеличивая этот параметр с каждым хостом на единицу.

### 5.6. Использование протокола ICMP при маршрутизации
1. Запустить на r1 перехват сетевого трафика, проходящего через eth0 с помощью команды: \
![tcpdum No Ping](../misc/images/screen%20network/dumpNonPing.png)

2. Пропинговать с ws11 несуществующий IP (например, 10.30.0.111) с помощью команды: \
![No Ping](../misc/images/screen%20network/nonPing.png)

### 6. Динамическая настройка IP с помощью DHCP
1. Для r2 настроить в файле /etc/dhcp/dhcpd.conf конфигурацию службы DHCP: \
![dhcp R2](../misc/images/screen%20network/dhcpR2.png)

2. В файле resolv.conf прописать nameserver 8.8.8.8.: \
![nameserver](../misc/images/screen%20network/nameserverR2.png)

3. Перезагрузить службу DHCP командой systemctl restart isc-dhcp-server. Машину ws21 перезагрузить при помощи reboot и через ip a показать, что она получила адрес. Также пропинговать ws22 с ws21.
    - Restart dhcp: \
    ![restart dhcp](../misc/images/screen%20network/restart_dhcp.png)

    - ws21 `ip a`: \
    ![ws21 ip a](../misc/images/screen%20network/ip_a_ws21_reboot.png)

    - ws22 `ip a`: \
    ![ws21 ip a](../misc/images/screen%20network/ip_a_ws22_reboot.png)

    - ws21 ping ws22: \
    ![ws21 ping ws22](../misc/images/screen%20network/new_ip_ping_ws21_ws22.png)

4. Указать MAC адрес у ws11, для этого в etc/netplan/00-installer-config.yaml надо добавить строки: macaddress:
    - `yaml` \
    ![macaddres ws11](../misc/images/screen%20network/macaddres_ws11.png)

    - `10:10:10:10:10:BA`: \
    ![macaddress ws11](../misc/images/screen%20network/macaddress_ws11.png)


5. Для r1 настроить аналогично r2, но сделать выдачу адресов с жесткой привязкой к MAC-адресу (ws11). Провести аналогичные тесты:
    - r1: \
    ![dhcp r1](../misc/images/screen%20network/dhcp_r1_macadd.png)

    - ws11 `ip a`: \
    ![ws11 ip a](../misc/images/screen%20network/ip_a_ws11_reboot.png)

    - ping ws1 -> r1: \
    ![dhcp r1](../misc/images/screen%20network/new_ping_ws11_r1.png)

6. Запросить с ws21 обновление ip адреса:
    - до: \
    ![ip old ws21](../misc/images/screen%20network/ip_a_ws21_reboot.png)

    - после: \
    ![ip old ws21](../misc/images/screen%20network/dhclient_ws21_newip.png)

    - опции: `-r – освободить текущий адрес`;

### 7. NAT
1. В файле /etc/apache2/ports.conf на ws22 и r2 изменить строку Listen 80 на Listen 0.0.0.0:80, то есть сделать сервер Apache2 общедоступным:
    - r2: \
    ![apache r2](../misc/images/screen%20network/apache_port_r2.png)

    - ws22: \
    ![apache ws22](../misc/images/screen%20network/apache_port_ws22.png)

2. Запустить веб-сервер Apache командой service apache2 start на ws22 и r1:
    - ws22: \
    ![apache start ws22](../misc/images/screen%20network/apache_start_ws22.png)

    - r1: \
    ![apache start ws22](../misc/images/screen%20network/apache_start_r1.png)

    - firewall: \
    ![firewall start r2](../misc/images/screen%20network/firewall_first_r2.png)

    - firewall command: \
    ![firewall command](../misc/images/screen%20network/firewall_command_r2.png)



3. Проверить соединение между ws22 и r1 командой ping:
    - ping: \
    ![ping ws22 r1](../misc/images/screen%20network/apache_no_ping_ws22_r1.png)


4. Проверить соединение между ws22 и r1 командой ping:
    - ping: \
    ![ping2 ws22 r1](../misc/images/screen%20network/apache_ping_r1_ws22.png)

5. `Включить SNAT`, а именно маскирование всех локальных ip из локальной сети, находящейся за r2, `Включить DNAT` на 8080 порт машины r2 и добавить к веб-серверу Apache, запущенному на ws22, доступ извне сети: \
![telnet_ws22](../misc/images/screen%20network/telnet_ws22.png)
![telnet_r1](../misc/images/screen%20network/telnet_r1.png)
![firewall r2](../misc/images/screen%20network/dnat_firewall_r2.png)

### 8. Дополнительно. Знакомство с SSH Tunnels
1. Воспользоваться Local TCP forwarding с ws21 до ws22, чтобы получить доступ к веб-серверу на ws22 с ws21:
    - apache2 start: \
    ![apache2 start](../misc/images/screen%20network/apache_start_ws22.png)

    - window 1: \
    ![ssh ws21 ws22](../misc/images/screen%20network/ssh_ws21_ws22.png)

    - window 2: \
    ![ssh ws21 ws22 window 2](../misc/images/screen%20network/ssh_ws21_ws22_2_window.png)

2. Воспользоваться Remote TCP forwarding c ws11 до ws22, чтобы получить доступ к веб-серверу на ws22 с ws11:
    - window 1: \
    ![ssh ws11 ws22](../misc/images/screen%20network/ssh_ws11_ws22_new.png)

    - window 2: \
    ![ssh ws11 ws22 window 2](../misc/images/screen%20network/ssh_ws21_ws22_2_window.png)

    - описание команд:
    ssh -L (пробросить порт) локальный_порт:удаленный_адрес:удаленный_порт пользователь@сервер

    - описание команд:
    ssh -R  (доступ локального сервиса на удаленной машине) локальный_порт:удаленный_адрес:удаленный_порт пользователь@сервер