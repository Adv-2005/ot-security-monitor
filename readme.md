to run the code(v1)

term1- make sure openplc is running cd ot-security cd OpenPLC_v3 && sudo ./start_openplc.sh
term2- activate conpot env then conpot --template default -f
term3 -cd ot-security-monitor then sudo /opt/zeek/bin/zeek -i any zeek_scripts/ics_monitor.zeek
term4 - source ~/ot-security-env/bin/activate then cd ot-security-monitor 
        if you wanna train model python bootstrap_train.py
        then  python pipeline/zeek_parser.py

term5 - nmap -p 502 --script modbus-discover localhost (normal port)
        nmap -p 5020 --script modbus-discover localhost (conpot port)
        

#next prompt would be to implement phase 6 the dashboard- 
Okay everything is working well according to me. 
OpenPLC is running and conpot is also running and zeek is also running with updated scripts. These are the logs of zeek (logs from terminal3)
sudo /opt/zeek/bin/zeek -C -i any ~/ot-security-monitor/zeek_scripts/ics_monitor.zeek
listening on any

[OT-CONN] 127.0.0.1:46324 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[OT-CONN] 127.0.0.1:46332 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[MODBUS ] src=127.0.0.1  func=17  is_request=T
[MODBUS ] src=127.0.0.1  func=145  is_request=F
[OT-CONN] 127.0.0.1:46336 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[MODBUS ] src=127.0.0.1  func=43  is_request=T
[MODBUS ] src=127.0.0.1  func=171  is_request=F
[OT-CONN] 127.0.0.1:60536 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[OT-CONN] 127.0.0.1:60546 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[MODBUS ] src=127.0.0.1  func=17  is_request=T
[MODBUS ] src=127.0.0.1  func=145  is_request=F
[OT-CONN] 127.0.0.1:60560 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[MODBUS ] src=127.0.0.1  func=43  is_request=T
[MODBUS ] src=127.0.0.1  func=171  is_request=F
[OT-CONN] 127.0.0.1:42858 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[OT-CONN] 127.0.0.1:42866 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[MODBUS ] src=127.0.0.1  func=17  is_request=T
[MODBUS ] src=127.0.0.1  func=145  is_request=F
[OT-CONN] 127.0.0.1:42878 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[MODBUS ] src=127.0.0.1  func=43  is_request=T
[MODBUS ] src=127.0.0.1  func=171  is_request=F
[OT-CONN] 127.0.0.1:47076 \xe2\x86\x92 127.0.0.1:5020  (5020/tcp)
[OT-CONN] 127.0.0.1:58198 \xe2\x86\x92 127.0.0.1:5020  (5020/tcp)
[OT-CONN] 127.0.0.1:54630 \xe2\x86\x92 127.0.0.1:5020  (5020/tcp)
[OT-CONN] 127.0.0.1:60998 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[OT-CONN] 127.0.0.1:32776 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[MODBUS ] src=127.0.0.1  func=17  is_request=T
[MODBUS ] src=127.0.0.1  func=145  is_request=F
[OT-CONN] 127.0.0.1:32784 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[MODBUS ] src=127.0.0.1  func=43  is_request=T
[MODBUS ] src=127.0.0.1  func=171  is_request=F
[OT-CONN] 127.0.0.1:56396 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
[OT-CONN] 127.0.0.1:56406 \xe2\x86\x92 127.0.0.1:502  (502/tcp)
 
and these are the logs from zeek_parser (terminal4)
 python pipeline/zeek_parser.py
[*] Loading NetworkDetector …
[✓] Alert DB: data/alerts.db
[*] Waiting for Zeek conn.log events …

[✓] Tailing /home/advar/zeek-logs/conn.log
[ALERT] CRITICAL | 127.0.0.1:35058 → 127.0.0.1:80 (tcp) | refused_connection | score=3.670
[ALERT] CRITICAL | 127.0.0.1:51062 → 127.0.0.1:443 (tcp) | refused_connection | score=3.670
[ALERT] CRITICAL | 127.0.0.1:60536 → 127.0.0.1:502 (tcp) | ot_protocol_probe | score=19.166
[ALERT] LOW      | 127.0.0.1:60546 → 127.0.0.1:502 (tcp) | ot_protocol_probe | score=-0.639
[ALERT] LOW      | 127.0.0.1:60560 → 127.0.0.1:502 (tcp) | ot_protocol_probe | score=-1.007
[ALERT] CRITICAL | 127.0.0.1:47578 → 127.0.0.1:80 (tcp) | refused_connection | score=3.669
[ALERT] CRITICAL | 127.0.0.1:58288 → 127.0.0.1:443 (tcp) | refused_connection | score=3.670
[ALERT] CRITICAL | 127.0.0.1:42858 → 127.0.0.1:502 (tcp) | ot_protocol_probe | score=19.166
[ALERT] LOW      | 127.0.0.1:42866 → 127.0.0.1:502 (tcp) | ot_protocol_probe | score=-0.746
[ALERT] LOW      | 127.0.0.1:42878 → 127.0.0.1:502 (tcp) | ot_protocol_probe | score=-1.003
[ALERT] CRITICAL | 127.0.0.1:38952 → 127.0.0.1:80 (tcp) | refused_connection | score=3.669
[ALERT] CRITICAL | 127.0.0.1:45836 → 127.0.0.1:443 (tcp) | refused_connection | score=3.670
[ALERT] CRITICAL | 127.0.0.1:47076 → 127.0.0.1:5020 (tcp) | ot_protocol_probe | score=19.166
[ALERT] CRITICAL | 127.0.0.1:52196 → 127.0.0.1:80 (tcp) | refused_connection | score=3.670
[ALERT] CRITICAL | 127.0.0.1:53508 → 127.0.0.1:443 (tcp) | refused_connection | score=3.670
[ALERT] CRITICAL | 127.0.0.1:58198 → 127.0.0.1:5020 (tcp) | ot_protocol_probe | score=19.166
[ALERT] CRITICAL | 127.0.0.1:41866 → 127.0.0.1:80 (tcp) | refused_connection | score=3.670
[ALERT] CRITICAL | 127.0.0.1:52102 → 127.0.0.1:443 (tcp) | refused_connection | score=3.670
[ALERT] CRITICAL | 127.0.0.1:54630 → 127.0.0.1:5020 (tcp) | ot_protocol_probe | score=19.166
[ALERT] CRITICAL | 127.0.0.1:36216 → 127.0.0.1:80 (tcp) | refused_connection | score=3.670
[ALERT] CRITICAL | 127.0.0.1:38348 → 127.0.0.1:443 (tcp) | refused_connection | score=3.670
[ALERT] CRITICAL | 127.0.0.1:60998 → 127.0.0.1:502 (tcp) | ot_protocol_probe | score=19.166
[ALERT] LOW      | 127.0.0.1:32776 → 127.0.0.1:502 (tcp) | ot_protocol_probe | score=-0.485
[ALERT] LOW      | 127.0.0.1:32784 → 127.0.0.1:502 (tcp) | ot_protocol_probe | score=-1.003
[ALERT] CRITICAL | 127.0.0.1:48706 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:48728 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:42800 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:42808 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:42816 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:42830 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:42850 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:42864 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:42880 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:42884 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:50168 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
[ALERT] CRITICAL | 127.0.0.1:50200 → 127.0.0.1:8080 (tcp) | network_anomaly | score=22.026
  … 50 flows processed, 36 alerts so far
and so on

Everytime i do term5 commands

nmap -p 502 --script modbus-discover localhost
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-15 19:57 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00027s latency).

PORT    STATE  SERVICE
502/tcp closed mbap

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds

nmap -p 5020 --script modbus-discover localhost
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-15 19:55 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00030s latency).

PORT     STATE SERVICE
5020/tcp open  zenginkyo-1

logs gets updated with 3 4 lines for terminal 4 and terminal 3 also gets updated and when openplc is running terminal 4 keeps getting updated continously. 

If i hit nmap to conpot port this is the conpot logs
2026-04-15 19:55:25,433 New modbus session from 127.0.0.1 (e3ef5696-ebd1-426b-8201-7ecf6937e83d)
2026-04-15 19:55:25,434 New Modbus connection from 127.0.0.1:58430. (e3ef5696-ebd1-426b-8201-7ecf6937e83d)
ERROR:conpot.protocols.modbus.modbus_server:Exception occurred in ModbusServer.handle() at sock.recv(): [Errno 104] Connection reset by peer
2026-04-15 19:55:25,434 Exception occurred in ModbusServer.handle() at sock.recv(): [Errno 104] Connection reset by peer
2026-04-15 19:55:25,434 Modbus client disconnected. (e3ef5696-ebd1-426b-8201-7ecf6937e83d)
2026-04-15 19:55:57,453 Session timed out: e3ef5696-ebd1-426b-8201-7ecf6937e83d


If all of this is working fine according to you lets implement phase 6 - the dashboard as when i start uvicorn server in another terminal at this point it shows
{"detail":"Not Found"}
Thats it. 