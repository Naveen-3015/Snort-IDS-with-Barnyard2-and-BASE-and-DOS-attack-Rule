# Snort-IDS  
Snort with Barnyard and BASE With DOS attack rule.

Software Requirement 
Operating system : linux(debian 8.6.0)                                                                                                              
Tools: Snort (2.9.8.3)                                                                                                                      
Barnyard2(2.0.6)                                                                                                                                
Base(2.9.2.2)                                                                                                                                               
Server: MySql

Architecture:                                                                                                                                                                       
First install snort.                                                                                                                                
Then install barnyard2 and then                                                                                                                         
Base(Basic Analysis and Security Engine).                                                                                                                                               
Working                                                                                                                                         
After configuring snort with barnyard2 the output of snort which is in binary format will go to the barnyard2 and it will then convert it into a human binary format. We have created an database, barnyard2 will save its output in this database. We have configure base such that it will fetch the data from database and show it in a web front end.   

SNORT:                                                                                                                                        
Snort is a free open source Network Intrusion Detection System (NIDS) and Network Intrusion Prevention System (NIPS).           Created by Martin Roesch in 1998. Snort is now developed by CISCO from 2013.                                                          With the help of Snort we can perform real-time traffic analysis, it also used to detect attacks, etc. Snort can work as Intrusion Detection System (IDS) and Intrusion Prevention System (IPS), Snort as IDS generate an alert if there is anysuspicious activity is going on in the network, and Snort as IPS prevent any suspicious or unauthorized or malicious activity on network by monitoring and scanning network traffic.                                                                                                           Snort is also a well-functional packet sniffer and packet logger. In addition to these features,Snort supports other useful functions such as sending real-time alerts, closer examination and the filtering of entries in log files and live traffic sampling. And, it can be used as an Intrusion Prevention System (IPS). To work as an IPS it is enough to set up snort in the inline mode and then passing traffic will not be only analyzed and logged, but also can be blocked.

IDS:                                                                                                                                                            
An intrusion detection system (IDS) is a device or software application that monitors a network or systems for malicious activity or policy violations.An important advantage of this IDS is the opportunity to work on different operating systems.Snort is a signature-based IDS, using rules to check for suspicious packets. A rule is a collection of requirements based on which an alert is generated.

Snort can be confihured into three main modes:                                                                                                
1. Sniffer: In sniffer mode, the program will read network packets and display them on the console.                               
2. Packet Logger: In packet logger mode, the program will log packets to the disk.                                                
3. Intrusion Detection: In intrusion detection mode, the program will monitor network traffic and analyze it against a rule set defined by the user. The program will then perform a specific action based on what has been identified.

Snort can perform:                                                                                                                        
1.Real-time traffic analysis                                                                                                        
2. Content Matching 
3. Content Searching
4. Detect attacks   
5. Protocol analysis

Barnyard2: Snort write its output into a file named as snort.u2 in a binary format, which is a unified file. Barnyard is an output system for Snort. Barnyard is used to read this file, then convert the data of the unified file in a human readable format and send it to a database.                                                                                                                
Barnyard2 is an open source interpreter for snort unified2 binary output files.
Barnyard2 has 3 modes of operation:                                                                                                                         
1. Batch : In batch (or one-shot) mode, barnyard2 will process the explicitly specified file(s) and exit.                           
2 . Continual: In continual mode, barnyard2 will start with a location to look and a specified file pattern and continue to process new data (and new spool files) as they appear.                                                                                                      
3. Continual w/ bookmark: Continual mode w/ bookmarking will also use a checkpoint file (or waldo file in the snort world) to track where it is. In the event the barnyard2 process ends while a waldo file is in use, barnyard2 will resume processing at the last entry as listed in the waldo file.                                                                                                                                        The "-f", "-w", and "-o" options are used to determine which mode barnyard2 will run in.

BASE: BASE is the Basic Analysis and Security Engine. BASE, the Basic Analysis and Security Engine was based off of the old ACID code codebase. The ACID (Analysis Console for Intrusion Database)base GUI interface which is dead now and has been for about five to six years.BASE, a fork of the ACID code(because ACID is not being actively maintained)picked up where the original author left off, added bunch of new features,and made easy to use,multi-language and highly functional GUI. BASE is written in PHP, and has several dependencies.                                                                                                                               

BASE is a graphical interface tool used for network interface monitoring which provides a front end web to analyze the alert generated by Snort IDS. BASE read the database and shows it in human readable format.

We need a database to store output of snort so we have to create a database, we named the database snort with a password of toor. We have used the mysql command-line tool to connect to the database to verify that we can connect to the database server and access the database.Now all that is left is to configure Barnyard to send data to the database.We have decided to that in addition to the alert information we also want to have full packet details insert into the database.                                             BASE is a graphical interface tool used for network interface monitoring which provides a front end web to analyze the alert generated by Snort IDS. BASE read the database and shows it in human readable format.

In this document we are using Snort as Intrusion Detection System. And the command we have used for installing snort and configuring it are as follows:                                                                                                                                   

Step 1. Initial setup and Dependencies check:                                                                                                           
apt-get install bison build-essential checkinstall flex iptables-dev libc6-dev libc-dev-bin libdnet libdnet-dev libdumbnet1 libdumbnet-dev libghc-zlib-dev libnet1 libnet1-dev libnetfilter-queue1 libnetfilter-queue-dev libnfnetlink-dev libpcap-dev libpcre3-dev linux-libc-dev make pkg-config tree                                                                                                           

Step 2. Download, configure and install DAQ:                                                                                                              
wget http://192.168.1.135/sw/security_tools/snort/daq-2.0.6.tar.gz                                                                          
./configure                                                                                                                                     
make                                                                                                                                                        
make install

Step 3. Download, configure and install Snort:                                                                                                                    
wget http://192.168.1.135/sw/security_tools/snort/snort-2.9.8.3.tar.gz                                                                        
./configure                                                                                                                                                                                                                 
make                                                                                                                                                  
make install

Step 4. Load libraries in memory:                                                                                                                                                                                                                                                                                                                                                                         
ldconfig

Step 5. Create a group and user named as snort:                                                                                                                                                     
groupadd snort                                                                                                                                                                                  
useradd snort -r -s /usr/sbin/nologin -c SNORTIDS -g snort                

Step 6. Create File and Directory:                                                                                                                                                                                                                                                                                                                                        
mkdir /etc/snort                                                                                                                                  
mkdir /etc/snort/rules                                                                                                                                                                                                
mkdir /etc/snort/preproc-rules                                                                                                                              
mkdir /var/log/snort                                                                                                                                    
mkdir /usr/local/lib/snort_dynamicrules

Step 7. Copying configuration file and map file to the folder that we have created:                                                                                                                                                         
cp /usr/src/snort_src/snort-2.9.8.3/etc/*.conf* /etc/snort/                                                                                                                                                                                                                   
cp /usr/src/snort_src/snort-2.9.8.3/etc/*.map /etc/snort/
Step 8. Creating three files in rules folder:                                                                                                                       
touch /etc/snort/rules/white_list.rules                                                                                                                                                                                                                                   
touch /etc/snort/rules/black_list.rules                                                                                                                                                                                                                                                                                               
touch /etc/snort/rules/local.rules

Step 9. Changing files and folders ownership:                                                                                                                                     
chown -R snort:snort /etc/snort                                                                                                                   
chown -R snort:snort /var/log/snort                                                                                                                                   
chown -R snort:snort /usr/local/lib/snort_dynamicrules                                                                                                        
chown -R snort:snort /usr/local/lib/snort                                                                                                                                                                                                               
chown -R snort:snort /usr/local/lib/snort_dynamicengine                                                                                                                                                                   
chown -R snort:snort /usr/local/lib/snort_dynamicpreprocessor                                                                                                                             
chown -R snort:snort /usr/local/lib/pkgconfig                                                                                                                                                       
chown -R snort:snort /usr/local/bin/daq-modules-config                                                                                        
chown -R snort:snort /usr/local/bin/u2boat                                                                                                                                                      
chown -R snort:snort /usr/local/bin/u2spewfoo

Step 10. Changing files and folders permission:                                                                                                                                                                   
chmod -R 5775 /etc/snort                                                                                                                          
chmod -R 5775 /var/log/snort                                                                                                                                                
chmod -R 5775 /usr/local/lib/snort_dynamicrules                                                                                                                                           
chmod -R 5775 /usr/local/lib/snort                                                                                                                  
chmod -R 5775 /usr/local/lib/snort_dynamicengine                                                                                                                    
chmod -R 5775 /usr/local/lib/snort_dynamicpreprocessor                                                                                        
chmod -R 5775 /usr/local/lib/pkgconfig                                                                                                          
chmod -R 5775 /usr/local/bin/daq-modules-config                                                                                                 
chmod -R 5775 /usr/local/bin/u2boat                                                                                                                                   
chmod -R 5775 /usr/local/bin/u2spewfoo

Step 11. Edit some lines in Snorts configuration file:                                                                                                                                                                                                                                                                                                                                                                
From:                                                                                                                                                 
var RULE_PATH /..                                                                                                                                             
var SO_RULE_PATH /../so_rules                                                                                                                             
var PREPROC_RULE_PATH /../preproc_rules                                                                                                                   
var WHITE_LIST_PATH ..\rules                                                                                                                              
var BLACK_LIST_PATH ..\rules                                                                                                                        
To:                                                                                                                                                          
var RULE_PATH /etc/snort                                                                                                                                             
var SO_RULE_PATH /etc/snort/so_rules                                                                                                                                      
var PREPROC_RULE_PATH /etc/snort/preproc_rules                                                                                                          
var WHITE_LIST_PATH /etc/snort/rules                                                                                                                        
var BLACK_LIST_PATH /etc/snort/rules                                                                                                                                        
In Step: #7. We have added three rules:                                                                                                                               
include $RULE_PATH/local.rules                                                                                                                
include $RULE_PATH/white_list.rules                                                                                                         
include $RULE_PATH/black_list.rules

To run Snort following command is used:                                                                                                                                                                             
snort -i eth0 -u snort -g snort -c /etc/snort/snort.conf -A console                                                                                                                     
-i is used for defining the network interface on which we want to scan traffic                                                                                                                
-u is used to define user (in our case the user is snort)                                                                                               
-g is used to define group user (in our case the group user is snort)                                                                                 
-c is used to tell where is the configuration file stored, which we are going to use                                                                    
-A is used to show snort output on console.

The follwoing commands are used for installing Barnyard2 and configuring it are as follows:     

Step 1. Use following command to install prerequisite:                                                                                                                                                                                                              
apt-get install mariadb-server mariadb-client libmariadbclient18 libmariadbclient-dev libmariadbd-dev libtool unzip dos2unix autoconf

Step 2. First create a file named as snort.u2 with limit 128 MB so do some changes in configuration file of snort, so we write command as:                                                                                                                                    
output unified2: filename snort.u2, limit 128

Step 3. Load libraries in memory :                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
ldconfig

Step 4. Configure and install barnyard2:                                                                                                  
./configure –with-mysql –with-mysql-libraries=/usr/lib/                                                                                                                                                         
make                                                                                                                                                                                                      
make install

Step 5. Creating a directory and changing its ownership:                                                                                                                                                              
mkdir /var/log/barnyard2                                                                                                                                  
chown snort:snort /var/log/barnyard2
Step 6. Creating a waldo file and changing its ownership to snort:                                                                                                                                                          
touch /var/log/snort/barnyard2.waldo                                                                                                                  
chown snort:snort /var/log/snort/barnyard2.waldo
To run Barnyard2 following command is used:                                                                                           
barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort/ -f snort.u2 -w /var/log/snort/barnyard2.waldo -u snort -g snort                                                                         
- c is used to define that where is barnyard configuration file                                                                                                                                                                                   
- d is used to tell directory                                                                                                                                             
- f is used to tell the file snort.u2                                                                                                                                                                         
- w is used to tell barnyard that where the barnyard2.waldo file is                                                                                                                                                                                                                                                   
- u is used for user                                                                                                                                      
- g is used for group user
We will create a user snort and have given all the permission to it so that it can fetch the data. Now to create database following commands are used:                                                                                                                                  
Step 1. Creating a database named as snort:                                                                                                                           
CREATE DATABASE IF NOT EXISTS snort;
Step 2. Use database snort and give a source:                                                                                                           
USE snort;                                                                                                                                        
source ~/dl/barnyard2-master/schemas/create-mysql
Step 3. Creating user:                                                                                                                                            
CREATING USER ‘snort’@’localhost’ IDENTIFIED BY ‘toor’;
Step 4. Giving permission to user:                                                                                                                  
Grant create, insert, select, delete, update on snort.* to ‘snort’@’localhost’;
Step 5. Giving barnyard2 database details so edit:                                                                                                    
Output database: log, mysql, user=snort, password=toor, dbname=snort host=localhost

Now run snort, barnyard and it will show the output with BASE.

Basics of writing Snort Rules:
action protocol srcIP srcPort DirectionOperator dstIP dstPort (msg:”Message”; sid:555555; rev:1;)                                                                             
This is the rule that we have written, it has two part one is Rule Header and the other is Rule Options. Rule Header, it contain rule action, protocol, IP address, Port number.                                                                                                                                                        
Action: Action is the action that is going to take place if the rule is applied, there are total of                                                           
8 types of action are there, which can take place:                                                                                            
1.Alert: It will generate an alert using the selected alert method and then log the packet.                                                                                                         
2.Log: It will log the packet.                                                                                                              
3.Pass: Ignore the packet.                                                                                                              
4.Activate: Alert and then turn on another dynamic rule.                                                                                  
5.Dynamic: Remain idle until activated by an activated rule, then act as a lo rule.                                                             
6.Drop: Make iptables drop the packet and log the packet.                                                                                     
7.Reject: Make iptables drop the packet log it, and then send a TCP reset if the protocol is TCP or an ICMP port unreachable message if the protocol is UDP.                                                                                                                
8.SDrop: Make iptable drop the packet but does not log it.                                                                                  
Protocol: Snort generally analyzes only three protocols,                                                                                                
TCP                                                                                                                                                                 
UDP                                                                                                                                                   
ICMP                                                                                                                                                
IP Address: Used for adding either a specific IP address (source or destination) or we can write “any” or we can also write IP range.                                                                                                                                                         
Port Address: Used for adding either a specific Port (source or destination) or we can write “any” or we can also write Port range.                                                                                                                                             
Rule Options, it contain alert message and information, it is divided into two parts, one is rule option which is separated by “;”, and other is rule option keyword which is separated by “:”.                                                                                 
Sample rule: If any ICMP packet received by our system then generate an alert                                                               
alert icmp any any -> any any (msg:”ICMP packet found”; sid:6666667; rev:1;)


DoS attack Signature:                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
As a denial of service is type of attack in which attacker sends a huge number of request in a limited time period, according to the number of request send by a unique IP address we have created a signature.
In rule:                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
Rule Header:-                                                                                                                                             
alert: it will generate an alert using the selected alert method and then log the packet.                                                                                                                                                                       
udp: as we are creating rule to protect a Domain Name Server we are using udp protocol, because an DNS request or response uses UDP protocol.                                                                                                                                     
any: as we are creating general rule so we are using any which means it will capture packet coming from any source IP address.  
any: as we are creating general rule so we are using any which means it will capture packet coming from any port number.                        
->: it indicates the direction                                                                                                                  
any: as we are creating general rule so we are using any which means it will capture packet going to any destination IP address.  
53: as we are creating rule to protect a DNS server and, DNS server uses port number 53 to listen request or give responses, so it will capture all the packet going to port number 53.                                                                                                                                                                                                                                                                                                                                                                                                                           
Rule Option:                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
msg: to see alerts according to the message that we have given in this field.                                                                                         
threshold: it works on its parameter which are given below                                                                                                                      
type:                                                                                                                                                           
1. limit: Type limit alerts on the first m events during the time interval, then ignores events for the rest of the time interval.                                                                                                                                        
2. threshold: Type threshold alerts on every m times we see this event during the time interval.                                                                                  
3. both: Type both alerts once per time interval after seeing m occurrences of the event, then ignores any additional events during the time interval.                                                                                                                      
track by:                                                                                                                                                   
Rate is tracked by either source IP address or destination IP address.Ports or anything else are not tracked.                                     
1. _src: This means count is maintained for each unique source IP addresses.                                                                                    
2. _dst: This means count is maintained for each unique destination IP addresses.                                                                                                       
count: number of rule matching in s seconds that will cause event_filter limit to be exceeded.                                              
Count must be non-zero value.
seconds:  time period over which count is accrued. seconds must be a non-zero value. In the rule threshold: type both, track by_src, count 255, seconds 3; it means that it will capture only if in 3 seconds there are at least 255 packet are coming from a unique source IP address.



alert udp any any -> any 53 ( msg: “It can be DoS attack;” threshold: type both, track by_src, count 255, seconds 3; sid: 1000001; rev:1;)



According to the rule for DoS attack, it will capture packet if the packet is having UDP protocol and coming from any Source IP and any port number and going to any destination IP address but on port number 53 (as DNS listen on port number 53 for request and response.) and generate alert if at least 255 packets are coming from a unique IP address in 3 seconds.


