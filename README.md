# eJPT
![eJPT Logo](/ejpt_logo.png)

## Notes

To use these commands, make sure to:
- Replace ‘10.10.10.10’ with the relevant IP address
- Replace ‘port’ with the relevant port number
- Replace /path/to/x with the relevant path to the relevant file

## Networking
| slash notation | net mask        | hex        | binary representation               | number of hosts |
|----------------|-----------------|------------|-------------------------------------|-----------------|
| /0             | 0.0.0.0         | 0x00000000 | 00000000 00000000 00000000 00000000 | 4294967296      |
| /1             | 128.0.0.0       | 0x80000000 | 10000000 00000000 00000000 00000000 | 2147483648      |
| /2             | 192.0.0.0       | 0xc0000000 | 11000000 00000000 00000000 00000000 | 1073741824      |
| /3             | 224.0.0.0       | 0xe0000000 | 11100000 00000000 00000000 00000000 | 536870912       |
| /4             | 240.0.0.0       | 0xf0000000 | 11110000 00000000 00000000 00000000 | 268435456       |
| /5             | 248.0.0.0       | 0xf8000000 | 11111000 00000000 00000000 00000000 | 134217728       |
| /6             | 252.0.0.0       | 0xfc000000 | 11111100 00000000 00000000 00000000 | 67108864        |
| /7             | 254.0.0.0       | 0xfe000000 | 11111110 00000000 00000000 00000000 | 33554432        |
| /8             | 255.0.0.0       | 0xff000000 | 11111111 00000000 00000000 00000000 | 16777216        |
| /9             | 255.128.0.0     | 0xff800000 | 11111111 10000000 00000000 00000000 | 8388608         |
| /10            | 255.192.0.0     | 0xffc00000 | 11111111 11000000 00000000 00000000 | 4194304         |
| /11            | 255.224.0.0     | 0xffe00000 | 11111111 11100000 00000000 00000000 | 2097152         |
| /12            | 255.240.0.0     | 0xfff00000 | 11111111 11110000 00000000 00000000 | 1048576         |
| /13            | 255.248.0.0     | 0xfff80000 | 11111111 11111000 00000000 00000000 | 524288          |
| /14            | 255.252.0.0     | 0xfffc0000 | 11111111 11111100 00000000 00000000 | 262144          |
| /15            | 255.254.0.0     | 0xfffe0000 | 11111111 11111110 00000000 00000000 | 131072          |
| /16            | 255.255.0.0     | 0xffff0000 | 11111111 11111111 00000000 00000000 | 65536           |
| /17            | 255.255.128.0   | 0xffff8000 | 11111111 11111111 10000000 00000000 | 32768           |
| /18            | 255.255.192.0   | 0xffffc000 | 11111111 11111111 11000000 00000000 | 16384           |
| /19            | 255.255.224.0   | 0xffffe000 | 11111111 11111111 11100000 00000000 | 8192            |
| /20            | 255.255.240.0   | 0xfffff000 | 11111111 11111111 11110000 00000000 | 4096            |
| /21            | 255.255.248.0   | 0xfffff800 | 11111111 11111111 11111000 00000000 | 2048            |
| /22            | 255.255.252.0   | 0xfffffc00 | 11111111 11111111 11111100 00000000 | 1024            |
| /23            | 255.255.254.0   | 0xfffffe00 | 11111111 11111111 11111110 00000000 | 512             |
| /24            | 255.255.255.0   | 0xffffff00 | 11111111 11111111 11111111 00000000 | 256             |
| /25            | 255.255.255.128 | 0xffffff80 | 11111111 11111111 11111111 10000000 | 128             |
| /26            | 255.255.255.192 | 0xffffffc0 | 11111111 11111111 11111111 11000000 | 64              |
| /27            | 255.255.255.224 | 0xffffffe0 | 11111111 11111111 11111111 11100000 | 32              |
| /28            | 255.255.255.240 | 0xfffffff0 | 11111111 11111111 11111111 11110000 | 16              |
| /29            | 255.255.255.248 | 0xfffffff8 | 11111111 11111111 11111111 11111000 | 8               |
| /30            | 255.255.255.252 | 0xfffffffc | 11111111 11111111 11111111 11111100 | 4               |
| /31            | 255.255.255.254 | 0xfffffffe | 11111111 11111111 11111111 11111110 | 2               |
| /32            | 255.255.255.255 | 0xffffffff | 11111111 11111111 11111111 11111111 | 1               |

## Common ports
| Port | Protocol | Hint                   |
|------|----------|------------------------|
| 22   | SSH      |                        |
| 25   | SMTP     |                        |
| 110  | POP3     |                        |
| 115  | SFTP     |                        |
| 143  | IMAP     |                        |
| 80   | HTTP     |                        |
| 443  | HTTPS    |                        |
| 23   | TELNET   |                        |
| 21   | FTP      |                        |
| 3389 | RDP      |                        |
| 3306 | MYSQL    |                        |
| 1433 | MS SQL   |                        |
| 137  | NETBIOS  | find work groups       |
| 138  | NETBIOS  | list shares & machines |
| 139  | NETBIOS  | transit data           |
| 53   | DNS      |                        |

## Routing/Pivoting
One thing I am almost sure you will have to do is set up IP routing and routing tables. There are plenty of resources available online for this, but the course content itself seemed to be pretty lacking here.

    ip route - prints the routing table for the host you are on
    ip route add ROUTETO via ROUTEFROM - add a route to a new network if on a switched network and you need to pivot
    

## Enumeration
Anyone experienced in penetration testing will tell you that enumeration is 90% of the battle, and I don’t disagree. Although the eJPT doesn’t require a very in depth enumeration cycle, it does cover a broad number of techniques.

### Enumeration (Whois)
    whois
    whois site.com
### Enumeration (Ping Sweep)
    fping -a -g 10.10.10.0/24 2>/dev/null
    nmap -sn 10.10.10.0/24
### Nmap Scans
#### OS Detection
    nmap -Pn -O 10.10.10.10
#### Nmap Scan (Quick)
    nmap -sC -sV 10.10.10.10
#### Nmap Scan (Full)
    nmap -sC -sV -p- 10.10.10.10
#### Nmap Scan (UDP Quick)
    nmap -sU -sV 10.10.10.10
#### Nmap output file (-oN)
    nmap -sn 10.10.10.0/24 -oN hosts.nmap
#### To filter out just IPs from the nmap scan results
    cat hosts.nmap | grep for | cut -d " " -f 5  
#### Other nmap scan useful during exam
    nmap -sV -Pn -T4 -A -p- -iL hosts.nmap -oN ports.nmap
    nmap --script vuln --script-args=unsafe=1 -iL hosts.nmap

## Web Applications
The following commands could be useful when enumerating and attacking web applications. Again, make sure you understand what each one does rather than blindly throwing them at the machine in question.

### Banner Grabbing
    nc -v 10.10.10.10 port
    HEAD / HTTP/1.0
### OpenSSL for HTTPS services
    openssl s_client -connect 10.10.10.10:443
    HEAD / HTTP/1.0
### Httprint
    httprint -P0 -h 10.10.10.10 -s /path/to/signaturefile.txt
### HTTP Verbs
    GET, POST, HEAD, PUT, DELETE, OPTIONS
Use the OPTIONS verb to see what other verbs are available

    nc 10.10.10.10 80
    OPTIONS / HTPP/1.0

You can use HTTP verbs to upload a php shell. Find the content length, then use PUT to upload the shell. Make sure you include the size of the payload when using the PUT command.

    wc -m shell.php
    x shell.php

    PUT /shell.php
    Content-type: text/html
    Content-length: x
    Directory and File Scanning

My preferred tool at the moment is dirsearch, I find it to to be fast and easy to use. For a more in depth scan, use gobuster and include a large wordlist.

    dirsearch.py -u http://10.10.10.10 -e *
    gobuster -u 10.10.10.10 -w /path/to/wordlist.txt

Advanced Google Searches
Not really necessary, but useful to know all the same.

    site:
    intitle:
    inurl:
    filetype:
    AND, OR, &, |, -

### Cross Site Scripting (XSS)
The general steps I use to find and test XSS are as follows:

1. Find a reflection point
2. Test with <i> tag
3. Test with HTML/JavaScript code (alert('XSS'))

- Reflected XSS = Payload is carried inside the request the victim sends to the website. Typically the link contains the malicious payload
- Persistent XSS = Payload remains in the site that multiple users can fall victim to. Typically embedded via a form or forum post

### SQLMap
    sqlmap -u http://10.10.10.10 -p parameter
    sqlmap -u http://10.10.10.10  --data POSTstring -p parameter
    sqlmap -u http://10.10.10.10 --os-shell
    sqlmap -u http://10.10.10.10 --dump

## System Attacks
The other type of ‘attack’ you will be doing are system attacks. Make sure you understand why/how to brute force types of services and hashes, as well as basic metasploit usage.

### Password Attacks
#### Unshadow
This prepares a file for use with John the Ripper
    
    unshadow passwd shadow > unshadow

#### Hash Cracking
    john -wordlist /path/to/wordlist -users=users.txt hashfile

### Network Attacks
Brute Forcing with Hydra
replace ‘ssh’ with any relevant service

    hydra -L users.txt -P pass.txt -t 10 10.10.10.10 ssh -s 22
    hydra -L users.txt -P pass.txt telnet://10.10.10.10

### Windows Shares Using Null sessions
    nmblookup -A 10.10.10.10
    smbclient -L //10.10.10.10 -N (list shares)
    smbclient //10.10.10.10/share -N (mount share)
    enum4linux -a 10.10.10.10

#### ARP spoofing
    echo 1 > /proc/sys/net/ipv4/ip_forward
    arpspoof -i tap0 -t 10.10.10.10 -r 10.10.10.11

### Metasploit
Metasploit is a very useful tool for penetration testers, and I’d recommend going through a Metasploitable for an effective, hands on way to learn about Metasploit. There are plenty of guides and walkthroughs available to learn from. Doing even part of a Metasploitable box will more than prepare you for the Metasploit usage required here.

#### Basic Metasploit Commands
    search x
    use x
    info
    show options, show advanced options
    SET X (e.g. set RHOST 10.10.10.10, set payload x)

#### Meterpreter
The below are some handy commands for use with a Meterpreter session. Again, I’d recommend going through a Metasploitable or doing some extra study here.
    
    background
    sessions -l
    sessions -i 1
    sysinfo, ifconfig, route, getuid
    getsystem (privesc)
    bypassuac
    download x /root/
    upload x C:\\Windows
    shell
    use post/windows/gather/hashdump
    
## Possible Exam Questions:

Below are some examples of the exam questions that you might have during the test:

- What’s the password for specific user?
- What’s in the file “test.txt”?
- How many routers there are in the internal network?
- Which IP address belongs to Windows machine?
- There is one machine contains the following file C:\\Windows\secret.txt. What is its content?
- What are the hard drives in the Windows machine?
- What is the IBAN number for the XXXX user?
- What is your IP address?
