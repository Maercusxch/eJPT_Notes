**What version of windows is running**

- `sysinfo`

**What current user we have access to**

- `getuid`

**What privileges this user has**

- `getprivs`

**Verify if this user is part of the local administrator group**

- `net user` display detailed information about user accounts on a local computer or domain
- `net localgroup administrators`

**open shell session**

- `shell`

**Meterpreter Session Migration to 64-bit Process**

The initial Meterpreter session ran in a 32-bit process (x86/windows) on a 64-bit system. To avoid stability issues and enable full functionality, the session was migrated to a native 64-bit process.
- `pgrep explorer`
- `migrate (Actuall PID)`

![image](https://github.com/user-attachments/assets/00d5e812-50e3-4d54-915a-eeb787cdadb2)

