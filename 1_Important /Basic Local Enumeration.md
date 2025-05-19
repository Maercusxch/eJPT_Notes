**What version of Windows is running**

- `sysinfo`
- 
**What current User we have access to**

**What Privileges this User has**

**Meterpreter Session Migration to 64-bit Process**

The initial Meterpreter session ran in a 32-bit process (x86/windows) on a 64-bit system. To avoid stability issues and enable full functionality, the session was migrated to a native 64-bit process.
- `pgrep explorer`
- `migrate (Actuall PID)`
![image](https://github.com/user-attachments/assets/9e5e77bd-1ba1-41c8-873f-a16c2b20386e)
