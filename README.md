# SecureTOTP-CLI
This is a command-line tool for managing Time-based One-Time Passwords(TOTP). 
One day, I noticed that the number of configurations in my authenticator app was steadily increasing. 
Faced with the challenge of managing and backing up these TOTP configurations, I decided to create a solution to store them on my computer. 
With the assistance of ChatGPT, I quickly developed this tool.
The data file is encrypted and stored locally, making it convenient for backup to cloud storage services like OneDrive, Google Drive, etc.

# Feature
- Works with both 6 and 8-digit passwords, tested with GitHub, Hotmail, Google, and Amazon Web Services.
- Easily imports and exports data in JSON or CSV format.
- Supports the generation of TOTP configuration URLs (See [Key-Uri-Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)).
- Ensures security with AES-256 encryption.
- Argon2 Hashing, Passwords are securely hashed using the Argon2 algorithm that offers high resistance to both brute-force and side-channel attacks.
- This program does not require any network connection.

# Screenshots
## Bash on CentOS 
![MainWindow](https://github.com/jaco00/totp/blob/main/images/screenshots/screenshot.gif)

# Important Note for Windows Users
**Windows Defender False Positive Alert:**
Due to the use of AES encryption within SecureTOTP-CLI, some Windows users may experience false positive alerts from Windows Defender or other antivirus software. 
This is a common occurrence with programs utilizing encryption algorithms.
As a precautionary measure, I currently do not provide direct builds for the Windows version. If you need a Windows executable, 
feel free to attempt building the software from the source code yourself.

# How to Build
To ensure successful building of the SecureTOTP-CLI, ensure that the Go programming language is installed on your system.
```bash 
git clone https://github.com/jaco00/SecureTOTP-CLI  
cd SecureTOTP-CLI
go build
```

# Function

## Command Line Parameters
- **Passwordless Launch**: Start the program without entering a password using `-p YourPassword`.
- **Specify Storage File**: Specify the storage file using `-f FileName` (default: ~/.securetotp-cli/mytotp.vault).

## Commands
- **New**: Add a new configuration.
- **Delete**: Remove a configuration.
- **Fetch**: Retrieve detailed information for a configuration, including the key and code.
- **Update**: Modify information for a configuration.
- **List**: Display all current configurations.
- **FetchAll**: Check all configurations and output codes.
- **Export**: Export all configurations to a file.
- **Import**: Import configurations from a file. Note: If there are configurations with matching Labels and Issues in both the current setup and the imported file, 
    the imported data will overwrite the current ones.

# Security Considerations
- **Quit the App at Any Time:**
  Terminate the application promptly to prevent data leakage in memory.

- **Use Strong Passwords:**
  Encourage users to utilize passwords with a length of 8 characters or more, including a mix of uppercase, lowercase, numbers, and special symbols, to enhance security.

- **Consider KeyFile for Short Passwords:**
  If shorter passwords are necessary, consider using a KeyFile to bolster security.
