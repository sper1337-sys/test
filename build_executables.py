"""
Build Executables Script
Creates standalone executables from Python source files
"""

import os
import sys
import subprocess
import shutil
import json
from pathlib import Path

class ExecutableBuilder:
    """Build standalone executables using PyInstaller"""
    
    def __init__(self):
        self.build_dir = "build"
        self.dist_dir = "dist"
        self.spec_dir = "specs"
        self.icon_file = None
        self.build_config = {}
    
    def load_build_config(self, config_file="build_config.json"):
        """Load build configuration from JSON file"""
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.build_config = json.load(f)
                return True
        except Exception as e:
            print(f"Failed to load build config: {e}")
        
        # Default configuration
        self.build_config = {
            "client": {
                "script": "bb_secret.py",
                "name": "PollyTunnelsClient",
                "icon": None,
                "console": False,
                "onefile": True
            },
            "host": {
                "script": "aa_secret.py", 
                "name": "PollyTunnelsHost",
                "icon": None,
                "console": False,
                "onefile": True
            }
        }
        return False
    
    def build_client(self):
        """Build client executable"""
        return self._build_application("client")
    
    def build_host(self):
        """Build host executable"""
        return self._build_application("host")
    
    def _build_application(self, app_type):
        """Build application executable"""
        try:
            if app_type not in self.build_config:
                print(f"No configuration found for {app_type}")
                return False
            
            config = self.build_config[app_type]
            script_path = config["script"]
            app_name = config["name"]
            
            if not os.path.exists(script_path):
                print(f"Script not found: {script_path}")
                return False
            
            # Prepare PyInstaller command
            cmd = [
                "pyinstaller",
                "--name", app_name,
                "--distpath", self.dist_dir,
                "--workpath", self.build_dir,
                "--specpath", self.spec_dir
            ]
            
            # Add options based on configuration
            if config.get("onefile", True):
                cmd.append("--onefile")
            
            if not config.get("console", False):
                cmd.append("--windowed")
            
            if config.get("icon"):
                cmd.extend(["--icon", config["icon"]])
            
            # Add hidden imports for common dependencies
            hidden_imports = [
                "cryptography",
                "requests",
                "tkinter",
                "json",
                "base64",
                "secrets",
                "hashlib",
                "hmac",
                "time",
                "threading",
                "os",
                "sys"
            ]
            
            for import_name in hidden_imports:
                cmd.extend(["--hidden-import", import_name])
            
            # Add the script
            cmd.append(script_path)
            
            print(f"Building {app_name}...")
            print(f"Command: {' '.join(cmd)}")
            
            # Run PyInstaller
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"Successfully built {app_name}")
                return True
            else:
                print(f"Build failed for {app_name}")
                print(f"Error: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"Build error: {e}")
            return False
    
    def build_all(self):
        """Build all applications"""
        results = {}
        
        print("Starting build process...")
        
        # Create directories
        os.makedirs(self.build_dir, exist_ok=True)
        os.makedirs(self.dist_dir, exist_ok=True)
        os.makedirs(self.spec_dir, exist_ok=True)
        
        # Build client
        print("\n" + "="*50)
        print("Building Client Application")
        print("="*50)
        results["client"] = self.build_client()
        
        # Build host
        print("\n" + "="*50)
        print("Building Host Application")
        print("="*50)
        results["host"] = self.build_host()
        
        # Summary
        print("\n" + "="*50)
        print("Build Summary")
        print("="*50)
        
        for app, success in results.items():
            status = "SUCCESS" if success else "FAILED"
            print(f"{app.capitalize()}: {status}")
        
        return all(results.values())
    
    def clean_build_files(self):
        """Clean build artifacts"""
        try:
            dirs_to_clean = [self.build_dir, self.dist_dir, self.spec_dir]
            
            for dir_path in dirs_to_clean:
                if os.path.exists(dir_path):
                    shutil.rmtree(dir_path)
                    print(f"Cleaned: {dir_path}")
            
            # Clean .spec files in current directory
            for spec_file in Path(".").glob("*.spec"):
                spec_file.unlink()
                print(f"Cleaned: {spec_file}")
            
            return True
            
        except Exception as e:
            print(f"Clean failed: {e}")
            return False
    
    def create_installer_script(self):
        """Create installer script for the executables"""
        installer_script = '''@echo off
echo Polly Tunnels Installation
echo ========================

echo.
echo Installing Polly Tunnels Client and Host applications...
echo.

REM Create installation directory
set INSTALL_DIR=%PROGRAMFILES%\\Polly Tunnels
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Copy executables
copy "PollyTunnelsClient.exe" "%INSTALL_DIR%\\" >nul
copy "PollyTunnelsHost.exe" "%INSTALL_DIR%\\" >nul

REM Create desktop shortcuts
echo Creating desktop shortcuts...
powershell "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\\Desktop\\Polly Tunnels Client.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\\PollyTunnelsClient.exe'; $Shortcut.Save()"
powershell "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\\Desktop\\Polly Tunnels Host.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\\PollyTunnelsHost.exe'; $Shortcut.Save()"

REM Create start menu entries
set START_MENU=%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Polly Tunnels
if not exist "%START_MENU%" mkdir "%START_MENU%"
powershell "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%START_MENU%\\Polly Tunnels Client.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\\PollyTunnelsClient.exe'; $Shortcut.Save()"
powershell "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%START_MENU%\\Polly Tunnels Host.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\\PollyTunnelsHost.exe'; $Shortcut.Save()"

echo.
echo Installation completed successfully!
echo.
echo Applications installed to: %INSTALL_DIR%
echo Desktop shortcuts created
echo Start menu entries created
echo.
pause
'''
        
        try:
            installer_path = os.path.join(self.dist_dir, "install.bat")
            with open(installer_path, 'w') as f:
                f.write(installer_script)
            
            print(f"Created installer script: {installer_path}")
            return True
            
        except Exception as e:
            print(f"Failed to create installer script: {e}")
            return False
    
    def package_release(self, version="1.0.0"):
        """Package the release files"""
        try:
            release_dir = f"polly_tunnels_v{version}"
            release_path = os.path.join(self.dist_dir, release_dir)
            
            # Create release directory
            os.makedirs(release_path, exist_ok=True)
            
            # Copy executables
            client_exe = os.path.join(self.dist_dir, "PollyTunnelsClient.exe")
            host_exe = os.path.join(self.dist_dir, "PollyTunnelsHost.exe")
            
            if os.path.exists(client_exe):
                shutil.copy2(client_exe, release_path)
            
            if os.path.exists(host_exe):
                shutil.copy2(host_exe, release_path)
            
            # Copy installer
            installer_path = os.path.join(self.dist_dir, "install.bat")
            if os.path.exists(installer_path):
                shutil.copy2(installer_path, release_path)
            
            # Create README
            readme_content = f"""Polly Tunnels v{version}
===================

Secure Communication System

Files:
- PollyTunnelsClient.exe: Client application
- PollyTunnelsHost.exe: Host application  
- install.bat: Automatic installer

Installation:
1. Run install.bat as Administrator
2. Follow the installation prompts
3. Launch applications from Desktop or Start Menu

Manual Installation:
1. Copy the .exe files to your desired location
2. Run the applications directly

System Requirements:
- Windows 10 or later
- Internet connection for Tor functionality

For support and documentation, visit:
https://github.com/your-repo/polly-tunnels
"""
            
            readme_path = os.path.join(release_path, "README.txt")
            with open(readme_path, 'w') as f:
                f.write(readme_content)
            
            print(f"Release package created: {release_path}")
            return True
            
        except Exception as e:
            print(f"Failed to package release: {e}")
            return False

def main():
    """Main build script"""
    builder = ExecutableBuilder()
    
    # Load configuration
    builder.load_build_config()
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "clean":
            builder.clean_build_files()
        elif command == "client":
            builder.build_client()
        elif command == "host":
            builder.build_host()
        elif command == "installer":
            builder.create_installer_script()
        elif command == "package":
            version = sys.argv[2] if len(sys.argv) > 2 else "1.0.0"
            builder.package_release(version)
        else:
            print("Unknown command. Available commands:")
            print("  clean    - Clean build artifacts")
            print("  client   - Build client only")
            print("  host     - Build host only")
            print("  installer - Create installer script")
            print("  package  - Package release files")
            print("  (no args) - Build all applications")
    else:
        # Build all applications
        success = builder.build_all()
        
        if success:
            builder.create_installer_script()
            builder.package_release()
            print("\nBuild process completed successfully!")
        else:
            print("\nBuild process failed!")
            sys.exit(1)

if __name__ == "__main__":
    main()