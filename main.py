import sys
import os
import platform
import subprocess
import re
import time
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QTextEdit, QProgressBar, QMessageBox, QLineEdit, QInputDialog,
    QTabWidget, QScrollArea, QGroupBox, QFormLayout, QDialog, QToolTip
)
from PyQt5.QtCore import Qt, QTimer, QSize, QProcess, QUrl, QThread, pyqtSignal
from PyQt5.QtGui import QPixmap, QMovie, QFont, QColor, QPalette
from PyQt5.QtMultimedia import QSoundEffect
from PyQt5.QtWidgets import QFileDialog, QDesktopWidget
import threading
import psutil

class ScanWorker(QThread):
    update_signal = pyqtSignal(str, str)
    result_signal = pyqtSignal(dict)

    def __init__(self, command, is_admin=False, sudo_password=None):
        super().__init__()
        self.command = command
        self.is_admin = is_admin
        self.sudo_password = sudo_password
        self.os_type = platform.system()

    def run(self):
        result = {'output': '', 'errors': '', 'malware_found': 0}
        
        try:
            if self.os_type == "Windows":
                process = subprocess.Popen(
                    ["cmd.exe", "/c", self.command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    text=True
                )
            else:
                if self.is_admin:
                    full_command = f"echo '{self.sudo_password}' | sudo -S {self.command}"
                    process = subprocess.Popen(
                        ["sh", "-c", full_command],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        text=True
                    )
                else:
                    process = subprocess.Popen(
                        ["sh", "-c", self.command],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        text=True
                    )

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.update_signal.emit(output.strip(), "#ffffff")
                    result['output'] += output
                    # Simple malware detection in output
                    malware_keywords = ['virus', 'malware', 'trojan', 'worm', 'rootkit', 'adware', 'spyware']
                    if any(keyword in output.lower() for keyword in malware_keywords):
                        result['malware_found'] += 1

            errors = process.stderr.read()
            if errors:
                self.update_signal.emit(errors.strip(), "#ff0000")
                result['errors'] = errors

        except Exception as e:
            self.update_signal.emit(f"Error executing command: {str(e)}", "#ff0000")
            result['errors'] = str(e)

        self.result_signal.emit(result)

class USBHealer(QWidget):
    def __init__(self):
        super().__init__()
        self.current_os = platform.system()
        self.healing_commands = self.get_os_commands()
        self.current_command_index = 0
        self.process = QProcess()
        self.sudo_password = None
        self.scan_results = {
            'malware': {'found': 0, 'removed': 0, 'details': ''},
            'hardware': {'issues': 0, 'details': ''},
            'performance': {'benchmarks': {}, 'details': ''},
            'system': {'issues': 0, 'details': ''}
        }
        self.initUI()
        self.initSounds()
        self.initVideoBackground()

    def initUI(self):
        """Initialize the main application UI"""
        # Window setup
        self.setWindowTitle("Cyber - Medic Pro v1.0")
        self.setFixedSize(1000, 800)
        
        # Set dark theme
        self.set_dark_theme()
        
        # Main layout
        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.setLayout(self.main_layout)
        
        # Header with logo and loading animation
        self.init_header()
        
        # Terminal output area
        self.init_terminal()
        
        # Progress section
        self.init_progress_section()
        
        # Button controls
        self.init_buttons()
        
        # Status bar
        self.init_status_bar()

    def set_dark_theme(self):
        """Apply a dark theme to the application"""
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(20, 20, 20))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(10, 10, 10))
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(50, 50, 50))
        palette.setColor(QPalette.ButtonText, Qt.white)
        self.setPalette(palette)

    def init_header(self):
        """Initialize the header section with logo and title"""
        header_layout = QHBoxLayout()
        
        # Logo with loading animation
        self.logo_container = QWidget()
        logo_layout = QVBoxLayout()
        
        # Logo
        self.logo = QLabel()
        pixmap = QPixmap("assets/logo.png").scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.logo.setPixmap(pixmap)
        self.logo.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(self.logo)
        
        # Loading animation
        self.loading_label = QLabel()
        self.loading_movie = QMovie("assets/loading.gif")
        self.loading_movie.setScaledSize(QSize(50, 50))
        self.loading_label.setMovie(self.loading_movie)
        self.loading_label.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(self.loading_label)
        
        self.logo_container.setLayout(logo_layout)
        header_layout.addWidget(self.logo_container)
        
        # Title and OS info
        title_layout = QVBoxLayout()
        title = QLabel("CYBER - MEDIC PRO v1.0")
        title.setFont(QFont("Courier New", 24, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #00ff00;")
        
        self.os_label = QLabel(f"Detected OS: {self.current_os}")
        self.os_label.setFont(QFont("Courier New", 12))
        self.os_label.setAlignment(Qt.AlignCenter)
        self.os_label.setStyleSheet("color: #00a8ff;")
        
        title_layout.addWidget(title)
        title_layout.addWidget(self.os_label)
        header_layout.addLayout(title_layout)
        
        self.main_layout.addLayout(header_layout)

    def init_terminal(self):
        """Initialize the terminal output area"""
        self.terminal = QTextEdit()
        self.terminal.setReadOnly(True)
        self.terminal.setFont(QFont("Courier New", 10))
        self.terminal.setStyleSheet("""
            QTextEdit {
                background-color: #000;
                color: #00ff00;
                border: 2px solid #00ff00;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        self.main_layout.addWidget(self.terminal)

    def init_progress_section(self):
        """Initialize progress bar and current task label"""
        progress_layout = QVBoxLayout()
        
        self.current_task = QLabel("Ready to begin system healing")
        self.current_task.setFont(QFont("Courier New", 10))
        self.current_task.setStyleSheet("color: #00a8ff;")
        progress_layout.addWidget(self.current_task)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #00ff00;
                border-radius: 5px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #00ff00;
                width: 10px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        self.main_layout.addLayout(progress_layout)

    def init_buttons(self):
        """Initialize control buttons"""
        button_layout = QHBoxLayout()
        
        # Start Healing Button
        self.heal_button = QPushButton("START FULL HEAL")
        self.heal_button.setFont(QFont("Courier New", 12, QFont.Bold))
        self.heal_button.setStyleSheet("""
            QPushButton {
                background-color: #006400;
                color: #00ff00;
                border: 2px solid #00ff00;
                border-radius: 5px;
                padding: 10px 20px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #00aa00;
                border: 2px solid #00ff88;
            }
            QPushButton:pressed {
                background-color: #004400;
            }
            QPushButton:disabled {
                background-color: #333;
                color: #666;
                border: 2px solid #666;
            }
        """)
        self.heal_button.clicked.connect(self.start_healing)
        button_layout.addWidget(self.heal_button)
        
        # Get Sudo Password Button (Linux only)
        if self.current_os == "Linux":
            self.sudo_button = QPushButton("SET SUDO PASSWORD")
            self.sudo_button.setFont(QFont("Courier New", 10))
            self.sudo_button.setStyleSheet("""
                QPushButton {
                    background-color: #1a3d6d;
                    color: white;
                    border: 1px solid #2a5d9f;
                    border-radius: 5px;
                    padding: 8px 15px;
                }
                QPushButton:hover {
                    background-color: #2a5d9f;
                }
            """)
            self.sudo_button.clicked.connect(self.get_sudo_password)
            button_layout.addWidget(self.sudo_button)
        
        # Quick Scan Button
        self.quick_scan_button = QPushButton("QUICK SCAN")
        self.quick_scan_button.setFont(QFont("Courier New", 10))
        self.quick_scan_button.setStyleSheet("""
            QPushButton {
                background-color: #1a6d3d;
                color: white;
                border: 1px solid #2a9f5d;
                border-radius: 5px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #2a9f5d;
            }
        """)
        self.quick_scan_button.clicked.connect(self.quick_scan)
        button_layout.addWidget(self.quick_scan_button)
        
        
        
        # Custom Scan Button
        self.custom_scan_button = QPushButton("CUSTOM SCAN")
        self.custom_scan_button.setFont(QFont("Courier New", 10))
        self.custom_scan_button.setStyleSheet("""
            QPushButton {
                background-color: #1a6d3d;
                color: white;
                border: 1px solid #2a9f5d;
                border-radius: 5px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #2a9f5d;
            }
        """)
        self.custom_scan_button.clicked.connect(self.custom_scan)
        button_layout.addWidget(self.custom_scan_button)
        
        self.main_layout.addLayout(button_layout)

    def init_status_bar(self):
        """Initialize status bar at the bottom"""
        self.status_bar = QLabel("System ready for diagnostics")
        self.status_bar.setFont(QFont("Courier New", 10))
        self.status_bar.setStyleSheet("color: #00ff00;")
        self.main_layout.addWidget(self.status_bar)

    def initSounds(self):
        """Initialize sound effects"""
        self.start_sound = QSoundEffect()
        self.start_sound.setSource(QUrl.fromLocalFile("assets/start.wav"))
        
        self.typing_sound = QSoundEffect()
        self.typing_sound.setSource(QUrl.fromLocalFile("assets/start.wav"))
        self.typing_sound.setLoopCount(QSoundEffect.Infinite)
        
        self.success_sound = QSoundEffect()
        self.success_sound.setSource(QUrl.fromLocalFile("assets/success.wav"))

    def initVideoBackground(self):
        self.bg_label = QLabel(self)
        self.bg_label.setScaledContents(True)
        self.bg_movie = QMovie("assets/bg.gif")
        self.bg_label.setMovie(self.bg_movie)
        self.bg_movie.start()
        self.bg_label.lower()
        self.bg_label.setAttribute(Qt.WA_TransparentForMouseEvents)
        
        # Add video widget behind everything
        self.bg_label.setGeometry(0, 0, self.width(), self.height())
        self.bg_label.lower()
        self.bg_label.setAttribute(Qt.WA_TransparentForMouseEvents)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'bg_label'):
            self.bg_label.resize(self.size())

    def get_os_commands(self):
        """Return full list including auto-installers & fallback tools"""
        if self.current_os == "Linux":
            return [
                # --- Auto-install helpers ---------------------------------------------
                {"name": "Install sysbench (if missing)",  "cmd": "which sysbench >/dev/null || (sudo apt-get update -y && sudo apt-get install -y sysbench) || echo 'sysbench install skipped'", "admin": True, "category": "system"},
                {"name": "Install rkhunter (if missing)",  "cmd": "which rkhunter >/dev/null 2>&1 || sudo apt-get update -y && sudo apt-get install -y rkhunter", "admin": True, "category": "system"},
                {"name": "Install chkrootkit (if missing)", "cmd": "which chkrootkit >/dev/null 2>&1 || sudo apt-get update -y && sudo apt-get install -y chkrootkit", "admin": True, "category": "system"},
                
                # --- Recovery from broken dpkg / apt ---------------------------------
                {"name": "Fix dpkg lock", "cmd": "sudo dpkg --configure -a || true", "admin": True, "category": "system"},
                {"name": "Fix broken APT", "cmd": "sudo apt --fix-broken install -y", "admin": True, "category": "system"},
                {"name": "Update Package List", "cmd": "sudo apt update", "admin": True, "category": "system"},
                {"name": "Full Upgrade", "cmd": "sudo apt full-upgrade -y", "admin": True, "category": "system"},
                {"name": "Autoremove & Autoclean", "cmd": "sudo apt autoremove -y && sudo apt autoclean", "admin": True, "category": "system"},
                
                # --- Hardware ---------------------------------------------------------
                {"name": "Check CPU Temperature", "cmd": "sensors", "admin": False, "category": "hardware"},
                {"name": "Check Disk Health", "cmd": "sudo smartctl -a /dev/sda", "admin": True, "category": "hardware"},
                {"name": "Check Disk Space", "cmd": "df -h", "admin": False, "category": "hardware"},
                {"name": "Check Memory", "cmd": "free -h", "admin": False, "category": "hardware"},
                
                # --- Performance ------------------------------------------------------
                {"name": "Install sysbench (if missing)",  "cmd": "which sysbench >/dev/null || (sudo apt-get update -y && sudo apt-get install -y sysbench) || echo 'sysbench install skipped'", "admin": True, "category": "system"},
                {"name": "Performance Benchmark (CPU)", "cmd": "sysbench cpu --cpu-max-prime=20000 run", "admin": False, "category": "performance"},
                {"name": "Performance Benchmark (Disk)", "cmd": "sysbench fileio --file-total-size=1G prepare && sysbench fileio --file-total-size=1G --file-test-mode=rndrw --time=30 --max-requests=0 run && sysbench fileio --file-total-size=1G cleanup", "admin": False, "category": "performance"},
                
                # --- Malware ----------------------------------------------------------
                {"name": "Rkhunter Scan (Malware)", "cmd": "sudo rkhunter --check --sk", "admin": True, "category": "malware"},
                {"name": "ClamAV Scan (Malware)", "cmd": "sudo clamscan -r /", "admin": True, "category": "malware"},
                {"name": "Check Rootkits", "cmd": "sudo chkrootkit", "admin": True, "category": "malware"},
                
                # --- System -----------------------------------------------------------
                {"name": "System Information", "cmd": "lscpu && free -h && df -h", "admin": False, "category": "system"},
                {"name": "Check Open Ports", "cmd": "netstat -tuln", "admin": False, "category": "system"},
                {"name": "Check Failed Logins", "cmd": "sudo lastb", "admin": True, "category": "system"},
            ]
        elif self.current_os == "Windows":
            return [
                {"name": "System Information", "cmd": "systeminfo", "admin": False, "category": "system"},
                {"name": "DISM Health Check", "cmd": "DISM /Online /Cleanup-Image /CheckHealth", "admin": True, "category": "system"},
                {"name": "DISM Restore Health", "cmd": "DISM /Online /Cleanup-Image /RestoreHealth", "admin": True, "category": "system"},
                {"name": "System File Check", "cmd": "sfc /scannow", "admin": True, "category": "system"},
                {"name": "Chkdsk Scan", "cmd": "chkdsk C: /scan", "admin": True, "category": "hardware"},
                {"name": "Windows Defender Quick Scan", "cmd": "MpCmdRun -Scan -ScanType 1", "admin": True, "category": "malware"},
                {"name": "Windows Defender Full Scan", "cmd": "MpCmdRun -Scan -ScanType 2", "admin": True, "category": "malware"},
                {"name": "Check for Windows Updates", "cmd": "powershell Get-WindowsUpdate", "admin": True, "category": "system"},
                {"name": "Clear Temp Files", "cmd": "del /q/f/s %TEMP%\\*", "admin": False, "category": "system"},
                {"name": "Flush DNS", "cmd": "ipconfig /flushdns", "admin": False, "category": "system"},
                {"name": "Performance Benchmark (CPU)", "cmd": "winsat cpu", "admin": True, "category": "performance"},
                {"name": "Performance Benchmark (Disk)", "cmd": "winsat disk", "admin": True, "category": "performance"},
                {"name": "Check Disk Health", "cmd": "powershell Get-PhysicalDisk | Get-StorageReliabilityCounter", "admin": True, "category": "hardware"},
                {"name": "Check Memory", "cmd": "mdsched.exe", "admin": True, "category": "hardware"},
                {"name": "Check Network", "cmd": "ping 8.8.8.8 -n 4", "admin": False, "category": "hardware"}
            ]
        return []

    def get_sudo_password(self):
        """Get sudo password from user"""
        password, ok = QInputDialog.getText(
            self, 
            'Sudo Password', 
            'Enter your sudo password:', 
            QLineEdit.Password
        )
        if ok:
            self.sudo_password = password
            self.status_bar.setText("Sudo password set (not stored)")
            self.heal_button.setEnabled(True)
            self.quick_scan_button.setEnabled(True)
            self.custom_scan_button.setEnabled(True)

    def quick_scan(self):
        """Perform a quick system scan"""
        if self.current_os == "Linux" and not self.sudo_password:
            QMessageBox.warning(self, "Warning", "Please set your sudo password first!")
            return
        
        self.heal_button.setEnabled(False)
        self.quick_scan_button.setEnabled(False)
        self.custom_scan_button.setEnabled(False)
        self.terminal.clear()
        self.current_command_index = 0
        self.progress_bar.setValue(0)
        self.status_bar.setText("Quick scan in progress...")
        self.loading_movie.start()
        
        self.append_to_terminal("=== CYBER - MEDIC PRO QUICK SCAN INITIATED ===", "#00ff00")
        self.append_to_terminal(f"Operating System: {self.current_os}", "#00a8ff")
        
        # Filter only quick scan commands
        quick_commands = []
        for cmd in self.healing_commands:
            if "quick" in cmd['name'].lower() or "basic" in cmd['name'].lower():
                quick_commands.append(cmd)
        
        if not quick_commands:
            quick_commands = self.healing_commands[:3]  # First 3 commands if no quick scan specific ones
            
        self.append_to_terminal(f"Found {len(quick_commands)} quick scan commands to execute\n", "#ffffff")
        
        self.execute_commands(quick_commands, quick_scan=True)

    def custom_scan(self):
        """Perform a custom system scan"""
        if self.current_os == "Linux" and not self.sudo_password:
            QMessageBox.warning(self, "Warning", "Please set your sudo password first!")
            return
        
        self.heal_button.setEnabled(False)
        self.quick_scan_button.setEnabled(False)
        self.custom_scan_button.setEnabled(False)
        self.terminal.clear()
        self.current_command_index = 0
        self.progress_bar.setValue(0)
        self.status_bar.setText("Custom scan in progress...")
        self.loading_movie.start()
        
        self.append_to_terminal("=== CYBER - MEDIC PRO CUSTOM SCAN INITIATED ===", "#00ff00")
        self.append_to_terminal(f"Operating System: {self.current_os}", "#00a8ff")
        
        # Get user selection for custom scan
        options = ["Malware", "Hardware", "Performance", "System"]
        selected_options, ok = QInputDialog.getItem(self, "Custom Scan", "Select scan type:", options, 0, False)
        if not ok or not selected_options:
            self.status_bar.setText("Custom scan cancelled")
            self.heal_button.setEnabled(True)
            self.quick_scan_button.setEnabled(True)
            self.custom_scan_button.setEnabled(True)
            return
        
        custom_commands = [cmd for cmd in self.healing_commands if cmd['category'] == selected_options.lower()]
        if not custom_commands:
            self.append_to_terminal(f"No commands found for {selected_options} scan", "#ff0000")
            self.status_bar.setText("Custom scan completed with no commands executed")
            self.heal_button.setEnabled(True)
            self.quick_scan_button.setEnabled(True)
            self.custom_scan_button.setEnabled(True)
            return
        
        self.append_to_terminal(f"Found {len(custom_commands)} commands for {selected_options} scan\n", "#ffffff")
        
        self.execute_commands(custom_commands, quick_scan=False)

    def start_healing(self):
        """Start the full healing process"""
        # Check for admin/sudo requirements
        if self.current_os == "Linux" and not self.sudo_password:
            QMessageBox.warning(self, "Warning", "Please set your sudo password first!")
            return
        
        if self.current_os == "Windows" and not self.is_admin_windows():
            QMessageBox.warning(
                self, 
                "Admin Required", 
                "Please run this program as Administrator on Windows"
            )
            return
        
        self.start_sound.play()
        self.heal_button.setEnabled(False)
        self.quick_scan_button.setEnabled(False)
        self.custom_scan_button.setEnabled(False)
        self.terminal.clear()
        self.current_command_index = 0
        self.progress_bar.setValue(0)
        self.status_bar.setText("Preparing system for healing...")
        self.loading_movie.start()
        
        self.append_to_terminal("=== CYBER - MEDIC PRO FULL SYSTEM SCAN INITIATED ===", "#00ff00")
        self.append_to_terminal(f"Operating System: {self.current_os}", "#00a8ff")
        self.append_to_terminal(f"Found {len(self.healing_commands)} commands to execute\n", "#ffffff")
        
        # Pre-healing step to kill interfering processes
        self.pre_healing_cleanup()
        self.execute_commands(self.healing_commands)

    def pre_healing_cleanup(self):
        """Kill conflicting apt/dpkg processes, recover any broken locks"""
        self.append_to_terminal("\n=== PRE-HEALING CLEANUP ===", "#00a8ff")
        self.append_to_terminal("Recovering broken locks & killing apt/dpkg processes...", "#00ff00")

        # 1) Kill apt / dpkg / snap / flatpak
        for proc in ["apt", "apt-get", "dpkg", "snap", "flatpak"]:
            try:
                pids = subprocess.check_output(["pgrep", "-f", proc], text=True).strip().split()
                for pid in pids:
                    self.append_to_terminal(f"Killing {proc} process {pid}", "#ff0000")
                    subprocess.run(["sudo", "kill", "-9", pid], stderr=subprocess.DEVNULL)
                    time.sleep(1)
            except subprocess.CalledProcessError:
                pass  # no process running

        # 2) Remove stale lock files
        lock_files = [
            "/var/lib/dpkg/lock",
            "/var/lib/dpkg/lock-frontend",
            "/var/cache/apt/archives/lock"
        ]
        for lock in lock_files:
            subprocess.run(["sudo", "rm", "-f", lock], stderr=subprocess.DEVNULL)

        # 3) Repair dpkg state
        self.append_to_terminal("Repairing dpkg state...", "#00ff00")
        subprocess.run(["sudo", "dpkg", "--configure", "-a"], stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "apt", "install", "-f", "-y"], stderr=subprocess.DEVNULL)

        self.append_to_terminal("Pre-healing cleanup complete", "#00ff00")

    def execute_commands(self, commands, quick_scan=False):
        """Execute a list of commands"""
        self.commands_to_execute = commands
        self.current_command_index = 0
        self.scan_results = {
            'malware': {'found': 0, 'removed': 0, 'details': ''},
            'hardware': {'issues': 0, 'details': ''},
            'performance': {'benchmarks': {}, 'details': ''},
            'system': {'issues': 0, 'details': ''}
        }
        self.execute_next_command_in_list(quick_scan)

    def execute_next_command_in_list(self, quick_scan=False):
        """Execute the next command in the current list"""
        if self.current_command_index >= len(self.commands_to_execute):
            if quick_scan:
                self.quick_scan_complete()
            else:
                self.healing_complete()
            return
            
        command = self.commands_to_execute[self.current_command_index]
        self.current_task.setText(f"Executing: {command['name']}")
        self.progress_bar.setValue(int((self.current_command_index / len(self.commands_to_execute)) * 100))
        
        self.append_to_terminal(f"\n=== {command['name'].upper()} ===", "#00a8ff")
        self.append_to_terminal(f"$ {command['cmd']}", "#00ff00")
        
        # Start typing sound
        self.typing_sound.play()
        
        # Create and start worker thread
        self.worker = ScanWorker(
            command["cmd"], 
            command["admin"], 
            self.sudo_password
        )
        self.worker.update_signal.connect(self.append_to_terminal)
        self.worker.result_signal.connect(lambda result: self.command_finished(result, command, quick_scan))
        self.worker.start()

    def command_finished(self, result, command, quick_scan):
        """Handle when a command finishes"""
        # Stop typing sound
        self.typing_sound.stop()
        
        # Process results based on command category
        if command['category'] == 'malware':
            self.process_malware_results(result, command)
        elif command['category'] == 'hardware':
            self.process_hardware_results(result, command)
        elif command['category'] == 'performance':
            self.process_performance_results(result, command)
        else:  # system
            self.process_system_results(result, command)
        
        self.current_command_index += 1
        self.execute_next_command_in_list(quick_scan)

    def process_malware_results(self, result, command):
        """Process results from malware scans"""
        if result['errors']:
            self.append_to_terminal(f"Command failed with errors", "#ff0000")
            return
        
        output = result['output']
        self.scan_results['malware']['details'] += f"\n=== {command['name']} ===\n{output}\n"
        
        # Simple malware detection
        malware_count = result['malware_found']
        if malware_count > 0:
            self.scan_results['malware']['found'] += malware_count
            self.append_to_terminal(f"⚠️  Found {malware_count} potential malware indicators", "#ff9900")
            
            # Try to remove if this was a removal command
            if 'remove' in command['name'].lower() or 'clean' in command['name'].lower():
                removed_count = output.count('removed') + output.count('cleaned') + output.count('deleted')
                self.scan_results['malware']['removed'] += removed_count
                self.append_to_terminal(f"✅  Removed {removed_count} threats", "#00ff00")
        else:
            self.append_to_terminal("✅  No malware detected", "#00ff00")

    def process_hardware_results(self, result, command):
        """Process results from hardware diagnostics"""
        if result['errors']:
            self.append_to_terminal(f"Command failed with errors", "#ff0000")
            return
        
        output = result['output']
        self.scan_results['hardware']['details'] += f"\n=== {command['name']} ===\n{output}\n"
        
        # Simple hardware issue detection
        issue_keywords = ['error', 'fail', 'warning', 'bad', 'critical']
        issues_found = sum(output.lower().count(keyword) for keyword in issue_keywords)
        
        if issues_found > 0:
            self.scan_results['hardware']['issues'] += issues_found
            self.append_to_terminal(f"⚠️  Found {issues_found} potential hardware issues", "#ff9900")
        else:
            self.append_to_terminal("✅  No hardware issues detected", "#00ff00")

    def process_performance_results(self, result, command):
        """Process performance benchmark results"""
        if result['errors']:
            self.append_to_terminal(f"Command failed with errors", "#ff0000")
            return
        
        output = result['output']
        self.scan_results['performance']['details'] += f"\n=== {command['name']} ===\n{output}\n"
        
        # Extract benchmark numbers
        benchmark_name = command['name'].split('(')[1].split(')')[0].lower()
        numbers = re.findall(r"\d+\.\d+|\d+", output)
        
        if numbers:
            # Get the last number which is usually the score
            score = float(numbers[-1])
            self.scan_results['performance']['benchmarks'][benchmark_name] = score
            self.append_to_terminal(f"📊  {benchmark_name.upper()} score: {score}", "#00a8ff")

    def process_system_results(self, result, command):
        """Process general system check results"""
        if result['errors']:
            self.append_to_terminal(f"Command failed with errors", "#ff0000")
            return
        
        output = result['output']
        self.scan_results['system']['details'] += f"\n=== {command['name']} ===\n{output}\n"
        
        # Simple system issue detection
        issue_keywords = ['error', 'fail', 'warning', 'corrupt']
        issues_found = sum(output.lower().count(keyword) for keyword in issue_keywords)
        
        if issues_found > 0:
            self.scan_results['system']['issues'] += issues_found
            self.append_to_terminal(f"⚠️  Found {issues_found} potential system issues", "#ff9900")
        else:
            self.append_to_terminal("✅  No system issues detected", "#00ff00")

    def is_admin_windows(self):
        """Check if running as admin on Windows"""
        try:
            return os.getuid() == 0
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0

    def append_to_terminal(self, text, color):
        """Append colored text to the terminal"""
        self.terminal.setTextColor(QColor(color))
        self.terminal.append(text)
        self.terminal.ensureCursorVisible()

    def quick_scan_complete(self):
        """Handle quick scan completion"""
        self.success_sound.play()
        self.progress_bar.setValue(100)
        self.current_task.setText("Quick scan complete!")
        self.status_bar.setText("System quick scan completed")
        self.heal_button.setEnabled(True)
        self.quick_scan_button.setEnabled(True)
        self.custom_scan_button.setEnabled(True)
        self.loading_movie.stop()
        
        self.append_to_terminal("\n=== QUICK SCAN COMPLETE ===", "#00ff00")
        self.append_to_terminal("Quick scan finished. Review results below or run full scan for complete diagnostics.", "#ffffff")
        
        # Show quick results
        self.show_results_dialog(quick_scan=True)

    def healing_complete(self):
        """Handle full healing completion"""
        self.success_sound.play()
        self.progress_bar.setValue(100)
        self.current_task.setText("Full system scan complete!")
        self.status_bar.setText("System healing completed successfully")
        self.heal_button.setEnabled(True)
        self.quick_scan_button.setEnabled(True)
        self.custom_scan_button.setEnabled(True)
        self.loading_movie.stop()
        
        self.append_to_terminal("\n=== FULL SYSTEM SCAN COMPLETE ===", "#00ff00")
        self.append_to_terminal("All commands executed. Your system should be optimized now.", "#ffffff")
        
        # Show comprehensive results
        self.show_results_dialog()

    def show_results_dialog(self, quick_scan=False):
        """Show detailed scan results in a dialog"""
        dialog = QDialog()
        dialog.setWindowTitle("Scan Results Summary")
        dialog.setMinimumSize(800, 600)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #222;
                color: #eee;
            }
            QTabWidget::pane {
                border: 1px solid #444;
            }
            QTabBar::tab {
                background: #333;
                color: #eee;
                padding: 8px;
                border: 1px solid #444;
            }
            QTabBar::tab:selected {
                background: #555;
            }
            QGroupBox {
                border: 1px solid #444;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
            }
            QTextEdit {
                background-color: #111;
                color: #eee;
                border: 1px solid #444;
            }
            QLabel {
                color: #eee;
            }
        """)
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        # Create tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Summary tab
        summary_tab = QWidget()
        summary_layout = QVBoxLayout()
        summary_tab.setLayout(summary_layout)
        
        # Add summary stats
        stats_group = QGroupBox("Scan Statistics")
        stats_layout = QFormLayout()
        
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        stats_layout.addRow(QLabel("Scan Time:"), QLabel(scan_time))
        stats_layout.addRow(QLabel("Scan Type:"), QLabel("Quick Scan" if quick_scan else "Full Scan"))
        
        if self.scan_results['malware']['found'] > 0:
            stats_layout.addRow(QLabel("Malware Found:"), QLabel(f"{self.scan_results['malware']['found']} (Removed: {self.scan_results['malware']['removed']})"))
        else:
            stats_layout.addRow(QLabel("Malware:"), QLabel("No issues detected"))
            
        if self.scan_results['hardware']['issues'] > 0:
            stats_layout.addRow(QLabel("Hardware Issues:"), QLabel(f"{self.scan_results['hardware']['issues']} potential issues"))
        else:
            stats_layout.addRow(QLabel("Hardware:"), QLabel("No issues detected"))
            
        if self.scan_results['system']['issues'] > 0:
            stats_layout.addRow(QLabel("System Issues:"), QLabel(f"{self.scan_results['system']['issues']} potential issues"))
        else:
            stats_layout.addRow(QLabel("System:"), QLabel("No issues detected"))
            
        if self.scan_results['performance']['benchmarks']:
            stats_layout.addRow(QLabel("Performance Benchmarks:"), QLabel(f"{len(self.scan_results['performance']['benchmarks'])} tests completed"))
        
        stats_group.setLayout(stats_layout)
        summary_layout.addWidget(stats_group)
        
        # Add recommendations
        rec_group = QGroupBox("Recommendations")
        rec_layout = QVBoxLayout()
        
        recommendations = []
        if self.scan_results['malware']['found'] > 0 and self.scan_results['malware']['found'] > self.scan_results['malware']['removed']:
            recommendations.append("Run additional malware scans to remove remaining threats")
        if self.scan_results['hardware']['issues'] > 0:
            recommendations.append("Check hardware components for potential failures")
        if self.scan_results['system']['issues'] > 0:
            recommendations.append("Review system logs for detailed error information")
        if not quick_scan and len(recommendations) == 0:
            recommendations.append("Your system appears to be in good condition")
        elif quick_scan and len(recommendations) == 0:
            recommendations.append("No issues found in quick scan. Run full scan for complete diagnostics")
            
        if not recommendations:
            recommendations.append("No recommendations at this time")
            
        for rec in recommendations:
            rec_layout.addWidget(QLabel(f"• {rec}"))
            
        rec_group.setLayout(rec_layout)
        summary_layout.addWidget(rec_group)
        
        tabs.addTab(summary_tab, "Summary")
        
        # Detailed tabs for each category
        self.add_details_tab(tabs, "Malware", self.scan_results['malware']['details'])
        self.add_details_tab(tabs, "Hardware", self.scan_results['hardware']['details'])
        self.add_details_tab(tabs, "Performance", self.scan_results['performance']['details'])
        self.add_details_tab(tabs, "System", self.scan_results['system']['details'])
        
        # Add close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)
        
        dialog.exec_()

    def add_details_tab(self, tabs, title, content):
        """Add a details tab with scrollable content"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        content_widget = QWidget()
        content_layout = QVBoxLayout()
        content_widget.setLayout(content_layout)
        
        text_edit = QTextEdit()
        text_edit.setPlainText(content)
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier New", 10))
        content_layout.addWidget(text_edit)
        
        scroll.setWidget(content_widget)
        layout.addWidget(scroll)
        
        tabs.addTab(tab, title)

    

    def closeEvent(self, event):
        """Handle window close event"""
        if self.process.state() == QProcess.Running:
            self.process.kill()
        self.media_player.stop()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the main window
    healer = USBHealer()
    healer.show()
    
    sys.exit(app.exec_())