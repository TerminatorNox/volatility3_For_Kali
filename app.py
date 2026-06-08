#!/usr/bin/env python3

import os
import sys
import subprocess
import threading
import shutil
import time
import re
import urllib.request
import zipfile
from pathlib import Path

from PyQt6.QtWidgets import *
from PyQt6.QtGui import *
from PyQt6.QtCore import *
from PyQt6.QtCore import pyqtSignal

from reportlab.platypus import *
from reportlab.lib.styles import getSampleStyleSheet

########################################################################
# CONFIGURATION
########################################################################

VOLATILITY_GIT = "https://github.com/volatilityfoundation/volatility3.git"

HOME = str(Path.home())

VOLATILITY_PATHS = [
    os.path.join(HOME, "volatility3"),
    "/opt/volatility3",
    "/usr/share/volatility3"
]

SUPPORTED_EXTENSIONS = [
    ".lime",
    ".mem",
    ".data",
    ".raw",
    ".img",
    ".bin"
]

memory_image = None
volatility_directory = None

########################################################################
# PLUGIN LIST
########################################################################

PLUGINS = {

    "Processes": [

        "linux.pslist",
        "linux.psaux",
        "linux.pstree",
        "linux.pslist_cache",
        "linux.pidhashtable",
        "linux.psxview",
        "linux.lsof"

    ],

    "Process Memory": [

        "linux.memmap",
        "linux.proc_maps",
        "linux.dump_map",
        "linux.bash"

    ],

    "Kernel Memory": [

        "linux.lsmod",
        "linux.moddump",
        "linux.tmpfs"

    ],

    "Rootkit Detection": [

        "linux.check_afinfo",
        "linux.check_tty",
        "linux.keyboard_notifier",
        "linux.check_creds",
        "linux.check_fop",
        "linux.check_idt",
        "linux.check_syscall",
        "linux.check_modules"

    ],

    "Networking": [

        "linux.arp",
        "linux.ifconfig",
        "linux.route_cache",
        "linux.netstat",
        "linux.pkt_queues",
        "linux.sk_buff_cache"

    ],

    "System Information": [

        "linux.cpuinfo",
        "linux.dmesg",
        "linux.iomem",
        "linux.slabinfo",
        "linux.mount",
        "linux.mount_cache",
        "linux.dentry_cache",
        "linux.find_file",
        "linux.vma_cache"

    ],

    "Miscellaneous": [

        "linux.volshell",
        "linux.yarascan"

    ]

}

########################################################################
# HELPER FUNCTIONS
########################################################################

def run_command(command):

    try:

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        return process

    except Exception as e:

        return str(e)


def command_exists(command):

    return shutil.which(command) is not None


def extract_kernel_version(text):
    """Extract kernel version from banner output."""
    if isinstance(text, list):
        text = '\n'.join(text)
    match = re.search(r'Linux version ([\d\.\+\-a-z]+)', text)
    return match.group(1) if match else None


def download_symbols_for_kernel(kernel_version, vol_dir):
    """
    Attempt to download Kali Linux symbols for kernel.
    Returns (success: bool, message: str)
    """
    if not vol_dir or not os.path.exists(vol_dir):
        return False, "Volatility3 not found"
    
    symbols_dir = os.path.join(vol_dir, "volatility3", "symbols", "linux")
    os.makedirs(symbols_dir, exist_ok=True)
    
    # Parse kernel version: 6.19.14+kali-amd64 -> base_version
    match = re.match(r'([\d\.]+)\+kali', kernel_version)
    if not match:
        return False, f"Could not parse kernel version: {kernel_version}"
    
    base_version = match.group(1)
    
    # Try common Kali symbol filenames
    symbol_urls = [
        f"https://mirrors.kali.org/volatility-symbols/linux/kali-{base_version}-1kali1-x86_64.zip",
        f"https://mirrors.kali.org/volatility-symbols/linux/Linux-{base_version}-x86_64.zip",
        f"https://mirrors.kali.org/volatility-symbols/linux/kali-{base_version}-x86_64.zip",
    ]
    
    for url in symbol_urls:
        try:
            zip_file = os.path.join(symbols_dir, os.path.basename(url))
            
            # Download using urllib (no external dependencies)
            urllib.request.urlretrieve(url, zip_file)
            
            if os.path.exists(zip_file) and os.path.getsize(zip_file) > 100:
                try:
                    # Verify it's a valid zip file before extracting
                    with zipfile.ZipFile(zip_file, 'r') as zf:
                        # Test the zip file
                        test_result = zf.testzip()
                        if test_result is None:
                            # Valid zip, extract it
                            zf.extractall(symbols_dir)
                            os.remove(zip_file)
                            return True, f"Downloaded and extracted symbols for kernel {kernel_version}"
                except zipfile.BadZipFile:
                    # Not a valid zip, likely HTML error page
                    os.remove(zip_file)
                    continue
        except Exception as e:
            # Try next URL
            if os.path.exists(zip_file):
                try:
                    os.remove(zip_file)
                except:
                    pass
            continue
    
    return False, "Could not download symbols. Check network or try manual download."



########################################################################
# VOLATILITY INSTALLER
########################################################################

class VolatilityInstaller:

    def __init__(self):

        self.install_path = None

    def search(self):

        global volatility_directory

        for path in VOLATILITY_PATHS:

            if os.path.exists(path):

                if os.path.exists(
                    os.path.join(path, "vol.py")
                ):

                    self.install_path = path
                    volatility_directory = path
                    return True

        return False

    def install(self):

        global volatility_directory

        target = os.path.join(HOME, "volatility3")

        try:

            subprocess.check_call([

                "git",
                "clone",
                VOLATILITY_GIT,
                target

            ])

            self.install_path = target
            volatility_directory = target

            return True

        except:

            return False

########################################################################
# DEPENDENCY CHECKER
########################################################################

class DependencyChecker:

    def __init__(self):

        self.status = {}

    def check(self):

        packages = [

            "python3",
            "git",
            "pip3"

        ]

        for item in packages:

            self.status[item] = command_exists(item)

        return self.status

    def install_python_package(self, package):

        try:

            subprocess.check_call([

                "pip3",
                "install",
                package

            ])

            return True

        except:

            return False

########################################################################
# SYMBOL CHECKER
########################################################################

class SymbolChecker:

    def __init__(self):

        pass

    def get_symbol_directory(self):

        global volatility_directory

        if volatility_directory is None:

            return None

        return os.path.join(

            volatility_directory,
            "volatility3",
            "symbols",
            "linux"

        )

    def check(self):

        folder = self.get_symbol_directory()

        if folder is None:

            return False

        if not os.path.exists(folder):

            return False

        files = os.listdir(folder)

        if len(files) == 0:

            return False

        return True

########################################################################
# BANNER DETECTOR
########################################################################

class BannerDetector:

    def __init__(self):

        pass

    def detect(self, image):

        global volatility_directory

        if volatility_directory is None:

            return None

        command = [

            "python3",

            os.path.join(
                volatility_directory,
                "vol.py"
            ),

            "-f",
            image,

            "banners.Banners"

        ]

        return run_command(command)
    ########################################################################
# TERMINAL WIDGET
########################################################################

class TerminalWidget(QPlainTextEdit):

    append_text = pyqtSignal(str)

    def __init__(self):

        super().__init__()

        self.setReadOnly(True)

        font = QFont("Courier New")
        font.setPointSize(10)

        self.setFont(font)

        self.setStyleSheet("""

            QPlainTextEdit
            {
                background-color:#000000;
                color:#00FF00;
                border:1px solid #444444;
            }

        """)

        self.append_text.connect(self._append)

    def _append(self, text: str):

        self.appendPlainText(text)

        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def write(self, text):

        try:

            self.append_text.emit(str(text))

        except Exception:

            # Fallback to direct append if signals fail

            self._append(str(text))

    def clear_terminal(self):

        self.clear()


########################################################################
# PLUGIN TREE
########################################################################

class PluginTree(QTreeWidget):

    def __init__(self):

        super().__init__()

        self.setHeaderLabel("Volatility Plugins")

        self.populate()

    def populate(self):

        self.clear()

        for category in PLUGINS:

            parent = QTreeWidgetItem(self)

            parent.setText(0, category)

            for plugin in PLUGINS[category]:

                child = QTreeWidgetItem(parent)

                child.setText(0, plugin)

    def get_selected_plugin(self):

        item = self.currentItem()

        if item is None:
            return None

        if item.parent() is None:
            return None

        return item.text(0)


########################################################################
# MAIN WINDOW
########################################################################

class MainWindow(QMainWindow):

    plugin_finished = pyqtSignal(str)
    set_progress_range = pyqtSignal(int, int)
    set_progress_value = pyqtSignal(int)

    def __init__(self):

        super().__init__()

        self.memory_image = None
        self.current_process = None

        self.setWindowTitle(
            "Volatility 3 Linux GUI"
        )

        self.resize(1500, 850)

        self.create_ui()

        self.apply_theme()

        self.initialize()

        # connect signals for thread-safe UI updates
        self.plugin_finished.connect(self._on_plugin_finished)
        self.set_progress_range.connect(self.progress.setRange)
        self.set_progress_value.connect(self.progress.setValue)

    def _on_plugin_finished(self, plugin_name: str):

        self.terminal.write("[+] Plugin finished: " + plugin_name)

        self.current_process = None

        # re-enable run controls
        try:
            self.run_button.setEnabled(True)
            self.plugin_tree.setEnabled(True)
        except Exception:
            pass

        # indicate finished and reset shortly after
        self.set_progress_range.emit(0, 100)
        self.set_progress_value.emit(100)

        QTimer.singleShot(500, lambda: self.set_progress_value.emit(0))

    ####################################################################

    def create_ui(self):

        main_widget = QWidget()

        self.setCentralWidget(main_widget)

        layout = QHBoxLayout(main_widget)

        ############################################################

        left_panel = QWidget()

        left_layout = QVBoxLayout(left_panel)

        ############################################################

        self.search_box = QLineEdit()

        self.search_box.setPlaceholderText(
            "Search Plugin..."
        )

        self.search_box.textChanged.connect(
            self.search_plugins
        )

        left_layout.addWidget(
            self.search_box
        )

        ############################################################

        self.plugin_tree = PluginTree()

        left_layout.addWidget(
            self.plugin_tree
        )

        ############################################################

        self.run_button = QPushButton(
            "Run Plugin"
        )

        self.run_button.clicked.connect(
            self.run_selected_plugin
        )

        left_layout.addWidget(
            self.run_button
        )

        ############################################################

        self.memory_label = QLabel(
            "No Memory Image Loaded"
        )

        left_layout.addWidget(
            self.memory_label
        )

        ############################################################

        layout.addWidget(
            left_panel,
            30
        )

        ############################################################

        right_panel = QWidget()

        right_layout = QVBoxLayout(right_panel)

        ############################################################

        self.terminal = TerminalWidget()

        right_layout.addWidget(
            self.terminal
        )

        ############################################################

        self.progress = QProgressBar()

        self.progress.setValue(0)

        right_layout.addWidget(
            self.progress
        )

        ############################################################

        layout.addWidget(
            right_panel,
            70
        )

        ############################################################

        self.create_toolbar()

        self.create_statusbar()

    ####################################################################

    def create_toolbar(self):

        toolbar = QToolBar()

        self.addToolBar(toolbar)

        ############################################################

        install_btn = QAction(
            "Install Volatility3",
            self
        )

        install_btn.triggered.connect(
            self.install_volatility
        )

        toolbar.addAction(
            install_btn
        )

        ############################################################

        load_btn = QAction(
            "Load Memory",
            self
        )

        load_btn.triggered.connect(
            self.load_memory
        )

        toolbar.addAction(
            load_btn
        )

        ############################################################

        clear_btn = QAction(
            "Clear Terminal",
            self
        )

        clear_btn.triggered.connect(
            self.terminal.clear_terminal
        )

        toolbar.addAction(
            clear_btn
        )

        ############################################################

        save_txt = QAction(
            "Save TXT",
            self
        )

        save_txt.triggered.connect(
            self.save_txt
        )

        toolbar.addAction(
            save_txt
        )

        ############################################################

        save_pdf = QAction(
            "Save PDF",
            self
        )

        save_pdf.triggered.connect(
            self.save_pdf
        )

        toolbar.addAction(
            save_pdf
        )

        stop_btn = QAction(
            "Stop Plugin",
            self
        )

        stop_btn.triggered.connect(self.stop_current_plugin)

        toolbar.addAction(stop_btn)

        ############################################################

        download_symbols_btn = QAction(
            "Download Symbols",
            self
        )

        download_symbols_btn.triggered.connect(self.download_symbols_manual)

        toolbar.addAction(download_symbols_btn)

        ############################################################

        generate_symbols_btn = QAction(
            "Generate Symbols Locally",
            self
        )

        generate_symbols_btn.triggered.connect(self.generate_symbols_local)

        toolbar.addAction(generate_symbols_btn)

        ############################################################

        quick_fix_btn = QAction(
            "Quick Fix Symbols",
            self
        )

        quick_fix_btn.triggered.connect(self.quick_fix_symbols)

        toolbar.addAction(quick_fix_btn)

    ####################################################################

    def create_statusbar(self):

        self.status = self.statusBar()

        self.status.showMessage(
            "Initializing..."
        )

    ####################################################################

    def apply_theme(self):

        self.setStyleSheet("""

        QWidget
        {
            background-color:#202020;
            color:white;
        }

        QPushButton
        {
            background-color:#303030;
            border:1px solid #505050;
            padding:6px;
        }

        QPushButton:hover
        {
            background-color:#505050;
        }

        QTreeWidget
        {
            background-color:#2B2B2B;
        }

        QLineEdit
        {
            background-color:#2B2B2B;
            border:1px solid #555555;
            padding:5px;
        }

        QProgressBar
        {
            border:1px solid gray;
        }

        """)

    ####################################################################

    def initialize(self):

        self.status.showMessage(
            "Checking Volatility3..."
        )

        installer = VolatilityInstaller()

        if installer.search():

            self.terminal.write(
                "[+] Volatility3 Found"
            )

        else:

            self.terminal.write(
                "[-] Volatility3 Not Found"
            )

        checker = DependencyChecker()

        result = checker.check()

        for item in result:

            if result[item]:

                self.terminal.write(
                    "[OK] " + item
                )

            else:

                self.terminal.write(
                    "[MISSING] " + item
                )

        self.status.showMessage(
            "Ready"
        )

    ####################################################################

    def search_plugins(self):

        text = self.search_box.text().lower()

        root = self.plugin_tree.invisibleRootItem()

        for i in range(root.childCount()):

            category = root.child(i)

            visible = False

            for j in range(category.childCount()):

                plugin = category.child(j)

                if text in plugin.text(0).lower():

                    plugin.setHidden(False)

                    visible = True

                else:

                    plugin.setHidden(True)

            category.setHidden(
                not visible
            )

    ####################################################################

    def load_memory(self):

        file_name, _ = QFileDialog.getOpenFileName(

            self,

            "Select Memory Image",

            "",

            "Memory Images (*.lime *.mem *.data *.raw *.img *.bin)"

        )

        if file_name:

            self.memory_image = file_name

            self.memory_label.setText(

                "Loaded : " +

                os.path.basename(
                    file_name
                )

            )

            self.terminal.write(

                "[+] Memory Image Loaded"

            )

            self.terminal.write(

                file_name

            )

    ####################################################################

    def install_volatility(self):

        self.terminal.write("Starting Installation...")

        def worker():

            installer = VolatilityInstaller()

            success = installer.install()

            if success:

                self.terminal.write("[+] Volatility3 installed: " + str(installer.install_path))

            else:

                self.terminal.write("[!] Volatility3 installation failed. Check git and network.")

        threading.Thread(target=worker, daemon=True).start()

    ####################################################################

    def run_selected_plugin(self):
        global volatility_directory

        try:

            self.terminal.write("[*] Run Plugin invoked")

            plugin = self.plugin_tree.get_selected_plugin()

            if plugin is None:

                self.terminal.write("[!] No plugin selected")

                return

            if self.memory_image is None:

                self.terminal.write("[!] No memory image loaded")

                return

            if volatility_directory is None:

                self.terminal.write("[!] Volatility3 not found. Install or set path.")

                return

            vol_path = os.path.join(volatility_directory, "vol.py")

            if not os.path.exists(vol_path):

                self.terminal.write("[!] vol.py not found at: " + str(vol_path))

                return

            command = [

                sys.executable,

                vol_path,

                "-f",

                self.memory_image,

                plugin

            ]

            # disable run button to prevent duplicate runs
            try:
                self.run_button.setEnabled(False)
                self.plugin_tree.setEnabled(False)
            except Exception:
                pass

            def worker():
                try:
                    # run banners first to help detect kernel/symbol info
                    detected_kernel = None
                    try:
                        banner_cmd = [sys.executable, vol_path, '-f', self.memory_image, 'banners.Banners']
                        banner_proc = run_command(banner_cmd)

                        if isinstance(banner_proc, str):
                            self.terminal.write('[!] Failed to run banners.Banners: ' + banner_proc)
                        else:
                            banner_output = []
                            for line in banner_proc.stdout:
                                text = line.rstrip()
                                banner_output.append(text)
                                self.terminal.write(text)
                            banner_proc.wait()
                            
                            # Extract kernel version
                            detected_kernel = extract_kernel_version('\n'.join(banner_output))

                    except Exception as e:
                        self.terminal.write('[!] Error running banners: ' + str(e))

                    proc = run_command(command)

                    if isinstance(proc, str):
                        self.terminal.write("[!] Failed to start plugin: " + proc)
                        # re-enable UI
                        self.plugin_finished.emit(plugin)
                        return

                    # mark running process and set progress to busy
                    self.current_process = proc
                    try:
                        self.set_progress_range.emit(0, 0)
                    except Exception:
                        try:
                            self.progress.setRange(0, 0)
                        except Exception:
                            pass

                    unsatisfied_detected = False

                    for line in proc.stdout:
                        text = line.rstrip()
                        self.terminal.write(text)
                        if 'Unsatisfied requirement' in text or 'Unable to validate the plugin requirements' in text:
                            unsatisfied_detected = True

                    if unsatisfied_detected and detected_kernel:
                        self.terminal.write('[*] Attempting to download kernel symbols...')
                        success, msg = download_symbols_for_kernel(detected_kernel, volatility_directory)
                        self.terminal.write('[*] ' + msg)
                        
                        if success:
                            self.terminal.write('[*] Retrying plugin with downloaded symbols...')
                            time.sleep(1)
                            
                            # Retry the plugin
                            proc2 = run_command(command)
                            if not isinstance(proc2, str):
                                for line in proc2.stdout:
                                    self.terminal.write(line.rstrip())
                                proc2.wait()
                            else:
                                self.terminal.write('[!] Failed to retry plugin: ' + proc2)
                        else:
                            self.terminal.write('')
                            self.terminal.write('[!] WARNING: Kernel symbols are missing!')
                            self.terminal.write('[!] Download from Kali mirrors failed.')
                            self.terminal.write('')
                            self.terminal.write('[+] SOLUTION: Click "Quick Fix Symbols" button in toolbar')
                            self.terminal.write('[i] This will:')
                            self.terminal.write('[i]   1. Install kernel headers')
                            self.terminal.write('[i]   2. Generate symbols for kernel ' + detected_kernel)
                            self.terminal.write('[i]   3. Then re-run the plugin')
                            self.terminal.write('')
                            self.terminal.write('[i] Detected kernel: ' + detected_kernel)
                    elif unsatisfied_detected:
                        self.terminal.write('[!] Plugin reported unsatisfied requirements.')
                        self.terminal.write('[!] Kernel symbols are missing.')
                        self.terminal.write('[+] Click "Quick Fix Symbols" button in toolbar to fix this.')

                    proc.wait()
                    self.plugin_finished.emit(plugin)

                except Exception as e:
                    self.terminal.write('[!] Error in plugin worker: ' + str(e))
                    import traceback
                    self.terminal.write('\n'.join(traceback.format_exc().splitlines()))
                    try:
                        self.plugin_finished.emit(plugin)
                    except Exception:
                        pass

            threading.Thread(target=worker, daemon=True).start()

        except Exception as e:

            # ensure UI stays responsive and show the error
            try:
                self.run_button.setEnabled(True)
                self.plugin_tree.setEnabled(True)
            except Exception:
                pass

            self.terminal.write("[!] Exception in run_selected_plugin: " + str(e))
            import traceback
            self.terminal.write('\n'.join(traceback.format_exc().splitlines()))

    ####################################################################

    def save_txt(self):

        text = self.terminal.toPlainText()

        file_name, _ = QFileDialog.getSaveFileName(self, "Save Text", "", "Text Files (*.txt);;All Files (*)")

        if file_name:

            try:

                with open(file_name, "w", encoding="utf-8") as f:

                    f.write(text)

                self.terminal.write("[+] Saved TXT: " + file_name)

            except Exception as e:

                self.terminal.write("[!] Failed to save TXT: " + str(e))

    ####################################################################

    def save_pdf(self):

        text = self.terminal.toPlainText()

        file_name, _ = QFileDialog.getSaveFileName(self, "Save PDF", "", "PDF Files (*.pdf);;All Files (*)")

        if not file_name:

            return

        try:

            from reportlab.pdfgen import canvas

            c = canvas.Canvas(file_name)

            width, height = 595, 842

            y = height - 40

            lines = text.splitlines()

            for line in lines:

                c.drawString(40, y, line)

                y -= 12

                if y < 40:

                    c.showPage()

                    y = height - 40

            c.save()

            self.terminal.write("[+] Saved PDF: " + file_name)

        except Exception as e:

            self.terminal.write("[!] Failed to save PDF: " + str(e))

    def stop_current_plugin(self):

        if self.current_process is None:

            self.terminal.write("[!] No running plugin to stop")

            return

        try:

            proc = self.current_process

            proc.terminate()

            self.terminal.write("[+] Sent terminate to running plugin")

        except Exception as e:

            self.terminal.write("[!] Failed to stop plugin: " + str(e))

    def download_symbols_manual(self):

        global volatility_directory

        if volatility_directory is None:

            self.terminal.write("[!] Volatility3 not found. Install it first.")

            return

        # Prompt for kernel version
        text, ok = QInputDialog.getText(
            self,
            "Download Kernel Symbols",
            "Enter kernel version (e.g., 6.19.14+kali-amd64):\nOr press Cancel to auto-detect from banners.",
            QLineEdit.EchoMode.Normal,
            ""
        )

        if not ok and text == "":
            # Auto-detect mode: run banners
            self.terminal.write("[*] Auto-detecting kernel version via banners...")
            
            vol_path = os.path.join(volatility_directory, "vol.py")
            if not self.memory_image:
                self.terminal.write("[!] No memory image loaded. Load one first.")
                return
            
            banner_cmd = [sys.executable, vol_path, '-f', self.memory_image, 'banners.Banners']
            proc = run_command(banner_cmd)
            
            detected_kernel = None
            if not isinstance(proc, str):
                for line in proc.stdout:
                    if 'Linux version' in line:
                        detected_kernel = extract_kernel_version(line)
                        if detected_kernel:
                            break
                proc.wait()
            
            if not detected_kernel:
                self.terminal.write("[!] Could not detect kernel version. Specify manually.")
                return
            
            kernel_version = detected_kernel
        elif ok:
            kernel_version = text.strip()
        else:
            return

        if not kernel_version:
            self.terminal.write("[!] No kernel version provided.")
            return

        self.terminal.write(f"[*] Downloading symbols for kernel: {kernel_version}")
        
        def worker():
            try:
                success, msg = download_symbols_for_kernel(kernel_version, volatility_directory)
                self.terminal.write("[*] " + msg)
                
                if success:
                    self.terminal.write("[+] Symbols downloaded and extracted successfully!")
                    self.terminal.write("[i] Try running your plugin again.")
                else:
                    self.terminal.write("[!] Download failed: " + msg)
                    self.terminal.write("[i] Kali mirrors may be unreachable. Try:")
                    self.terminal.write("[i] 1. Click 'Generate Symbols Locally' (if on same Kali system)")
                    self.terminal.write("[i] 2. Manually place symbol files in: " + os.path.join(volatility_directory, "volatility3", "symbols", "linux"))
                    
            except Exception as e:
                self.terminal.write("[!] Exception during download: " + str(e))
                import traceback
                self.terminal.write('\n'.join(traceback.format_exc().splitlines()))
        
        threading.Thread(target=worker, daemon=True).start()

    def generate_symbols_local(self):

        global volatility_directory

        if volatility_directory is None:
            self.terminal.write("[!] Volatility3 not found.")
            return

        self.terminal.write("[*] Generating symbols locally...")
        self.terminal.write("[i] This requires:")
        self.terminal.write("[i]   - Running on the same Kali system/kernel")
        self.terminal.write("[i]   - Kernel headers installed")
        self.terminal.write("[i]   - dwarf2json tool available")
        self.terminal.write("")

        def worker():
            try:
                # Try to find vmlinux
                vmlinux_paths = [
                    "/boot/vmlinux",
                    "/boot/vmlinux-" + os.uname().release,
                    "/usr/lib/debug/boot/vmlinux-" + os.uname().release,
                ]

                vmlinux_file = None
                for path in vmlinux_paths:
                    if os.path.exists(path):
                        vmlinux_file = path
                        self.terminal.write(f"[+] Found vmlinux: {path}")
                        break

                if not vmlinux_file:
                    self.terminal.write("[!] vmlinux not found in standard locations")
                    self.terminal.write("[i] To generate symbols locally:")
                    self.terminal.write("[i] 1. Install kernel headers: sudo apt-get install linux-headers-$(uname -r)")
                    self.terminal.write("[i] 2. Install dwarf2json: go get -u github.com/volatilityfoundation/dwarf2json")
                    self.terminal.write("[i] 3. Generate symbols:")
                    self.terminal.write("[i]    dwarf2json linux -s /boot/vmlinux-$(uname -r) > symbol_file.json")
                    self.terminal.write("[i] 4. Place symbol_file.json in:")
                    symbols_dir = os.path.join(volatility_directory, "volatility3", "symbols", "linux")
                    self.terminal.write(f"[i]    {symbols_dir}")
                    return

                # Try to use volatility3's symbol construction
                try:
                    vol_path = os.path.join(volatility_directory, "vol.py")
                    symbols_dir = os.path.join(volatility_directory, "volatility3", "symbols", "linux")
                    os.makedirs(symbols_dir, exist_ok=True)

                    # Try volatility3's native symbol generation
                    self.terminal.write("[*] Attempting to construct symbols using volatility3...")
                    construct_cmd = [
                        sys.executable,
                        "-m", "volatility3.framework.symbols.linux.linux",
                        "construct",
                        "-s", vmlinux_file,
                        "-o", os.path.join(symbols_dir, "Linux-" + os.uname().release + "-x86_64.json")
                    ]

                    result = subprocess.run(construct_cmd, capture_output=True, timeout=120, cwd=volatility_directory)
                    
                    if result.returncode == 0:
                        self.terminal.write("[+] Symbols generated successfully!")
                        self.terminal.write("[i] Try running your plugin again.")
                    else:
                        self.terminal.write("[!] Symbol construction failed")
                        if result.stderr:
                            self.terminal.write("[E] " + result.stderr.decode('utf-8', errors='ignore'))

                except Exception as e:
                    self.terminal.write("[!] Error during symbol generation: " + str(e))

            except Exception as e:
                self.terminal.write("[!] Exception: " + str(e))
                import traceback
                self.terminal.write('\n'.join(traceback.format_exc().splitlines()))

        threading.Thread(target=worker, daemon=True).start()

    def quick_fix_symbols(self):

        global volatility_directory

        if volatility_directory is None:
            self.terminal.write("[!] Volatility3 not found.")
            return

        self.terminal.write("[*] Quick Fix: Installing kernel headers and generating symbols...")
        self.terminal.write("[*] This may take a few minutes. Please wait...")
        self.terminal.write("")

        def worker():
            try:
                # Step 1: Install kernel headers
                self.terminal.write("[*] Step 1/3: Installing kernel headers (this may take a few minutes)...")
                kernel_release = os.uname().release
                install_cmd = ["sudo", "apt-get", "install", "-y", f"linux-headers-{kernel_release}"]
                
                result = subprocess.run(install_cmd, capture_output=True, timeout=600)
                
                if result.returncode == 0:
                    self.terminal.write("[+] Kernel headers installed successfully")
                else:
                    self.terminal.write("[!] Kernel headers installation may have failed")
                    if result.stderr:
                        err = result.stderr.decode('utf-8', errors='ignore')
                        if err:
                            self.terminal.write("[E] " + err[:200])

                # Step 2: Find vmlinux
                self.terminal.write("[*] Step 2/3: Locating vmlinux...")
                vmlinux_paths = [
                    "/boot/vmlinux",
                    f"/boot/vmlinux-{kernel_release}",
                    f"/usr/lib/debug/boot/vmlinux-{kernel_release}",
                ]

                vmlinux_file = None
                
                # Try standard paths first
                for path in vmlinux_paths:
                    if os.path.exists(path):
                        vmlinux_file = path
                        self.terminal.write(f"[+] Found vmlinux: {path}")
                        break
                
                # If not found, scan /boot for vmlinux* files
                if not vmlinux_file:
                    self.terminal.write("[*] Scanning /boot for vmlinux files...")
                    try:
                        boot_files = os.listdir("/boot")
                        vmlinux_files = [f for f in boot_files if f.startswith("vmlinux")]
                        
                        if vmlinux_files:
                            vmlinux_file = os.path.join("/boot", vmlinux_files[0])
                            self.terminal.write(f"[+] Found vmlinux: {vmlinux_file}")
                        else:
                            self.terminal.write("[!] No vmlinux files found in /boot")
                    except Exception as e:
                        self.terminal.write(f"[!] Error scanning /boot: {e}")
                
                # If still not found, scan /usr/lib/debug/boot
                if not vmlinux_file:
                    self.terminal.write("[*] Scanning /usr/lib/debug/boot for vmlinux files...")
                    try:
                        debug_boot = "/usr/lib/debug/boot"
                        if os.path.exists(debug_boot):
                            debug_files = os.listdir(debug_boot)
                            vmlinux_files = [f for f in debug_files if f.startswith("vmlinux")]
                            
                            if vmlinux_files:
                                vmlinux_file = os.path.join(debug_boot, vmlinux_files[0])
                                self.terminal.write(f"[+] Found vmlinux: {vmlinux_file}")
                    except Exception as e:
                        self.terminal.write(f"[!] Error scanning /usr/lib/debug/boot: {e}")

                # If still not found, try locate (faster than find)
                if not vmlinux_file:
                    self.terminal.write("[*] Trying locate command for faster search...")
                    try:
                        result = subprocess.run(["locate", "vmlinux"], capture_output=True, timeout=5)
                        if result.returncode == 0:
                            found_files = result.stdout.decode('utf-8', errors='ignore').strip().split('\n')
                            found_files = [f for f in found_files if f and os.path.exists(f)]
                            if found_files:
                                vmlinux_file = found_files[0]
                                self.terminal.write(f"[+] Found vmlinux via locate: {vmlinux_file}")
                    except Exception:
                        pass  # locate may not be available
                
                # If still not found, search common locations more efficiently
                if not vmlinux_file:
                    self.terminal.write("[*] Searching common kernel paths...")
                    search_paths = [
                        "/usr/src",
                        "/usr/lib",
                        "/lib/modules",
                        "/boot"
                    ]
                    try:
                        for search_path in search_paths:
                            if os.path.exists(search_path):
                                find_cmd = ["find", search_path, "-name", "vmlinux*", "-type", "f"]
                                result = subprocess.run(find_cmd, capture_output=True, timeout=10)
                                
                                if result.returncode == 0:
                                    found_files = result.stdout.decode('utf-8', errors='ignore').strip().split('\n')
                                    found_files = [f for f in found_files if f and os.path.exists(f)]
                                    
                                    if found_files:
                                        vmlinux_file = found_files[0]
                                        self.terminal.write(f"[+] Found vmlinux: {vmlinux_file}")
                                        break
                    except Exception as e:
                        self.terminal.write(f"[!] Error searching common paths: {e}")

                # Fallback: Try to find and decompress vmlinuz (compressed kernel)
                if not vmlinux_file:
                    self.terminal.write("[*] vmlinux not found. Trying to find and decompress vmlinuz...")
                    try:
                        # Look for vmlinuz files (compressed kernel)
                        for search_path in ["/boot", "/usr/lib/modules"]:
                            if os.path.exists(search_path):
                                for file in os.listdir(search_path):
                                    if file.startswith("vmlinuz"):
                                        vmlinuz_path = os.path.join(search_path, file)
                                        self.terminal.write(f"[*] Found compressed kernel: {vmlinuz_path}")
                                        
                                        # Try to decompress it
                                        try:
                                            import gzip
                                            import bz2
                                            
                                            # Try to read and decompress
                                            with open(vmlinuz_path, 'rb') as f:
                                                data = f.read(2)
                                                f.seek(0)
                                                
                                                # Check magic number for gzip
                                                if data == b'\x1f\x8b':
                                                    self.terminal.write("[*] Decompressing gzip-compressed kernel...")
                                                    vmlinux_decompressed = vmlinuz_path + ".vmlinux"
                                                    with gzip.open(vmlinuz_path, 'rb') as gz:
                                                        with open(vmlinux_decompressed, 'wb') as out:
                                                            out.write(gz.read())
                                                    if os.path.exists(vmlinux_decompressed):
                                                        vmlinux_file = vmlinux_decompressed
                                                        self.terminal.write(f"[+] Successfully decompressed to: {vmlinux_file}")
                                                        break
                                                # Check magic number for bzip2
                                                elif data == b'BZ':
                                                    self.terminal.write("[*] Decompressing bzip2-compressed kernel...")
                                                    vmlinux_decompressed = vmlinuz_path + ".vmlinux"
                                                    with bz2.open(vmlinuz_path, 'rb') as bz:
                                                        with open(vmlinux_decompressed, 'wb') as out:
                                                            out.write(bz.read())
                                                    if os.path.exists(vmlinux_decompressed):
                                                        vmlinux_file = vmlinux_decompressed
                                                        self.terminal.write(f"[+] Successfully decompressed to: {vmlinux_file}")
                                                        break
                                        except Exception as e:
                                            self.terminal.write(f"[!] Could not decompress {vmlinuz_path}: {e}")
                            
                            if vmlinux_file:
                                break
                    except Exception as e:
                        self.terminal.write(f"[!] Error searching for vmlinuz: {e}")

                if not vmlinux_file:
                    self.terminal.write("")
                    self.terminal.write("[!] vmlinux not found. Kernel headers may not include debug symbols.")
                    self.terminal.write("")
                    self.terminal.write("[i] SOLUTION: Check available kernel packages:")
                    self.terminal.write(f"[i]   apt-cache search linux-image | grep {kernel_release.split('+')[0]}")
                    self.terminal.write("")
                    self.terminal.write("[i] Try installing linux-image with dbg suffix:")
                    self.terminal.write(f"[i]   sudo apt-get install linux-image-{kernel_release} linux-image-dbg-{kernel_release}")
                    self.terminal.write("")
                    self.terminal.write("[i] OR install kernel source and extract vmlinux:")
                    self.terminal.write(f"[i]   sudo apt-get install linux-source-{kernel_release.split('+')[0]}")
                    self.terminal.write(f"[i]   Then rebuild locate database: sudo updatedb")
                    self.terminal.write("[i]   Then click 'Quick Fix Symbols' again")
                    return

                # Step 3: Generate symbols
                self.terminal.write("[*] Step 3/3: Generating kernel symbols...")
                symbols_dir = os.path.join(volatility_directory, "volatility3", "symbols", "linux")
                os.makedirs(symbols_dir, exist_ok=True)

                symbol_output = os.path.join(symbols_dir, f"Linux-{kernel_release}-x86_64.json")

                construct_cmd = [
                    sys.executable,
                    "-m", "volatility3.framework.symbols.linux.linux",
                    "construct",
                    "-s", vmlinux_file,
                    "-o", symbol_output
                ]

                result = subprocess.run(construct_cmd, capture_output=True, timeout=300, cwd=volatility_directory)
                
                if result.returncode == 0 and os.path.exists(symbol_output):
                    self.terminal.write("[+] Kernel symbols generated successfully!")
                    self.terminal.write(f"[+] Symbols saved to: {symbol_output}")
                    self.terminal.write("[+] Quick Fix complete! Try running your plugin now.")
                else:
                    self.terminal.write("[!] Symbol generation failed")
                    if result.stderr:
                        err = result.stderr.decode('utf-8', errors='ignore')
                        self.terminal.write("[E] " + err[:500])
                    self.terminal.write("[i] Check if kernel headers are properly installed:")
                    self.terminal.write(f"[i]   ls -la /usr/src/linux-headers-{kernel_release}")

            except Exception as e:
                self.terminal.write("[!] Exception: " + str(e))
                import traceback
                self.terminal.write('\n'.join(traceback.format_exc().splitlines()))

        threading.Thread(target=worker, daemon=True).start()


########################################################################
# APPLICATION ENTRY
########################################################################

if __name__ == "__main__":

    app = QApplication(sys.argv)

    window = MainWindow()

    window.show()

    sys.exit(
        app.exec()
    )