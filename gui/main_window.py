# sniffguard/gui/main_window.py

import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QComboBox, QTextEdit, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView
)
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt

from utils.logger import log
from utils.config import APP_TITLE
from core.OS_detect import check_os
from core.interface_detect import get_interfaces
from core.monitor_mode import enable_monitor_mode, disable_monitor_mode
from threads.scan_thread import ScanThread

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.is_linux = check_os()
        self.scan_thread = None
        self.monitor_interface = None
        
        self.init_ui()
        # ** FIX: Call apply_styles() BEFORE post_init_setup() **
        self.apply_styles() 
        self.post_init_setup()

    def init_ui(self):
        self.setWindowTitle(APP_TITLE)
        self.setGeometry(100, 100, 1000, 730) 
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: qlineargradient(spread:pad, x1:0.5, y1:0, x2:0.5, y2:1,
                                                  stop:0 rgba(29, 32, 36, 255),
                                                  stop:1 rgba(43, 48, 54, 255));
                color: #f8f9fa; font-family: 'Calibri', 'Segoe UI', sans-serif;
            }
            QLabel { font-size: 13px; font-weight: bold; color: #20c997; }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10); main_layout.setSpacing(8)

        control_panel = QHBoxLayout(); control_panel.setSpacing(8)
        self.btn_detect_interfaces = QPushButton("Detect Interfaces")
        self.interface_combo = QComboBox()
        self.btn_toggle_monitor = QPushButton("Enable Monitor")
        self.btn_scan_networks = QPushButton("Start Scan")
        self.btn_deauth_rogue = QPushButton("Deauth Rogue")
        
        control_panel.addWidget(self.btn_detect_interfaces)
        control_panel.addWidget(QLabel("Interface:"))
        control_panel.addWidget(self.interface_combo, 1)
        control_panel.addSpacing(15)
        control_panel.addWidget(self.btn_toggle_monitor)
        control_panel.addWidget(self.btn_scan_networks)
        control_panel.addWidget(self.btn_deauth_rogue)
        main_layout.addLayout(control_panel)

        tables_layout = QVBoxLayout(); tables_layout.setSpacing(5)
        main_layout.addLayout(tables_layout, 1)
        tables_layout.addWidget(QLabel("All Detected Networks"))
        self.network_table = self.create_table(["BSSID", "SSID", "Signal", "Channel", "Vendor", "Score", "Threat"])
        tables_layout.addWidget(self.network_table)
        tables_layout.addWidget(QLabel("High-Risk Rogue APs"))
        self.rogue_table = self.create_table(["BSSID", "SSID", "Threat", "Reason"])
        tables_layout.addWidget(self.rogue_table)
        main_layout.addWidget(QLabel("Activity Log"))
        self.log_display = QTextEdit(); self.log_display.setReadOnly(True)
        self.log_display.setFixedHeight(100)
        main_layout.addWidget(self.log_display)
        
        # Don't call apply_styles here, it's now in __init__
        self.connect_signals()

    def create_table(self, headers):
        table = QTableWidget(); table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setFont(QFont("Segoe UI", 8))
        return table

    def apply_styles(self):
        # ** FIX: These attributes are now created here before they are needed **
        self.base_button_style = """
            QPushButton { color: white; border-radius: 7px; padding: 8px 14px; font-size: 13px; font-weight: bold; border: 1px solid #00000044; }
            QPushButton:hover { border: 1px solid #FFFFFF77; }
            QPushButton:disabled { background-color: #343a40; color: #6c757d; border: 1px solid #000; }
        """
        self.blue_gradient = "background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0d6efd, stop:1 #0dcaf0);"
        self.green_gradient = "background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #198754, stop:1 #20c997);"
        self.orange_gradient = "background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #ffc107, stop:1 #fd7e14);"
        self.red_gradient = "background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #dc3545, stop:1 #fd1440);"
        self.active_monitor_style = "background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #fd7e14, stop:1 #ffc107); border: 1px solid #ffffffaa;"

        self.btn_detect_interfaces.setStyleSheet(self.base_button_style + self.blue_gradient)
        self.btn_toggle_monitor.setStyleSheet(self.base_button_style + self.green_gradient)
        self.btn_scan_networks.setStyleSheet(self.base_button_style + self.orange_gradient)
        self.btn_deauth_rogue.setStyleSheet(self.base_button_style + self.red_gradient)
        
        # ** FIX: Use complete, correct stylesheet strings **
        table_style = """
            QTableWidget { background-color: #212529; gridline-color: #343a40; color: #dee2e6; }
            QHeaderView::section { background-color: #343a40; color: #f8f9fa; padding: 3px; border: 1px solid #495057; font-size: 11px; font-weight: bold;}
        """
        self.network_table.setStyleSheet(table_style)
        self.rogue_table.setStyleSheet(table_style)
        self.log_display.setFont(QFont("Consolas", 8)); 
        self.log_display.setStyleSheet("background-color: #212529; color: #E5E9F0; border-radius: 5px; border: 1px solid #343a40;")
        self.interface_combo.setStyleSheet("background-color: #495057; padding: 4px; border-radius: 4px;")

    def connect_signals(self):
        self.btn_detect_interfaces.clicked.connect(self.populate_interfaces)
        self.btn_toggle_monitor.clicked.connect(self.toggle_monitor_mode)
        self.btn_scan_networks.clicked.connect(self.start_network_scan)
        self.btn_deauth_rogue.clicked.connect(lambda: self.log_message("Deauthentication is disabled.", "WARNING"))

    def post_init_setup(self):
        self.btn_deauth_rogue.setEnabled(False)
        if not self.is_linux:
            self.disable_all_controls()
            msg = "Unsupported OS. SniffGu@rd requires a Linux environment."
            self.log_message(msg, "CRITICAL"); log.critical(msg)
        else:
            self.log_message("Welcome to SniffGu@rd! Use 'Detect Interfaces' to begin.", "INFO")
            self.update_monitor_button_state() # Now safe to call

    def disable_all_controls(self):
        for btn in self.findChildren(QPushButton): btn.setEnabled(False)
        self.interface_combo.setEnabled(False)
    
    def update_monitor_button_state(self):
        if self.monitor_interface:
            self.btn_toggle_monitor.setText("Disable Monitor")
            self.btn_toggle_monitor.setStyleSheet(self.base_button_style + self.active_monitor_style)
            self.interface_combo.setEnabled(False)
        else:
            self.btn_toggle_monitor.setText("Enable Monitor")
            self.btn_toggle_monitor.setStyleSheet(self.base_button_style + self.green_gradient)
            self.interface_combo.setEnabled(True)

    def toggle_monitor_mode(self):
        if self.monitor_interface:
            self.log_message(f"Disabling monitor mode on {self.monitor_interface}...", "INFO")
            success = disable_monitor_mode(self.monitor_interface)
            if success:
                self.log_message(f"Monitor mode disabled. Connectivity restored.", "INFO")
                self.monitor_interface = None
            else:
                self.log_message(f"Failed to disable monitor mode on {self.monitor_interface}.", "ERROR")
        else:
            interface = self.interface_combo.currentText()
            if not interface:
                self.log_message("Cannot enable: No interface selected.", "ERROR"); return
            self.log_message(f"Attempting to set {interface} to monitor mode...", "INFO")
            success = enable_monitor_mode(interface)
            if success:
                self.log_message(f"Successfully enabled monitor mode on {interface}.", "INFO")
                self.monitor_interface = interface
            else:
                self.log_message(f"Failed to enable monitor mode. Run with sudo.", "ERROR")
        
        self.populate_interfaces()
        self.update_monitor_button_state()
        
    def start_network_scan(self):
        if not self.monitor_interface:
            self.log_message("Scan requires an interface in monitor mode.", "WARNING")
            return
        self.log_message(f"Starting network scan and analysis on {self.monitor_interface}...", "INFO")
        self.network_table.setRowCount(0); self.rogue_table.setRowCount(0)
        self.scan_thread = ScanThread(self.monitor_interface)
        self.scan_thread.analysis_complete.connect(self.populate_network_table)
        self.scan_thread.rogue_aps_found.connect(self.populate_rogue_table)
        self.scan_thread.error_occurred.connect(lambda msg: self.log_message(msg, "ERROR"))
        self.scan_thread.start()
    
    def log_message(self, message, level="INFO"):
        colors = {"INFO": "#0dcaf0", "WARNING": "#ffc107", "ERROR": "#dc3545", "CRITICAL": "#fd7e14"}
        self.log_display.append(f"<font color='{colors.get(level, 'white')}'><b>{level}:</b> {message}</font>")
        self.log_display.verticalScrollBar().setValue(self.log_display.verticalScrollBar().maximum())
        
    def populate_network_table(self, networks):
        self.log_message(f"Analysis complete. Found {len(networks)} networks.", "INFO")
        self.network_table.setRowCount(len(networks))
        threat_colors = {"Critical": QColor("#dc3545"), "High": QColor("#fd7e14"), "Medium": QColor("#ffc107")}
        for row, net in enumerate(sorted(networks, key=lambda x: x['Score'], reverse=True)):
            threat = net.get('Threat', 'Low')
            color = threat_colors.get(threat)
            items = [ str(net.get(k, 'N/A')) for k in ['BSSID', 'SSID', 'Signal', 'Channel', 'Vendor', 'Score', 'Threat'] ]
            for col, item in enumerate(items):
                table_item = QTableWidgetItem(item)
                table_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if color: table_item.setBackground(color); table_item.setForeground(QColor("#FFFFFF"))
                self.network_table.setItem(row, col, table_item)
                
    def populate_rogue_table(self, rogue_aps):
        self.log_message(f"THREAT DETECTED! Found {len(rogue_aps)} high-risk rogue APs.", "CRITICAL")
        self.rogue_table.setRowCount(len(rogue_aps))
        for row, net in enumerate(rogue_aps):
            items = [str(net.get(k, 'N/A')) for k in ['BSSID', 'SSID', 'Threat', 'Reasons']]
            for col, item in enumerate(items):
                table_item = QTableWidgetItem(item)
                table_item.setBackground(QColor("#721c24")); table_item.setForeground(QColor("#f8d7da"))
                self.rogue_table.setItem(row, col, table_item)

    def populate_interfaces(self):
        current = self.monitor_interface or self.interface_combo.currentText()
        self.interface_combo.clear()
        interfaces = get_interfaces()
        if interfaces:
            self.interface_combo.addItems(interfaces)
            if current in interfaces: self.interface_combo.setCurrentText(current)
            else: self.log_message(f"Interfaces updated: {', '.join(interfaces)}", "INFO")
        else:
            self.log_message("No interfaces found.", "ERROR")

def start_gui():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())