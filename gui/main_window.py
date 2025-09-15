# sniffguard/gui/main_window.py

import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QComboBox, QTextEdit, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QProgressBar, QMessageBox, QCheckBox,
    QSpinBox, QGroupBox, QInputDialog
)
from PyQt6.QtGui import QFont, QColor, QMovie
from PyQt6.QtCore import Qt, QTimer

from utils.logger import log
from utils.config import APP_TITLE
from core.OS_detect import check_os
from core.interface_detect import get_interfaces
from core.monitor_mode import enable_monitor_mode, disable_monitor_mode
from threads.scan_thread import ScanThread
from threads.network_monitor_thread import NetworkMonitorThread
from core.deauth_attack import launch_deauth_attack, stop_deauth_attack, is_attack_running

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.is_linux = check_os()
        self.scan_thread = None
        self.monitor_thread = None
        self.monitor_interface = None
        
        # Progress and status tracking
        self.is_scanning = False
        self.is_monitoring = False
        
        self.init_ui()
        self.apply_styles() 
        self.post_init_setup()

    def init_ui(self):
        # This part is identical to your preferred version
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
        # Control Panel
        control_panel = QHBoxLayout(); control_panel.setSpacing(8)
        self.btn_detect_interfaces = QPushButton("Detect Interfaces")
        self.interface_combo = QComboBox()
        self.btn_toggle_monitor = QPushButton("Enable Monitor")
        self.btn_scan_networks = QPushButton("Start Scan")
        self.btn_continuous_monitor = QPushButton("Start Monitor")
        control_panel.addWidget(self.btn_detect_interfaces)
        control_panel.addWidget(QLabel("Interface:"))
        control_panel.addWidget(self.interface_combo, 1)
        control_panel.addSpacing(15)
        control_panel.addWidget(self.btn_toggle_monitor)
        control_panel.addWidget(self.btn_scan_networks)
        control_panel.addWidget(self.btn_continuous_monitor)
        main_layout.addLayout(control_panel)
        
        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFormat("Scanning... %p%")
        main_layout.addWidget(self.progress_bar)
        
        # Attack Panel
        attack_group = QGroupBox("Deauthentication Controls")
        attack_layout = QHBoxLayout(attack_group)
        self.btn_deauth_rogue = QPushButton("Deauth Selected")
        self.btn_stop_attack = QPushButton("Stop Attack")
        self.btn_stop_attack.setEnabled(False)
        attack_layout.addWidget(QLabel("Target:"))
        attack_layout.addWidget(self.btn_deauth_rogue)
        attack_layout.addWidget(self.btn_stop_attack)
        attack_layout.addStretch()
        main_layout.addWidget(attack_group)
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
        # Identical to previous working version
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
        table_style = """
            QTableWidget { background-color: #212529; gridline-color: #343a40; color: #dee2e6; }
            QHeaderView::section { background-color: #343a40; color: #f8f9fa; padding: 3px; border: 1px solid #495057; font-size: 11px; font-weight: bold;}
        """
        self.network_table.setStyleSheet(table_style); self.rogue_table.setStyleSheet(table_style)
        self.log_display.setFont(QFont("Consolas", 8)); 
        self.log_display.setStyleSheet("background-color: #212529; color: #E5E9F0; border-radius: 5px; border: 1px solid #343a40;")
        self.interface_combo.setStyleSheet("background-color: #495057; padding: 4px; border-radius: 4px;")

    def connect_signals(self):
        self.btn_detect_interfaces.clicked.connect(self.populate_interfaces)
        self.btn_toggle_monitor.clicked.connect(self.toggle_monitor_mode)
        self.btn_scan_networks.clicked.connect(self.start_network_scan)
        self.btn_continuous_monitor.clicked.connect(self.toggle_continuous_monitor)
        self.btn_deauth_rogue.clicked.connect(self.launch_deauth_attack)
        self.btn_stop_attack.clicked.connect(self.stop_deauth_attack)
        
        # Table selection for deauth targeting
        self.rogue_table.selectionModel().selectionChanged.connect(self.on_rogue_selection_changed)

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
        # This function logic is correct
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
            # The disable logic remains the same
            self.log_message(f"Disabling monitor mode on {self.monitor_interface}...", "INFO")
            success = disable_monitor_mode(self.monitor_interface)
            if success:
                self.log_message(f"Monitor mode disabled. Connectivity restored.", "INFO")
                self.monitor_interface = None
            else:
                self.log_message(f"Failed to disable monitor mode.", "ERROR")
            self.populate_interfaces()
            self.update_monitor_button_state()
            return

        # --- THIS IS THE NEW, SMARTER ENABLE LOGIC ---
        interface_to_set = self.interface_combo.currentText()
        if not interface_to_set:
            self.log_message("Cannot enable: No interface selected.", "ERROR"); return
        
        # 1. Get a snapshot of interfaces BEFORE the operation
        interfaces_before = set(get_interfaces())
        self.log_message(f"Attempting to set {interface_to_set} to monitor mode...", "INFO")
        
        success = enable_monitor_mode(interface_to_set)
        
        if success:
            # 2. Get a snapshot of interfaces AFTER the operation
            interfaces_after = set(get_interfaces())
            
            # 3. Find the NEW interface by comparing the sets
            new_mon_interfaces = interfaces_after - interfaces_before
            
            if new_mon_interfaces:
                # A new interface was created (e.g., wlan0mon)
                new_iface_name = new_mon_interfaces.pop()
                self.log_message(f"Success! Monitor mode active on new interface: {new_iface_name}", "INFO")
                self.monitor_interface = new_iface_name # ** CRITICAL FIX **
            else:
                # The interface name did not change
                self.log_message(f"Success! Monitor mode active on {interface_to_set}", "INFO")
                self.monitor_interface = interface_to_set # ** CRITICAL FIX **
        else:
            self.log_message(f"Failed to enable monitor mode on {interface_to_set}. Run with sudo.", "ERROR")
        
        self.populate_interfaces() # Refresh the dropdown with the new interface names
        self.update_monitor_button_state()
        
    def start_network_scan(self):
        if self.is_scanning:
            self.log_message("Scan already in progress.", "WARNING")
            return
            
        if not self.monitor_interface:
            self.show_error_dialog("Scan Failed", "Monitor mode is not active. Please enable monitor mode first.")
            return
            
        # Check for Scapy availability
        try:
            from core.scan_networks import SCAPY_AVAILABLE
            if not SCAPY_AVAILABLE:
                self.show_error_dialog(
                    "Scapy Required",
                    "Scapy is required for scanning. Please install it:\n\npip install scapy\n\nor\n\nsudo apt-get install python3-scapy"
                )
                return
        except ImportError:
            pass
            
        # Start scan with UI feedback
        self.is_scanning = True
        self._update_scan_ui(True)
        self.log_message(f"Initiating network scan on {self.monitor_interface}...", "INFO")
        self.network_table.setRowCount(0); self.rogue_table.setRowCount(0)
        
        self.scan_thread = ScanThread(self.monitor_interface)
        self.scan_thread.analysis_complete.connect(self.on_scan_complete)
        self.scan_thread.rogue_aps_found.connect(self.populate_rogue_table)
        self.scan_thread.error_occurred.connect(self.on_scan_error)
        self.scan_thread.finished.connect(self.on_scan_finished)
        self.scan_thread.start()
    
    def log_message(self, message, level="INFO"):
        # Correctly implemented, no change needed
        colors = {"INFO": "#0dcaf0", "WARNING": "#ffc107", "ERROR": "#dc3545", "CRITICAL": "#fd7e14"}
        self.log_display.append(f"<font color='{colors.get(level, 'white')}'><b>{level}:</b> {message}</font>")
        self.log_display.verticalScrollBar().setValue(self.log_display.verticalScrollBar().maximum())
        
    def populate_network_table(self, networks):
        # No change needed
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
        # No change needed
        self.log_message(f"THREAT DETECTED! Found {len(rogue_aps)} high-risk rogue APs.", "CRITICAL")
        self.rogue_table.setRowCount(len(rogue_aps))
        for row, net in enumerate(rogue_aps):
            items = [str(net.get(k, 'N/A')) for k in ['BSSID', 'SSID', 'Threat', 'Reasons']]
            for col, item in enumerate(items):
                table_item = QTableWidgetItem(item)
                table_item.setBackground(QColor("#721c24")); table_item.setForeground(QColor("#f8d7da"))
                self.rogue_table.setItem(row, col, table_item)

    def populate_interfaces(self):
        # ** FIX: This function is now smarter to auto-select the active monitor interface **
        current_active_interface = self.monitor_interface or self.interface_combo.currentText()
        self.interface_combo.clear()
        interfaces = get_interfaces()
        if interfaces:
            self.interface_combo.addItems(interfaces)
            if current_active_interface in interfaces:
                self.interface_combo.setCurrentText(current_active_interface)
            # Log only if there's no selection or if something changed.
            # Avoids spamming logs on every refresh.
            if self.interface_combo.currentText() != current_active_interface:
                self.log_message(f"Interfaces updated: {', '.join(interfaces)}", "INFO")
        else:
            self.log_message("No interfaces found.", "ERROR")
    
    def show_error_dialog(self, title, message):
        """Show error dialog to user."""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Icon.Critical)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.exec()
        
    def show_info_dialog(self, title, message):
        """Show info dialog to user."""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Icon.Information)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.exec()
        
    def _update_scan_ui(self, scanning):
        """Update UI elements during scanning."""
        if scanning:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            self.btn_scan_networks.setText("Scanning...")
            self.btn_scan_networks.setEnabled(False)
            self.btn_toggle_monitor.setEnabled(False)
        else:
            self.progress_bar.setVisible(False)
            self.btn_scan_networks.setText("Start Scan")
            self.btn_scan_networks.setEnabled(True)
            self.btn_toggle_monitor.setEnabled(True)
            
    def on_scan_complete(self, networks):
        """Handle scan completion with networks data."""
        self.populate_network_table(networks)
        
    def on_scan_error(self, error_msg):
        """Handle scan errors."""
        self.log_message(f"Scan error: {error_msg}", "ERROR")
        
    def on_scan_finished(self):
        """Handle scan thread completion."""
        self.is_scanning = False
        self._update_scan_ui(False)
        
    def toggle_continuous_monitor(self):
        """Toggle continuous network monitoring."""
        if not self.monitor_interface:
            self.show_error_dialog("Monitor Failed", "Monitor mode is not active. Please enable monitor mode first.")
            return
            
        if self.is_monitoring:
            # Stop monitoring
            self.stop_continuous_monitor()
        else:
            # Start monitoring
            self.start_continuous_monitor()
            
    def start_continuous_monitor(self):
        """Start continuous network monitoring."""
        try:
            from core.scan_networks import SCAPY_AVAILABLE
            if not SCAPY_AVAILABLE:
                self.show_error_dialog(
                    "Scapy Required",
                    "Scapy is required for monitoring. Please install it first."
                )
                return
        except ImportError:
            pass
            
        self.monitor_thread = NetworkMonitorThread(self.monitor_interface, scan_interval=30)
        self.monitor_thread.networks_updated.connect(self.populate_network_table)
        self.monitor_thread.new_rogue_detected.connect(self.on_new_rogue_detected)
        self.monitor_thread.monitoring_status.connect(lambda msg: self.log_message(msg, "INFO"))
        self.monitor_thread.error_occurred.connect(lambda msg: self.log_message(msg, "ERROR"))
        self.monitor_thread.start()
        
        self.is_monitoring = True
        self.btn_continuous_monitor.setText("Stop Monitor")
        self.log_message("Continuous monitoring started", "INFO")
        
    def stop_continuous_monitor(self):
        """Stop continuous network monitoring."""
        if self.monitor_thread:
            self.monitor_thread.stop()
            self.monitor_thread.wait(3000)  # Wait up to 3 seconds
            
        self.is_monitoring = False
        self.btn_continuous_monitor.setText("Start Monitor")
        self.log_message("Continuous monitoring stopped", "INFO")
        
    def on_new_rogue_detected(self, new_rogues):
        """Handle detection of new rogue APs."""
        for rogue in new_rogues:
            ssid = rogue.get('SSID', 'Unknown')
            threat = rogue.get('Threat', 'Unknown')
            self.log_message(f"NEW ROGUE DETECTED: {ssid} - {threat} threat!", "CRITICAL")
            
        # Update rogue table
        self.populate_rogue_table(new_rogues)
        
        # Show alert dialog
        msg = f"Detected {len(new_rogues)} new rogue AP(s)!\n\nCheck the Rogue APs table for details."
        self.show_info_dialog("Rogue AP Alert", msg)
        
    def on_rogue_selection_changed(self):
        """Handle selection change in rogue table."""
        selected_rows = self.rogue_table.selectionModel().selectedRows()
        self.btn_deauth_rogue.setEnabled(len(selected_rows) > 0)
        
    def launch_deauth_attack(self):
        """Launch deauth attack on selected rogue AP."""
        selected_rows = self.rogue_table.selectionModel().selectedRows()
        if not selected_rows:
            self.show_error_dialog("No Target", "Please select a rogue AP to target.")
            return
            
        if not self.monitor_interface:
            self.show_error_dialog("Attack Failed", "Monitor mode is not active.")
            return
            
        # Get target BSSID from selected row
        row = selected_rows[0].row()
        target_bssid = self.rogue_table.item(row, 0).text()  # BSSID column
        target_ssid = self.rogue_table.item(row, 1).text()   # SSID column
        
        # Confirmation dialog with safety warning
        reply = QMessageBox.question(
            self,
            "Confirm Deauth Attack",
            f"⚠️ SECURITY TESTING ONLY ⚠️\n\n"
            f"Target: {target_ssid} ({target_bssid})\n\n"
            f"This will send deauthentication packets to disconnect clients from the rogue AP.\n\n"
            f"⚠️ Only use this on networks you own or have explicit permission to test!\n\n"
            f"Continue with attack?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success, message = launch_deauth_attack(self.monitor_interface, target_bssid)
            if success:
                self.log_message(f"Deauth attack started on {target_ssid}", "WARNING")
                self.btn_stop_attack.setEnabled(True)
                self.btn_deauth_rogue.setEnabled(False)
            else:
                self.show_error_dialog("Attack Failed", message)
                
    def stop_deauth_attack(self):
        """Stop current deauth attack."""
        if self.monitor_interface:
            success = stop_deauth_attack(self.monitor_interface)
            if success:
                self.log_message("Deauth attack stopped", "INFO")
            self.btn_stop_attack.setEnabled(False)
            self.btn_deauth_rogue.setEnabled(True)

def start_gui():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
