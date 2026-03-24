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

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.is_linux = check_os()
        self.monitor_interface = None
        self.realtime_monitor = None
        self.is_scanning = False
        
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
        self.network_table = self.create_table(["BSSID", "SSID", "Signal", "Channel", "Band", "Vendor", "Score", "Threat"])
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
        self.purple_gradient = "background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #6f42c1, stop:1 #a855f7);"
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
        self.btn_scan_networks.clicked.connect(self.toggle_network_scan)
        self.btn_deauth_rogue.clicked.connect(self.launch_deauth_attack)

    def post_init_setup(self):
        # Enable deauth button only when conditions are met
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
        
    def toggle_network_scan(self):
        """Toggle between start scan and stop scan with real-time monitoring"""
        if not self.is_scanning:
            self.start_continuous_scan()
        else:
            self.stop_continuous_scan()
    
    def start_continuous_scan(self):
        """Start continuous scanning with real-time monitoring"""
        # Check interface requirements
        interface = self.interface_combo.currentText()
        if not interface:
            self.log_message("Scan FAILED: No interface selected.", "ERROR")
            return
            
        # Clear previous results
        self.network_table.setRowCount(0)
        self.rogue_table.setRowCount(0)
        
        try:
            from core.realtime_monitor import RealTimeMonitor
            
            self.realtime_monitor = RealTimeMonitor(interface)
            
            # Connect signals for real-time updates
            self.realtime_monitor.new_threat_detected.connect(self.on_new_threat_detected)
            self.realtime_monitor.threat_level_changed.connect(self.on_threat_level_changed)
            self.realtime_monitor.monitoring_stats_updated.connect(self.on_monitoring_stats_updated)
            self.realtime_monitor.networks_updated.connect(self.on_networks_updated)
            
            # Configure monitoring for frequent updates
            self.realtime_monitor.set_scan_interval(10)  # Scan every 10 seconds
            self.realtime_monitor.set_threat_threshold(80)  # Alert on high-risk threats only
            
            # Start monitoring
            if self.realtime_monitor.start_monitoring():
                self.is_scanning = True
                self.btn_scan_networks.setText("Stop Scan")
                self.btn_scan_networks.setStyleSheet(self.base_button_style + "background-color: #dc3545;")  # Red stop button
                
                self.log_message(f"🔍 Started continuous scanning on {interface}", "INFO")
                self.log_message("📊 Real-time network monitoring active - networks will update every 8 seconds", "INFO")
                self.log_message("🛑 Click 'Stop Scan' to end monitoring", "INFO")
            else:
                self.log_message("Failed to start continuous scanning", "ERROR")
                
        except ImportError:
            self.log_message("Real-time monitoring module not available", "ERROR")
        except Exception as e:
            self.log_message(f"Error starting continuous scan: {e}", "ERROR")
    
    def stop_continuous_scan(self):
        """Stop continuous scanning and real-time monitoring"""
        if self.realtime_monitor:
            self.realtime_monitor.stop_monitoring()
            self.realtime_monitor = None
        
        self.is_scanning = False
        self.btn_scan_networks.setText("Start Scan")
        self.btn_scan_networks.setStyleSheet(self.base_button_style + self.orange_gradient)
        
        self.log_message("🛑 Continuous scanning stopped", "INFO")
    
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
            items = [ str(net.get(k, 'N/A')) for k in ['BSSID', 'SSID', 'Signal', 'Channel', 'Band', 'Vendor', 'Score', 'Threat'] ]
            for col, item in enumerate(items):
                table_item = QTableWidgetItem(item)
                table_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if color: table_item.setBackground(color); table_item.setForeground(QColor("#FFFFFF"))
                self.network_table.setItem(row, col, table_item)
                
    def populate_rogue_table(self, rogue_aps):
        # Enable deauth button when rogue APs are found
        if rogue_aps and self.monitor_interface:
            self.btn_deauth_rogue.setEnabled(True)
            self.log_message(f"THREAT DETECTED! Found {len(rogue_aps)} high-risk rogue APs. Deauth enabled.", "CRITICAL")
        else:
            self.btn_deauth_rogue.setEnabled(False)
            if rogue_aps:
                self.log_message(f"Found {len(rogue_aps)} rogue APs, but monitor mode required for deauth.", "WARNING")
        
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
    
    def launch_deauth_attack(self):
        """Launch deauthentication attack against selected rogue APs"""
        if not self.monitor_interface:
            self.log_message("Deauth FAILED: Monitor mode is not active.", "ERROR")
            return
        
        # Get selected row from rogue table
        selected_items = self.rogue_table.selectedItems()
        if not selected_items:
            self.log_message("Please select a rogue AP from the table to target.", "WARNING")
            return
        
        # Get BSSID from selected row (first column)
        selected_row = selected_items[0].row()
        target_bssid = self.rogue_table.item(selected_row, 0).text()  # BSSID column
        target_ssid = self.rogue_table.item(selected_row, 1).text()   # SSID column
        
        if target_bssid == 'N/A':
            self.log_message("Invalid target BSSID selected.", "ERROR")
            return
        
        # Confirm attack
        from PyQt6.QtWidgets import QMessageBox
        reply = QMessageBox.question(
            self, 'Confirm Deauth Attack', 
            f'Launch deauthentication attack against:\n'
            f'SSID: {target_ssid}\n'
            f'BSSID: {target_bssid}\n\n'
            f'This will disconnect clients from the target AP.\n'
            f'Continue?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.log_message(f"Launching deauth attack against {target_ssid} ({target_bssid})", "INFO")
            
            # Import and launch attack in a separate thread
            from threads.deauth_thread import DeauthThread
            self.deauth_thread = DeauthThread(self.monitor_interface, target_bssid)
            self.deauth_thread.attack_complete.connect(self.on_deauth_complete)
            self.deauth_thread.attack_progress.connect(self.on_deauth_progress)
            self.deauth_thread.start()
            
            # Disable button during attack
            self.btn_deauth_rogue.setEnabled(False)
            self.btn_deauth_rogue.setText("Attacking...")
    
    def on_deauth_complete(self, success, message, stats):
        """Handle completion of deauth attack"""
        if success:
            self.log_message(f"Deauth attack completed: {message}", "INFO")
        else:
            self.log_message(f"Deauth attack failed: {message}", "ERROR")
        
        # Re-enable button
        self.btn_deauth_rogue.setEnabled(True)
        self.btn_deauth_rogue.setText("Deauth Rogue")
        
        # Log statistics
        if stats:
            self.log_message(f"Attack stats: {stats.get('packets_sent', 0)} packets sent", "INFO")
    
    def on_deauth_progress(self, message):
        """Handle progress updates from deauth attack"""
        self.log_message(message, "INFO")
    
    def on_scan_finished(self):
        """Handle scan thread completion"""
        # Reset scan button
        self.btn_scan_networks.setText("Start Scan")
        self.btn_scan_networks.setEnabled(True)
    
    
    def on_new_threat_detected(self, threat_data):
        """Handle new threat detection from real-time monitor"""
        ssid = threat_data.get('ssid', 'Unknown')
        threat_level = threat_data.get('threat_level', 'Unknown')
        threat_score = threat_data.get('threat_score', 0)
        
        self.log_message(f"⚠️ NEW THREAT: {ssid} - Level: {threat_level} (Score: {threat_score})", "CRITICAL")
        
        # Trigger a scan update to show the new threat in tables
        self.refresh_network_tables()
    
    def on_threat_level_changed(self, bssid, old_level, new_level):
        """Handle threat level changes"""
        self.log_message(f"🔄 Threat level changed for {bssid}: {old_level} → {new_level}", "WARNING")
        self.refresh_network_tables()
    
    def on_monitoring_stats_updated(self, stats):
        """Handle monitoring statistics updates"""
        scan_count = stats.get('scan_count', 0)
        networks_seen = stats.get('networks_seen', 0)
        current_threats = stats.get('current_threats', 0)
        
        # Update status in log every 10 scans to avoid spam
        if scan_count % 10 == 0:
            self.log_message(f"📊 Monitor Stats: {networks_seen} networks, {current_threats} active threats (Scan #{scan_count})", "INFO")
    
    def on_networks_updated(self, networks):
        """Handle real-time network updates with live signal strength"""
        if not networks:
            return
            
        # Update the main network table with live data
        self.log_message(f"📶 Live update: {len(networks)} networks detected with current signal strengths", "INFO")
        
        # Convert realtime monitor data to display format
        display_networks = []
        for network in networks:
            display_net = {
                'BSSID': network.get('BSSID', 'N/A'),
                'SSID': network.get('SSID', '<Hidden>'),
                'Signal': network.get('Signal', 'N/A'),
                'Channel': network.get('Channel', 'N/A'),
                'Band': network.get('Band', 'N/A'),
                'Vendor': network.get('Vendor', 'Unknown'),
                'Score': network.get('Advanced_Threat_Score', 0),
                'Threat': network.get('Advanced_Threat_Level', 'Low')
            }
            display_networks.append(display_net)
        
        # Update tables
        self.populate_network_table(display_networks)
        
        # Update rogue table with current high-risk networks
        high_risk_nets = [net for net in networks if net.get('Advanced_Threat_Score', 0) >= 50]
        if high_risk_nets:
            rogue_display = []
            for net in high_risk_nets:
                rogue_net = {
                    'BSSID': net.get('BSSID', 'N/A'),
                    'SSID': net.get('SSID', '<Hidden>'),
                    'Threat': net.get('Advanced_Threat_Level', 'Unknown'),
                    'Reasons': net.get('Advanced_Reasons', 'N/A')
                }
                rogue_display.append(rogue_net)
            self.populate_rogue_table(rogue_display)
    
    def refresh_network_tables(self):
        """Refresh network tables with current real-time data"""
        if self.realtime_monitor:
            try:
                # Get current network data
                current_threats = self.realtime_monitor.get_current_threats()
                
                if current_threats:
                    # Update rogue table with current threats
                    self.populate_rogue_table(current_threats)
                    
                    # Also update main network table if we have the monitor's network data
                    # This would require extending the RealTimeMonitor to provide all network data
                    
            except Exception as e:
                self.log_message(f"Error refreshing tables: {e}", "ERROR")
        
    def on_scan_error(self, error_message):
        """Handle scan errors with helpful suggestions"""
        self.log_message(f"Scan Error: {error_message}", "ERROR")
        
        # Provide helpful suggestions based on error type
        if "Scapy" in error_message or "import" in error_message.lower():
            self.log_message("💡 Solution: Install Scapy with: pip3 install scapy", "INFO")
        elif "Permission" in error_message or "permission" in error_message.lower():
            self.log_message("💡 Solution: Run with sudo privileges", "INFO")
        elif "Interface" in error_message or "interface" in error_message.lower():
            self.log_message("💡 Solution: Check if interface is in monitor mode", "INFO")
        elif "timeout" in error_message.lower():
            self.log_message("💡 Try scanning again - network conditions may have changed", "INFO")
        else:
            self.log_message("💡 Check logs for detailed error information", "INFO")
            
        # Reset scan button
        self.btn_scan_networks.setText("Start Scan")
        self.btn_scan_networks.setEnabled(True)

def start_gui():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
