import sys
from PyQt6 import QtWidgets, QtGui, QtCore

from core.monitor_mode import enable_monitor_mode, disable_monitor_mode
from core.scan_networks import scan_networks
from core.analyzer import analyze_aps
from core.detect_rogue import detect_rogue_aps
from core.deauth_attack import send_deauth_packets

# ---- Thread classes ----
from PyQt6.QtCore import QThread, pyqtSignal


class ScanThread(QThread):
    ap_found = pyqtSignal(dict)
    finished_scanning = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, interface: str):
        super().__init__()
        self.interface = interface
        self._running = True

    def run(self):
        try:
            aps = scan_networks(self.interface, duration=10)
            if not self._running:
                return
            # Emit individual APs to update GUI table during scan if needed:
            for ap in aps:
                if not self._running:
                    break
                self.ap_found.emit(ap)
            self.finished_scanning.emit(aps)
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        self._running = False
        self.quit()
        self.wait()


class DeauthThread(QThread):
    status_update = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, target_bssids, interface):
        super().__init__()
        self.target_bssids = target_bssids  # List of BSSID strings
        self.interface = interface
        self._running = True

    def run(self):
        try:
            for bssid in self.target_bssids:
                if not self._running:
                    self.status_update.emit("Deauth attack stopped by user.")
                    break
                self.status_update.emit(f"Sending deauth packets to {bssid}...")
                send_deauth_packets(self.interface, bssid)
                self.status_update.emit(f"Deauth packets sent to {bssid}.")
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        self._running = False
        self.quit()
        self.wait()


class MonitorThread(QThread):
    status_update = pyqtSignal(str)
    finished = pyqtSignal(bool)
    error = pyqtSignal(str)

    def __init__(self, interface: str, enable: bool = True):
        super().__init__()
        self.interface = interface
        self.enable = enable

    def run(self):
        try:
            if self.enable:
                success, msg = enable_monitor_mode(self.interface)
            else:
                success, msg = disable_monitor_mode(self.interface)
            self.status_update.emit(msg)
            self.finished.emit(success)
        except Exception as e:
            self.error.emit(str(e))


# ---- GUI main window ----

class APTableWidget(QtWidgets.QTableWidget):
    def __init__(self, parent=None):
        super().__init__(0, 6, parent)
        self.setHorizontalHeaderLabels(
            ["BSSID", "SSID", "Signal", "Channel", "Vendor", "Threat"]
        )
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setShowGrid(False)
        self.setStyleSheet("QHeaderView::section {font-weight: bold; font-size: 13px;}")

    def insert_or_update(self, ap):
        bssid = ap.get("BSSID") or ap.get("bssid") or ""
        for row in range(self.rowCount()):
            if self.item(row, 0) and self.item(row, 0).text() == bssid:
                for col, key in enumerate(["BSSID", "SSID", "Signal", "Channel", "Vendor", "Threat"]):
                    existing_item = self.item(row, col)
                    val = ap.get(key) or ap.get(key.lower(), "")
                    if existing_item is None:
                        existing_item = QtWidgets.QTableWidgetItem(str(val))
                        existing_item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
                        self.setItem(row, col, existing_item)
                    else:
                        existing_item.setText(str(val))
                self._set_row_color(row, ap.get("Threat", ap.get("threat", "Normal")))
                return
        row = self.rowCount()
        self.insertRow(row)
        for col, key in enumerate(["BSSID", "SSID", "Signal", "Channel", "Vendor", "Threat"]):
            val = ap.get(key) or ap.get(key.lower(), "")
            item = QtWidgets.QTableWidgetItem(str(val))
            item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            self.setItem(row, col, item)
        self._set_row_color(row, ap.get("Threat", ap.get("threat", "Normal")))

    def clear_rows(self):
        self.setRowCount(0)

    def get_selected_bssid(self):
        selected = self.selectedItems()
        if selected:
            return selected[0].text()
        return None

    def _set_row_color(self, row, threat):
        theme_colors = {
            "Normal": QtGui.QColor("#38b6ff"),
            "Rogue": QtGui.QColor("#fcffa6"),
            "Confirmed Rogue": QtGui.QColor("#ff3864"),
        }
        color = theme_colors.get(threat, QtGui.QColor("#38b6ff"))
        # Set background with a light color depending on threat
        for col in range(self.columnCount()):
            item = self.item(row, col)
            if item:
                item.setBackground(color.lighter(130 if threat == "Normal" else 110))
                item.setForeground(QtGui.QColor("#fafaf6"))


class LogConsole(QtWidgets.QTextBrowser):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setMaximumHeight(160)
        self.setFontFamily('JetBrains Mono')
        self.setFontPointSize(13)
        self.setStyleSheet("""
        QTextBrowser {
            border-radius: 9px;
            border: 2px solid #b8c1ec;
            background:#313866;
            color: #fafaf6;
            padding: 8px;
            font-size: 13px;
            font-family: 'JetBrains Mono', 'Fira Mono', 'Consolas', monospace;
        }
        """)

    def log(self, message, level="INFO"):
        color = {
            "INFO": "#7fffd4",
            "WARN": "#ffe156",
            "ERROR": "#ff3864",
        }.get(level.upper(), "#7fffd4")
        self.append(f'<span style="color:{color};"><b>[{level.upper()}]</b> {message}</span>')

    def clear_log(self):
        self.clear()


class MainWindow(QtWidgets.QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SniffGu@rd – PyQt6 Evil Twin WIDS")
        self.resize(1040, 700)

        # State vars
        self.monitor_enabled = False
        self.scan_running = False
        self.deauth_running = False

        self.scan_thread = None
        self.deauth_thread = None
        self.monitor_thread = None

        self.setup_ui()
        self.bind_signals()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        controls = QtWidgets.QHBoxLayout()

        # Interface selector
        controls.addWidget(QtWidgets.QLabel("Wireless Interface:"))
        self.interface_combo = QtWidgets.QComboBox()
        self.interface_combo.addItems(["wlan0", "wlan1", "wlp2s0"])  # Replace with dynamic detection if needed
        controls.addWidget(self.interface_combo)

        # Buttons
        self.btn_monitor = QtWidgets.QPushButton("Enable Monitor Mode")
        controls.addWidget(self.btn_monitor)
        self.btn_scan = QtWidgets.QPushButton("Start Scan")
        controls.addWidget(self.btn_scan)
        self.btn_deauth = QtWidgets.QPushButton("Deauthenticate Rogue")
        controls.addWidget(self.btn_deauth)

        controls.addStretch(1)
        layout.addLayout(controls)

        # AP Table and Log Console
        self.table = APTableWidget()
        layout.addWidget(self.table)

        self.log_console = LogConsole()
        layout.addWidget(self.log_console)

    def bind_signals(self):
        self.btn_monitor.clicked.connect(self.toggle_monitor_mode)
        self.btn_scan.clicked.connect(self.toggle_scan)
        self.btn_deauth.clicked.connect(self.start_deauth)

    def get_selected_interface(self):
        return self.interface_combo.currentText()

    # --- Monitor Mode Methods ---

    def toggle_monitor_mode(self):
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.log_console.log("Monitor mode operation already in progress.", "WARN")
            return

        interface = self.get_selected_interface()
        if not self.monitor_enabled:
            self.log_console.log(f"Enabling monitor mode on {interface}...", "INFO")
            self.monitor_thread = MonitorThread(interface, enable=True)
            self.monitor_thread.status_update.connect(self.log_console.log)
            self.monitor_thread.finished.connect(self.on_monitor_enabled)
            self.monitor_thread.error.connect(lambda e: self.log_console.log(f"Monitor mode error: {e}", "ERROR"))
            self.btn_monitor.setEnabled(False)
            self.monitor_thread.start()
        else:
            self.log_console.log(f"Disabling monitor mode on {interface}...", "INFO")
            self.monitor_thread = MonitorThread(interface, enable=False)
            self.monitor_thread.status_update.connect(self.log_console.log)
            self.monitor_thread.finished.connect(self.on_monitor_disabled)
            self.monitor_thread.error.connect(lambda e: self.log_console.log(f"Monitor mode error: {e}", "ERROR"))
            self.btn_monitor.setEnabled(False)
            self.monitor_thread.start()

    def on_monitor_enabled(self, success):
        if success:
            self.monitor_enabled = True
            self.btn_monitor.setText("Disable Monitor Mode")
            self.log_console.log("Monitor mode enabled successfully.", "INFO")
        else:
            self.log_console.log("Failed to enable monitor mode.", "ERROR")
        self.btn_monitor.setEnabled(True)

    def on_monitor_disabled(self, success):
        if success:
            self.monitor_enabled = False
            self.btn_monitor.setText("Enable Monitor Mode")
            self.log_console.log("Monitor mode disabled successfully.", "WARN")
        else:
            self.log_console.log("Failed to disable monitor mode.", "ERROR")
        self.btn_monitor.setEnabled(True)

    # --- Scan Methods ---

    def toggle_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            # Stop scan
            self.log_console.log("Stopping scan...", "WARN")
            self.scan_thread.stop()
            self.scan_thread = None
            self.btn_scan.setEnabled(False)
        else:
            # Start scan
            interface = self.get_selected_interface()
            self.log_console.log(f"Starting scan on {interface}...", "INFO")
            self.table.clear_rows()
            self.scan_thread = ScanThread(interface)
            self.scan_thread.ap_found.connect(self.add_ap)
            self.scan_thread.finished_scanning.connect(self.scan_complete)
            self.scan_thread.error.connect(lambda e: self.log_console.log(f"Scan error: {e}", "ERROR"))
            self.btn_scan.setText("Stop Scan")
            self.btn_scan.setEnabled(True)
            self.interface_combo.setEnabled(False)
            self.scan_thread.start()

    def add_ap(self, ap):
        self.table.insert_or_update(ap)

    def scan_complete(self, aps):
        self.log_console.log(f"Scan complete: {len(aps)} networks found.", "INFO")
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("Start Scan")
        self.interface_combo.setEnabled(True)

        # Analyze APs after scan
        self.analyze_and_mark_rogues(aps)

    def analyze_and_mark_rogues(self, aps):
        suspicion_results = analyze_aps(aps)
        rogue_aps = detect_rogue_aps(suspicion_results)  # expected to return list of dict entries with 'BSSID'

        if rogue_aps:
            self.log_console.log(f"Found {len(rogue_aps)} rogue AP(s). Marking in table.", "WARN")
            # Mark rogue APs in table
            for rogue in rogue_aps:
                self.log_console.log(f"Rogue AP: {rogue.get('SSID', '')} - {rogue.get('BSSID', '')} Score: {rogue.get('score', 'N/A')}", "ERROR")
                self.table.insert_or_update({
                    "BSSID": rogue.get('BSSID'),
                    "SSID": rogue.get('SSID'),
                    "Signal": "",  # Add signal if you want
                    "Channel": "",
                    "Vendor": "",
                    "Threat": "Confirmed Rogue"
                })
        else:
            self.log_console.log("No rogue APs detected.", "INFO")

        self._last_rogue_bssids = [ap.get('BSSID') for ap in rogue_aps]

    # --- Deauth Methods ---

    def start_deauth(self):
        if self.deauth_running:
            self.log_console.log("Deauth attack already running.", "WARN")
            return
        target_bssid = self.table.get_selected_bssid()
        if not target_bssid:
            self.log_console.log("Select an AP row to deauth first.", "WARN")
            QtWidgets.QMessageBox.warning(self, "No AP Selected", "Please select an access point to deauthenticate.")
            return
        confirm = QtWidgets.QMessageBox.question(self, "Confirm Deauth",
                                                 f"Send deauthentication packets to {target_bssid}?",
                                                 QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No)
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            self.log_console.log("Deauth attack cancelled by user.", "INFO")
            return

        interface = self.get_selected_interface()
        self.deauth_thread = DeauthThread([target_bssid], interface)
        self.deauth_thread.status_update.connect(self.log_console.log)
        self.deauth_thread.finished.connect(self.on_deauth_finished)
        self.deauth_thread.error.connect(lambda e: self.log_console.log(f"Deauth error: {e}", "ERROR"))
        self.deauth_running = True
        self.btn_deauth.setEnabled(False)
        self.deauth_thread.start()
        self.log_console.log(f"Deauth attack started on {target_bssid}.", "ERROR")

    def on_deauth_finished(self):
        self.deauth_running = False
        self.btn_deauth.setEnabled(True)
        self.log_console.log("Deauth attack finished.", "WARN")

    def closeEvent(self, event):
        # Ensure threads are stopped properly on window close
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
        if self.deauth_thread and self.deauth_thread.isRunning():
            self.deauth_thread.stop()
        event.accept()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())
