import sys
import os
import unittest
from unittest.mock import patch, MagicMock, mock_open
import requests
from bs4 import BeautifulSoup

# Import PyQt6 components needed for GUI testing
from PyQt6.QtWidgets import QApplication, QMainWindow
from PyQt6.QtGui import QColor, QBrush

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Now import the tested classes
from loginscript import LoginGuesserGUI, LoginWorker


class TestLoginScript(unittest.TestCase):

    def setUp(self):
        # Initialize QApplication before creating GUI
        self.app = QApplication(sys.argv)
        self.gui = LoginGuesserGUI()

    def test_gui_initialization(self):
        """Test GUI initializes correctly"""
        self.assertEqual(self.gui.windowTitle(), "Login Guesser Tool")
        self.assertEqual(self.gui.url_input.text(), "http://localhost/webapp/login.php")
        self.assertIsNotNone(self.gui.results_table)

    def test_empty_url_validation(self):
        """Test URL input validation blocks empty URLs"""
        self.gui.url_input.setText("")
        self.gui.username_text.setText("admin")
        self.gui.password_text.setPlainText("password123")
        self.assertFalse(self.gui.start_attack())

    def test_empty_usernames_validation(self):
        """Test username list validation blocks empty input"""
        self.gui.url_input.setText("http://localhost/webapp/login.php")
        self.gui.username_text.setText("")
        self.gui.password_text.setPlainText("password123")
        self.assertFalse(self.gui.start_attack())

    def test_empty_passwords_validation(self):
        """Test password list validation blocks empty input"""
        self.gui.url_input.setText("http://localhost/webapp/login.php")
        self.gui.username_text.setText("admin")
        self.gui.password_text.setPlainText("")
        self.assertFalse(self.gui.start_attack())

    def test_thread_and_timeout_parsing(self):
        """Test thread count and timeout parsing"""
        self.gui.thread_input.setText("5")
        self.gui.timeout_input.setText("3")
        self.assertEqual(int(self.gui.thread_input.text()), 5)
        self.assertEqual(int(self.gui.timeout_input.text()), 3)

    @patch('loginscript.requests.Session.get')
    @patch('loginscript.requests.Session.post')
    def test_login_success(self, mock_post, mock_get):
        """Test successful login detection"""
        # Mock GET request
        mock_get.return_value.status_code = 200
        mock_get.return_value.cookies = {}

        # Mock POST response with redirect to index.php
        mock_post.return_value.status_code = 302
        mock_post.return_value.headers = {'Location': 'index.php'}

        session = requests.Session()
        result = self.gui.worker.try_login(session, "admin", "password")
        self.assertTrue(result)

    @patch('loginscript.requests.Session.get')
    @patch('loginscript.requests.Session.post')
    def test_login_failure_invalid_message(self, mock_post, mock_get):
        """Test invalid login detection via 'Invalid login' message"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.cookies = {}

        # Simulate HTML response with <em>Invalid login</em>
        mock_post.return_value.status_code = 200
        mock_post.return_value.text = "<em>Invalid login</em>"
        mock_post.return_value.cookies = {}

        session = requests.Session()
        result = self.gui.worker.try_login(session, "admin", "wrongpass")
        self.assertFalse(result)

    @patch('loginscript.requests.Session.get')
    @patch('loginscript.requests.Session.post')
    def test_login_success_with_session_cookie(self, mock_post, mock_get):
        """Test login success detected via PHPSESSID cookie"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.cookies = {}

        mock_post.return_value.status_code = 200
        mock_post.return_value.text = ""
        mock_post.return_value.cookies = {"PHPSESSID": "abc123"}

        session = requests.Session()
        result = self.gui.worker.try_login(session, "admin", "password")
        self.assertTrue(result)

    def test_progress_update(self):
        """Test progress bar updates correctly"""
        self.gui.progress_bar.setValue(0)
        self.gui.progress_bar.setMaximum(100)
        self.gui.update_progress(10)
        self.assertEqual(self.gui.progress_bar.value(), 10)

    def test_result_update_success(self):
        """Test success row added to table with green background"""
        self.gui.results_table.setRowCount(0)
        self.gui.update_result("admin", "password", True)
        status_item = self.gui.results_table.item(0, 2)
        self.assertEqual(status_item.text(), "Success")
        color = status_item.background().color().name()
        self.assertEqual(color, "#28a03c")  # Green for success

    def test_result_update_failure(self):
        """Test failure row added to table with red background"""
        self.gui.results_table.setRowCount(0)
        self.gui.update_result("invalid", "wrongpass", False)
        status_item = self.gui.results_table.item(0, 2)
        self.assertEqual(status_item.text(), "Failure")
        color = status_item.background().color().name()
        self.assertEqual(color, "#b43c3c")  # Red for failure

    def test_stop_attack_sets_ui_correctly(self):
        """Test stopping attack disables stop button and enables start"""
        self.gui.stop_attack()
        self.assertTrue(self.gui.start_btn.isEnabled())
        self.assertFalse(self.gui.stop_btn.isEnabled())

    def test_export_results_txt(self):
        """Test exporting results to .txt file"""
        self.gui.results_table.setRowCount(1)
        self.gui.results_table.setItem(0, 0, QTableWidgetItem("admin"))
        self.gui.results_table.setItem(0, 1, QTableWidgetItem("password"))
        self.gui.results_table.setItem(0, 2, QTableWidgetItem("Success"))

        with patch.object(QFileDialog, 'getSaveFileName', return_value=("test_results.txt", "")):
            with patch("builtins.open", mock_open()) as mock_file:
                self.gui.export_results()
                mock_file.assert_called_once_with("test_results.txt", 'w')
                handle = mock_file()
                handle.write.assert_any_call("admin:password - Success\n")

    def test_export_results_csv(self):
        """Test exporting results to .csv file"""
        self.gui.results_table.setRowCount(1)
        self.gui.results_table.setItem(0, 0, QTableWidgetItem("admin"))
        self.gui.results_table.setItem(0, 1, QTableWidgetItem("password"))
        self.gui.results_table.setItem(0, 2, QTableWidgetItem("Success"))

        with patch.object(QFileDialog, 'getSaveFileName', return_value=("test_results.csv", "")):
            with patch("builtins.open", mock_open()) as mock_file:
                self.gui.export_results()
                mock_file.assert_called_once_with("test_results.csv", 'w')
                handle = mock_file()
                handle.write.assert_any_call('"Username","Password","Status"\\n')
                handle.write.assert_any_call('"admin","password","Success"\\n')


if __name__ == '__main__':
    unittest.main()