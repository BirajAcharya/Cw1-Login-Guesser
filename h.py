import unittest
import queue
import threading
from unittest.mock import patch, MagicMock
from loginscript import LoginWorker, try_login_once

class TestLoginScript(unittest.TestCase):
    def test_try_login_once_success_redirect(self):
        with patch('requests.Session') as mock_session:
            mock_session.return_value.get.return_value = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 302
            mock_response.headers = {'Location': 'index.php'}
            mock_session.return_value.post.return_value = mock_response
            result = try_login_once(
                "http://localhost/webapp/login.php",
                "admin",
                "password"
            )
            self.assertTrue(result)

    def test_try_login_once_success_cookie(self):
        with patch('requests.Session') as mock_session:
            mock_session.return_value.get.return_value = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_session.return_value.post.return_value = mock_response
            mock_session.return_value.cookies.get_dict.return_value = {'PHPSESSID': '12345'}
            result = try_login_once(
                "http://localhost/webapp/login.php",
                "admin",
                "password"
            )
            self.assertTrue(result)

    def test_try_login_once_failure(self):
        with patch('requests.Session') as mock_session:
            mock_session.return_value.get.return_value = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '<em>Invalid login</em>'
            mock_session.return_value.post.return_value = mock_response
            result = try_login_once(
                "http://localhost/webapp/login.php",
                "admin",
                "wrongpass"
            )
            self.assertFalse(result)

    def test_try_login_once_timeout(self):
        with patch('requests.Session') as mock_session:
            mock_session.return_value.get.side_effect = TimeoutError("Connection timed out")
            result = try_login_once(
                "http://localhost/webapp/login.php",
                "admin",
                "password"
            )
            self.assertFalse(result)

    def test_worker_queue_initialization(self):
        usernames = ["user1", "user2", "user3"]
        passwords = ["pass1", "pass2"]
        worker = LoginWorker(
            "http://localhost/webapp/login.php",
            usernames,
            passwords,
            3,
            3
        )
        self.assertEqual(worker.queue.qsize(), len(usernames) * len(passwords))
        expected_combinations = set()
        for user in usernames:
            for pwd in passwords:
                expected_combinations.add((user.strip(), pwd.strip()))
        actual_combinations = set()
        while not worker.queue.empty():
            actual_combinations.add(worker.queue.get_nowait())
        self.assertSetEqual(expected_combinations, actual_combinations)

    @patch('loginscript.LoginWorker.try_login')
    def test_worker_execution(self, mock_try_login):
        mock_try_login.return_value = False
        usernames = ["user1", "user2"]
        passwords = ["pass1", "pass2"]
        worker = LoginWorker(
            "http://localhost/webapp/login.php",
            usernames,
            passwords,
            2,
            3
        )
        worker.run()
        self.assertEqual(mock_try_login.call_count, len(usernames) * len(passwords))

    def test_worker_stop_mechanism(self):
        worker = LoginWorker(
            "http://localhost/webapp/login.php",
            ["user1", "user2", "user3"],
            ["pass1", "pass2"],
            3,
            3
        )
        worker.stop()
        worker.run()
        self.assertGreater(worker.queue.qsize(), 0)

    @patch('loginscript.LoginWorker.try_login')
    def test_worker_success_detection(self, mock_try_login):
        mock_try_login.side_effect = [True, False, False, False]
        usernames = ["user1", "user2"]
        passwords = ["pass1", "pass2"]
        worker = LoginWorker(
            "http://localhost/webapp/login.php",
            usernames,
            passwords,
            1,
            3
        )
        captured_signals = []
        def capture_signal(username, password, success):
            captured_signals.append((username, password, success))
        # Patch connect to call the callback directly in the worker
        original_emit = worker.update_signal.emit
        def direct_emit(username, password, success):
            capture_signal(username, password, success)
            original_emit(username, password, success)
        worker.update_signal.emit = direct_emit
        worker.run()
        self.assertTrue(any(success for _, _, success in captured_signals))
        self.assertEqual(len(captured_signals), len(usernames) * len(passwords))

    @patch('requests.Session')
    def test_login_redirect_flow(self, mock_session):
        mock_session.return_value.get.return_value = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {'Location': 'index.php'}
        mock_session.return_value.post.return_value = mock_response
        worker = LoginWorker("http://localhost/webapp/login.php", ["admin"], ["password"], 1, 3)
        result = worker.try_login(mock_session.return_value, "admin", "password")
        self.assertTrue(result)
        mock_session.return_value.post.assert_called_once()

    @patch('requests.Session')
    def test_login_cookie_flow(self, mock_session):
        mock_session.return_value.get.return_value = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.return_value.post.return_value = mock_response
        mock_session.return_value.cookies.get_dict.return_value = {'PHPSESSID': '12345'}
        worker = LoginWorker("http://localhost/webapp/login.php", ["admin"], ["password"], 1, 3)
        result = worker.try_login(mock_session.return_value, "admin", "password")
        self.assertTrue(result)
        mock_session.return_value.post.assert_called_once()

    def test_worker_thread_count(self):
        usernames = ["user1", "user2", "user3", "user4", "user5"]
        passwords = ["pass1", "pass2"]
        worker = LoginWorker(
            "http://localhost/webapp/login.php",
            usernames,
            passwords,
            3,
            3
        )
        threads = []
        for _ in range(worker.thread_count):
            thread = threading.Thread(target=worker.worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join(timeout=0.1)
        self.assertEqual(len(threads), worker.thread_count)

if __name__ == '__main__':
    unittest.main()