import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QFileDialog, QProgressBar, QTabWidget, QMessageBox,
                            QGroupBox, QFormLayout, QComboBox, QRadioButton,
                            QButtonGroup, QFrame, QSizePolicy, QGridLayout,
                            QStyle, QAction, QMenu, QToolBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QMimeData, QUrl
from PyQt5.QtGui import QIcon, QDrag, QDragEnterEvent, QDropEvent, QFont

from encryption_utils import EncryptionUtils

class EncryptionThread(QThread):
    """Thread for performing encryption/decryption operations in the background."""
    progress_update = pyqtSignal(int)
    operation_complete = pyqtSignal(bool, str)
    
    def __init__(self, operation, input_file, output_file, password):
        super().__init__()
        self.operation = operation  # 'encrypt' or 'decrypt'
        self.input_file = input_file
        self.output_file = output_file
        self.password = password
    
    def run(self):
        try:
            if self.operation == 'encrypt':
                success = EncryptionUtils.encrypt_file(
                    self.input_file, 
                    self.output_file, 
                    self.password, 
                    self.update_progress
                )
            else:  # decrypt
                success = EncryptionUtils.decrypt_file(
                    self.input_file, 
                    self.output_file, 
                    self.password, 
                    self.update_progress
                )
            
            if success:
                self.operation_complete.emit(True, f"File {self.operation}ed successfully.")
            else:
                self.operation_complete.emit(False, f"Failed to {self.operation} file.")
        except Exception as e:
            self.operation_complete.emit(False, f"Error: {str(e)}")
    
    def update_progress(self, value):
        self.progress_update.emit(value)


class FileDropArea(QLabel):
    """Custom widget for drag and drop file selection."""
    file_dropped = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setText("Drop file here\nor click to browse")
        self.setStyleSheet("""
            QLabel {
                border: 2px dashed #aaa;
                border-radius: 8px;
                padding: 30px;
                background-color: #f8f8f8;
                font-size: 16px;
            }
            QLabel:hover {
                border-color: #6c8ebf;
                background-color: #e6f0ff;
            }
        """)
        self.setAcceptDrops(True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMinimumHeight(120)
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            url = event.mimeData().urls()[0]
            file_path = url.toLocalFile()
            self.file_dropped.emit(file_path)
    
    def mousePressEvent(self, event):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_dropped.emit(file_path)


class EncryptionApp(QMainWindow):
    """Main application window for the encryption tool."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Encryption Tool")
        self.setMinimumSize(600, 500)
        
        # Create the central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Add tabs for different operations
        self.tabs = QTabWidget()
        self.encrypt_tab = QWidget()
        self.decrypt_tab = QWidget()
        
        self.tabs.addTab(self.encrypt_tab, "Encrypt")
        self.tabs.addTab(self.decrypt_tab, "Decrypt")
        
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        
        self.main_layout.addWidget(self.tabs)
        
        # Add information about the encryption
        self.info_group = QGroupBox("About")
        info_layout = QVBoxLayout()
        
        info_text = QLabel(
            "This tool uses AES-256 encryption in CBC mode to securely encrypt your files. "
            "The encryption is password-based, and the password is never stored. "
            "Please remember your password as it cannot be recovered if lost."
        )
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text)
        
        self.info_group.setLayout(info_layout)
        self.main_layout.addWidget(self.info_group)
        
        # Setup status bar
        self.statusBar().showMessage("Ready")
        
        # Initialize other attributes
        self.encrypt_thread = None
        self.decrypt_thread = None
        
        self.setup_style()
    
    def setup_style(self):
        """Apply stylesheets and styling to the application."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #ddd;
                border-radius: 6px;
                margin-top: 1ex;
                padding: 10px;
                background-color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #4a86e8;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3a76d8;
            }
            QPushButton:pressed {
                background-color: #2a66c8;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 4px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #4a86e8;
                width: 10px;
                margin: 0.5px;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                border-radius: 6px;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                border: 1px solid #ddd;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 1px solid white;
            }
            QTabBar::tab:hover {
                background-color: #f0f0f0;
            }
        """)
    
    def setup_encrypt_tab(self):
        """Set up the encryption tab UI."""
        layout = QVBoxLayout(self.encrypt_tab)
        
        # File selection area
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()
        
        self.encrypt_drop_area = FileDropArea()
        self.encrypt_drop_area.file_dropped.connect(self.set_encrypt_file)
        file_layout.addWidget(self.encrypt_drop_area)
        
        file_selection = QHBoxLayout()
        self.encrypt_file_path = QLineEdit()
        self.encrypt_file_path.setPlaceholderText("Select a file to encrypt...")
        self.encrypt_file_path.setReadOnly(True)
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_encrypt_file)
        
        file_selection.addWidget(self.encrypt_file_path)
        file_selection.addWidget(browse_button)
        file_layout.addLayout(file_selection)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Password input
        password_group = QGroupBox("Encryption Password")
        password_layout = QFormLayout()
        
        self.encrypt_password = QLineEdit()
        self.encrypt_password.setEchoMode(QLineEdit.Password)
        self.encrypt_password.setPlaceholderText("Enter a strong password...")
        
        self.encrypt_confirm_password = QLineEdit()
        self.encrypt_confirm_password.setEchoMode(QLineEdit.Password)
        self.encrypt_confirm_password.setPlaceholderText("Confirm your password...")
        
        password_layout.addRow("Password:", self.encrypt_password)
        password_layout.addRow("Confirm:", self.encrypt_confirm_password)
        
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Action buttons
        actions_layout = QHBoxLayout()
        
        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.clicked.connect(self.start_encryption)
        
        self.encrypt_cancel_button = QPushButton("Cancel")
        self.encrypt_cancel_button.clicked.connect(self.cancel_encryption)
        self.encrypt_cancel_button.setEnabled(False)
        
        actions_layout.addWidget(self.encrypt_button)
        actions_layout.addWidget(self.encrypt_cancel_button)
        layout.addLayout(actions_layout)
        
        # Progress bar
        self.encrypt_progress = QProgressBar()
        self.encrypt_progress.setValue(0)
        layout.addWidget(self.encrypt_progress)
        
        # Status
        self.encrypt_status = QLabel("")
        layout.addWidget(self.encrypt_status)
        
        layout.addStretch()
    
    def setup_decrypt_tab(self):
        """Set up the decryption tab UI."""
        layout = QVBoxLayout(self.decrypt_tab)
        
        # File selection area
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()
        
        self.decrypt_drop_area = FileDropArea()
        self.decrypt_drop_area.file_dropped.connect(self.set_decrypt_file)
        file_layout.addWidget(self.decrypt_drop_area)
        
        file_selection = QHBoxLayout()
        self.decrypt_file_path = QLineEdit()
        self.decrypt_file_path.setPlaceholderText("Select a file to decrypt...")
        self.decrypt_file_path.setReadOnly(True)
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_decrypt_file)
        
        file_selection.addWidget(self.decrypt_file_path)
        file_selection.addWidget(browse_button)
        file_layout.addLayout(file_selection)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Password input
        password_group = QGroupBox("Decryption Password")
        password_layout = QFormLayout()
        
        self.decrypt_password = QLineEdit()
        self.decrypt_password.setEchoMode(QLineEdit.Password)
        self.decrypt_password.setPlaceholderText("Enter the password used for encryption...")
        
        password_layout.addRow("Password:", self.decrypt_password)
        
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Action buttons
        actions_layout = QHBoxLayout()
        
        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.clicked.connect(self.start_decryption)
        
        self.decrypt_cancel_button = QPushButton("Cancel")
        self.decrypt_cancel_button.clicked.connect(self.cancel_decryption)
        self.decrypt_cancel_button.setEnabled(False)
        
        actions_layout.addWidget(self.decrypt_button)
        actions_layout.addWidget(self.decrypt_cancel_button)
        layout.addLayout(actions_layout)
        
        # Progress bar
        self.decrypt_progress = QProgressBar()
        self.decrypt_progress.setValue(0)
        layout.addWidget(self.decrypt_progress)
        
        # Status
        self.decrypt_status = QLabel("")
        layout.addWidget(self.decrypt_status)
        
        layout.addStretch()
    
    def browse_encrypt_file(self):
        """Open file dialog to select a file for encryption."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            self.set_encrypt_file(file_path)
    
    def set_encrypt_file(self, file_path):
        """Set the selected file for encryption."""
        self.encrypt_file_path.setText(file_path)
        self.encrypt_status.setText(f"Selected: {os.path.basename(file_path)}")
    
    def browse_decrypt_file(self):
        """Open file dialog to select a file for decryption."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if file_path:
            self.set_decrypt_file(file_path)
    
    def set_decrypt_file(self, file_path):
        """Set the selected file for decryption."""
        self.decrypt_file_path.setText(file_path)
        self.decrypt_status.setText(f"Selected: {os.path.basename(file_path)}")
    
    def start_encryption(self):
        """Validate inputs and start the encryption process."""
        input_file = self.encrypt_file_path.text()
        if not input_file:
            QMessageBox.warning(self, "Missing File", "Please select a file to encrypt.")
            return
        
        password = self.encrypt_password.text()
        confirm_password = self.encrypt_confirm_password.text()
        
        if not password:
            QMessageBox.warning(self, "Missing Password", "Please enter a password.")
            return
        
        if password != confirm_password:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return
        
        # Get output file location
        default_output = input_file + ".encrypted"
        output_file, _ = QFileDialog.getSaveFileName(
            self, "Save Encrypted File", default_output, "Encrypted Files (*.encrypted);;All Files (*)"
        )
        
        if not output_file:
            return  # User cancelled
        
        # Start encryption in a separate thread
        self.encrypt_button.setEnabled(False)
        self.encrypt_cancel_button.setEnabled(True)
        self.encrypt_progress.setValue(0)
        self.encrypt_status.setText("Encrypting...")
        
        self.encrypt_thread = EncryptionThread('encrypt', input_file, output_file, password)
        self.encrypt_thread.progress_update.connect(self.update_encrypt_progress)
        self.encrypt_thread.operation_complete.connect(self.encryption_complete)
        self.encrypt_thread.start()
    
    def update_encrypt_progress(self, value):
        """Update the encryption progress bar."""
        self.encrypt_progress.setValue(value)
    
    def encryption_complete(self, success, message):
        """Handle encryption completion."""
        self.encrypt_button.setEnabled(True)
        self.encrypt_cancel_button.setEnabled(False)
        
        if success:
            self.encrypt_status.setText(message)
            QMessageBox.information(self, "Encryption Complete", message)
        else:
            self.encrypt_status.setText("Failed: " + message)
            QMessageBox.critical(self, "Encryption Failed", message)
    
    def start_decryption(self):
        """Validate inputs and start the decryption process."""
        input_file = self.decrypt_file_path.text()
        if not input_file:
            QMessageBox.warning(self, "Missing File", "Please select a file to decrypt.")
            return
        
        password = self.decrypt_password.text()
        if not password:
            QMessageBox.warning(self, "Missing Password", "Please enter the decryption password.")
            return
        
        # Get output file location
        suggested_name = os.path.splitext(input_file)[0]
        if suggested_name.endswith('.encrypted'):
            suggested_name = os.path.splitext(suggested_name)[0]
        
        output_file, _ = QFileDialog.getSaveFileName(
            self, "Save Decrypted File", suggested_name, "All Files (*)"
        )
        
        if not output_file:
            return  # User cancelled
        
        # Start decryption in a separate thread
        self.decrypt_button.setEnabled(False)
        self.decrypt_cancel_button.setEnabled(True)
        self.decrypt_progress.setValue(0)
        self.decrypt_status.setText("Decrypting...")
        
        self.decrypt_thread = EncryptionThread('decrypt', input_file, output_file, password)
        self.decrypt_thread.progress_update.connect(self.update_decrypt_progress)
        self.decrypt_thread.operation_complete.connect(self.decryption_complete)
        self.decrypt_thread.start()
    
    def update_decrypt_progress(self, value):
        """Update the decryption progress bar."""
        self.decrypt_progress.setValue(value)
    
    def decryption_complete(self, success, message):
        """Handle decryption completion."""
        self.decrypt_button.setEnabled(True)
        self.decrypt_cancel_button.setEnabled(False)
        
        if success:
            self.decrypt_status.setText(message)
            QMessageBox.information(self, "Decryption Complete", message)
        else:
            self.decrypt_status.setText("Failed: " + message)
            QMessageBox.critical(self, "Decryption Failed", message)
    
    def cancel_encryption(self):
        """Cancel the ongoing encryption process."""
        if self.encrypt_thread and self.encrypt_thread.isRunning():
            self.encrypt_thread.terminate()
            self.encrypt_status.setText("Encryption cancelled.")
            self.encrypt_button.setEnabled(True)
            self.encrypt_cancel_button.setEnabled(False)
    
    def cancel_decryption(self):
        """Cancel the ongoing decryption process."""
        if self.decrypt_thread and self.decrypt_thread.isRunning():
            self.decrypt_thread.terminate()
            self.decrypt_status.setText("Decryption cancelled.")
            self.decrypt_button.setEnabled(True)
            self.decrypt_cancel_button.setEnabled(False)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptionApp()
    window.show()
    sys.exit(app.exec_()) 