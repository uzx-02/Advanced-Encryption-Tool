# **Advanced Encryption Tool**

**Company:** CODTECH IT SOLUTIONS  

**Name:** Uzair Shaikh  

**Intern ID:** CT12OUP  

**Domain:** Cyber Security & Ethical Hacking  

**Duration:** 8 Weeks  

**Mentor:** Neela Santosh

### **Task Description:**

In this task, I developed a Python-based tool for secure file encryption and decryption using AES-256, a widely recognized and robust encryption standard. The primary goal was to create an application that enables users to effortlessly encrypt and decrypt files through a graphical user interface (GUI) built with PyQt5. The deliverable is a comprehensive Python script featuring intuitive drag and drop file selection, real-time progress indication via a progress bar, and secure password-based key derivation using PBKDF2, ensuring both ease of use and high security for a wide range of users.

### **Tools Used:**

- **Programming Language:** Python
- **Libraries/Modules:**  
  - `PyQt5`: For designing the user-friendly graphical interface and managing user interactions, leveraging widgets like QFileDialog for file selection and QThread for non-blocking background tasks.  
  - `EncryptionUtils`: Custom module that handles the core encryption and decryption functions using AES-256 in CBC mode with PKCS7 padding, ensuring secure file processing.  
  - `os` and `sys`: For efficient file path handling and system-level operations.  
  - `QThread`: From PyQt5, for performing encryption/decryption tasks in the background without freezing the UI, enhancing responsiveness.
  - `QFileDialog`: For intuitive file browsing and selection dialogs, improving user experience.
  - `QProgressBar`: Displays progress updates during encryption and decryption.
  - `QMessageBox`: Provides user feedback with alerts and messages.
  
- **IDE:** `Visual Studio Code` used for writing, testing, and debugging the script, providing a robust development environment.


### **Task Implementation:**

The Advanced Encryption Tool is structured around two primary components: **Encryption** and **Decryption**.

1. **Encryption:**  
   - **File Selection:** Users can select a file to encrypt either by browsing with QFileDialog or using a custom drag and drop widget, offering visual feedback for a seamless experience.
   - **Password Input:** The tool requires a password and its confirmation via a secure input dialog, ensuring accuracy and preventing encryption errors.
   - **Encryption Process:** Utilizes AES-256 encryption in CBC mode with PKCS7 padding. A random initialization vector (IV) is generated for each session to bolster security and prevent pattern-based attacks.
   - **Threaded Execution:** The encryption is performed on a separate thread using QThread to maintain GUI responsiveness, with progress updates relayed via a dynamic progress bar.
   - **User Feedback:** Real-time status messages (e.g., “Encrypting…”) inform the user about the progress and completion of the encryption process, with a success notification upon finishing.

2. **Decryption:**  
   - **File Selection:** Users select the encrypted file using the same intuitive browsing or drag and drop interface, ensuring consistency across operations.
   - **Password Verification:** The user enters the decryption password, which is validated against the file’s embedded key to unlock the original content..
   - **Decryption Process:** The decryption operation is handled in a separate thread with real-time progress updates and status notifications, mirroring the encryption workflow.
   - **Output Generation:** Upon successful decryption, the original file is restored and saved to a user-specified location, with a confirmation message displayed.
  
3. **Graphical User Interface & Usability:**  
   - The application features a main window with two distinct tabs for encryption and decryption, providing a clear and organized layout for users.
   - The interface includes drag and drop support, password confirmation prompts, real-time progress bars, and detailed error messages (e.g., “Incorrect password”) to guide users through each step.
   - Robust error handling ensures that issues such as missing files, incorrect passwords, or mismatched confirmations are promptly communicated, enhancing reliability.


### **Application of the Tool:**

The Advanced Encryption Tool is ideal for:
- **Personal Data Protection:** Encrypting sensitive documents, images, and other files to safeguard personal information from unauthorized access, perfect for individual privacy needs.
- **Business Use Cases:** Securing confidential files before sharing or archiving, ensuring data privacy and compliance in professional environments.
- **Educational Purposes:** Demonstrating modern encryption techniques (e.g., AES-256, PBKDF2) and best practices in secure file handling, serving as a hands-on learning resource.
- **Backup Security:** Encrypting backups to prevent unauthorized access to sensitive data, adding an extra layer of protection for critical information.


### **Output Achieved:**

1. **Main Interface**
Upon executing the application, the main window of the Advanced Encryption Tool is displayed. The interface consists of two tabs:
- **Encrypt:** To encrypt a file using a password.
- **Decrypt:** To decrypt a previously encrypted file.


2. **File Encryption Completion**
After selecting a file, entering a password, and starting the encryption process, the tool successfully encrypts the file and provides a 
confirmation message.


3. **File Decryption Completion**
Similarly, after selecting an encrypted file and entering the correct password, the decryption process restores the original file successfully.




**Testing Environment:**

Note: The tool was tested on a variety of file types (including text files, images, and PDFs) in a controlled environment using Python 3.6+ and PyQt5 across Windows and Linux. Testing confirmed that the encryption and decryption processes work reliably while the GUI remains responsive during operations..

### **Usage Instructions:**

1. **Installation:**  
   Ensure Python 3.x is installed. Then, install the required packages using:
   ```bash
   pip install -r requirements.txt
   ```

2. **Running the Application:**
Launch the tool by executing:
   ```bash
   python encryption_app.py
   ```
Or launch the tool by executing:
   ```
   run_encryption_tool.bat
   ```

3. **Encrypting a File:**
   - Navigate to the Encrypt tab.
   - Click `Browse` or drag and drop the file into the designated area.
   - Enter a strong password and confirm it.
   - Click `Encrypt File.`
   - Choose a destination to save the encrypted file.

4. **Decrypting a File:**
   - Navigate to the Decrypt tab.
   - Click `Browse` or drag and drop the file you wish to decrypt.
   - Enter the password used during encryption.
   - Click `Decrypt File.`
   - Choose a destination to save the decrypted file.

5. **Logs and Output**
   - The tool provides real-time logs and displays success or error messages upon the completion of each operation.


### **Disclaimer & Cautions:**
**Important Disclaimer:**

This Advanced Encryption Tool is provided for legitimate encryption and decryption purposes only. It is intended to be used on files for which you have the legal right to secure. Unauthorized or improper use of this tool may result in data loss or legal consequences. The developer is not responsible for any misuse or damages arising from the use of this tool. Always ensure you comply with all applicable laws and best practices in data security.

### **Conclusion:**

By leveraging Python and powerful libraries like PyQt5, I developed a user-friendly and robust encryption tool that meets modern security standards. The Advanced Encryption Tool not only simplifies the process of encrypting and decrypting files using AES-256 encryption but also provides a comprehensive graphical interface and real-time feedback. This tool offers an effective solution for securing sensitive data, making it a valuable asset for personal, educational, and professional applications.
