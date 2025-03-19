import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class EncryptionUtils:
    """Utility class for file encryption and decryption using AES-256."""
    
    @staticmethod
    def derive_key(password, salt, iterations=100000):
        """
        Derive a 256-bit key from a password using PBKDF2.
        
        Args:
            password (str): The password to derive the key from
            salt (bytes): Salt for key derivation
            iterations (int): Number of iterations for PBKDF2
            
        Returns:
            bytes: A 32-byte (256-bit) key
        """
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    
    @staticmethod
    def encrypt_file(input_file_path, output_file_path, password, callback=None):
        """
        Encrypt a file using AES-256 encryption.
        
        Args:
            input_file_path (str): Path to the file to encrypt
            output_file_path (str): Path to save the encrypted file
            password (str): Password for encryption
            callback (function, optional): Callback for progress updates
            
        Returns:
            bool: True if encryption was successful, False otherwise
        """
        try:
            # Generate a random salt
            salt = get_random_bytes(16)
            
            # Derive encryption key from password
            key = EncryptionUtils.derive_key(password, salt)
            
            # Generate a random IV
            iv = get_random_bytes(16)
            
            # Create AES cipher in CBC mode
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Get file size for progress reporting
            file_size = os.path.getsize(input_file_path)
            
            with open(input_file_path, 'rb') as in_file:
                with open(output_file_path, 'wb') as out_file:
                    # Write salt and IV to the output file
                    out_file.write(salt)
                    out_file.write(iv)
                    
                    # Process file in chunks to handle large files
                    chunk_size = 64 * 1024  # 64KB chunks
                    bytes_processed = 0
                    
                    while True:
                        chunk = in_file.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        
                        # If this is the last chunk, add padding
                        if len(chunk) % 16 != 0:
                            chunk = pad(chunk, AES.block_size)
                        
                        # Encrypt and write the chunk
                        encrypted_chunk = cipher.encrypt(chunk)
                        out_file.write(encrypted_chunk)
                        
                        # Update progress
                        bytes_processed += len(chunk)
                        if callback:
                            progress = min(100, int(100 * bytes_processed / file_size))
                            callback(progress)
            
            return True
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return False
    
    @staticmethod
    def decrypt_file(input_file_path, output_file_path, password, callback=None):
        """
        Decrypt a file that was encrypted using encrypt_file.
        
        Args:
            input_file_path (str): Path to the encrypted file
            output_file_path (str): Path to save the decrypted file
            password (str): Password used for encryption
            callback (function, optional): Callback for progress updates
            
        Returns:
            bool: True if decryption was successful, False otherwise
        """
        try:
            # Get file size for progress reporting
            file_size = os.path.getsize(input_file_path)
            
            with open(input_file_path, 'rb') as in_file:
                # Read salt and IV from the beginning of the file
                salt = in_file.read(16)
                iv = in_file.read(16)
                
                # Derive key from password and salt
                key = EncryptionUtils.derive_key(password, salt)
                
                # Create AES cipher in CBC mode
                cipher = AES.new(key, AES.MODE_CBC, iv)
                
                with open(output_file_path, 'wb') as out_file:
                    # Process file in chunks
                    chunk_size = 64 * 1024  # 64KB chunks
                    bytes_processed = 32  # Salt and IV bytes already processed
                    
                    # Read and decrypt chunks
                    while True:
                        chunk = in_file.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        
                        decrypted_chunk = cipher.decrypt(chunk)
                        
                        # If this is the last chunk, remove padding
                        if in_file.peek(1) == b'':
                            decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
                        
                        out_file.write(decrypted_chunk)
                        
                        # Update progress
                        bytes_processed += len(chunk)
                        if callback:
                            progress = min(100, int(100 * bytes_processed / file_size))
                            callback(progress)
            
            return True
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return False 