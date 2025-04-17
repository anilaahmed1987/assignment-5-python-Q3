# Secure Data Encryption System

A Streamlit-based secure data storage and retrieval system that allows users to store and retrieve encrypted data using unique passkeys.

## Features

- 🔐 Secure data encryption using Fernet
- 🔑 PBKDF2 password hashing
- ⏱️ 5-minute lockout after 3 failed attempts
- 💾 Persistent data storage
- 🎨 User-friendly interface

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   streamlit run secure_data_system.py
   ```

2. Navigate through the application using the sidebar menu:
   - **Home**: Overview of the system
   - **Store Data**: Encrypt and store new data
   - **Retrieve Data**: Decrypt and retrieve stored data
   - **Login**: Reauthorization page (after 3 failed attempts)

## Security Notes

- The master password is currently hardcoded as "admin123" for demonstration purposes. In a production environment, this should be replaced with proper authentication.
- The encryption key is stored in a file named `encryption_key.key`. Keep this file secure.
- Stored data is saved in `stored_data.json`. This file contains encrypted data and hashed passkeys.

## License

This project is open source and available under the MIT License. 