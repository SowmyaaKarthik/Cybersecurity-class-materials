# Coding in Cybersecurity 

## Scripting for Automation:

Purpose: Automation of repetitive tasks, such as system administration, log analysis, and data processing.
**1. System Administration:**

Example: List Files in a Directory
```
import os

def list_files(directory):
    files = os.listdir(directory)
    for file in files:
        print(file)

# Usage
directory_path = "/path/to/directory"
list_files(directory_path)

```
**2. Log Analysis:**
Example: Parse and Extract Information from Log File
```
import re

def analyze_log(log_file):
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'Error: (.+)', line)
            if match:
                error_message = match.group(1)
                print(f"Error found: {error_message}")

# Usage
log_file_path = "/path/to/logfile.log"
analyze_log(log_file_path)

```
**3. Data Processing:**

Example: Calculate Average from a List of Numbers

```
def calculate_average(numbers):
    if not numbers:
        return None
    return sum(numbers) / len(numbers)

# Usage
data = [23, 45, 12, 67, 89]
average = calculate_average(data)
print(f"Average: {average}")

```
## Web Application Security:

Purpose: Identifying and exploiting vulnerabilities in web applications.

**Example:** Basic script to detect XSS vulnerabilities in a web page

```
from bs4 import BeautifulSoup

def find_xss_vulnerabilities(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    script_tags = soup.find_all('script')

    if script_tags:
        print("Potential XSS vulnerabilities found:")
        for tag in script_tags:
            print(tag)
    else:
        print("No XSS vulnerabilities found.")

# Usage
html_content = "<html><head><script>alert('XSS');</script></head></html>"
find_xss_vulnerabilities(html_content)
```
### Network Security:

Purpose: Developing tools for network scanning, packet analysis, and intrusion detection.

**Example: Simple script to check if a website is up**
```
import requests

def check_website(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"{url} is up and running.")
        else:
            print(f"{url} is down with status code {response.status_code}.")
    except Exception as e:
        print(f"Error checking {url}: {e}")

# Usage
check_website("https://www.example.com")
```

**1. Network Scanning Tool (Port Scanner):**

```
import socket

def port_scanner(target, ports):
    print(f"Scanning target: {target}")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open")
        sock.close()

# Usage
target_ip = "127.0.0.1"
target_ports = [80, 22, 443, 8080]
port_scanner(target_ip, target_ports)

```
**2. Packet Analysis Tool (Sniffer):**

```
import socket
import struct
import binascii

def sniff_packets(interface="eth0"):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as s:
        s.bind((interface, 0x0003))
        while True:
            raw_packet = s.recvfrom(2048)[0]
            eth_header = struct.unpack("!6s6s2s", raw_packet[:14])
            dest_mac, src_mac, eth_type = binascii.hexlify(eth_header[0]), binascii.hexlify(eth_header[1]), binascii.hexlify(eth_header[2])
            print(f"Source MAC: {src_mac.decode('utf-8')}, Destination MAC: {dest_mac.decode('utf-8')}, Ethertype: {eth_type.decode('utf-8')}")

# Usage
sniff_packets()

```

**3. Intrusion Detection Tool (Simple IDS):**

Pre-requisite: 
```
sudo pip install scapy
```
Coding:
```
import scapy.all as scapy

def sniff_packets(interface="eth0"):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"Detected packet from {ip_src} to {ip_dst}")

# Usage
sniff_packets()

```

### Reverse Engineering and Malware Analysis:

Purpose: Analyzing and understanding malicious software, discovering vulnerabilities.

Pre-requisite:
```
pip install bandit pylint
```

Here's a simple Python program that demonstrates the use of Bandit and Pylint for static code analysis:
```
# Example Python code
import subprocess

def insecure_subprocess():
    # Example of insecure subprocess call
    subprocess.call('ls')

def hard_coded_password():
    # Example of hard-coded password
    password = 'my_password'

def main():
    insecure_subprocess()
    hard_coded_password()

if __name__ == "__main__":
    main()

```
To Run using `Bandit`:
```
bandit your_python_file.py
```
To Run using `Pylint`:
```
pylint your_python_file.py
```
### Cryptography:

Purpose: Implementing and analyzing cryptographic algorithms.

Pre-requisite:
```
!pip install cryptography
```
**Example: Implementing simple Symmetric key encryption and decryption**

Here's a simple example of symmetric key encryption and decryption using the cryptography library in Python. This example uses the Fernet symmetric key encryption scheme, which is a simple and secure way to encrypt data.

```
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return encrypted_message

def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
    return decrypted_message

# Generate a key (keep this secret and secure)
key = generate_key()

# Message to be encrypted
original_message = "Hello, cryptography!"

# Encrypt the message
encrypted_message = encrypt_message(original_message, key)
print(f'Encrypted message: {encrypted_message}')

# Decrypt the message
decrypted_message = decrypt_message(encrypted_message, key)
print(f'Decrypted message: {decrypted_message}')

```

### Security Automation and Orchestration:

Purpose: Building automated workflows for incident response, threat intelligence.

Building automated workflows for incident response and threat intelligence using Python involves integrating various tools, APIs, and scripts to streamline and automate processes. Below is a simplified example to get you started.

**Example: Automated Workflow for Incident Response and Threat Intelligence**

```
import requests
from datetime import datetime

# Function to fetch threat intelligence data
def fetch_threat_intelligence(ip_address):
    # Replace this URL with a real threat intelligence API endpoint
    threat_intel_api_url = f"https://example.com/threat-intel/{ip_address}"
    response = requests.get(threat_intel_api_url)
    threat_data = response.json() if response.status_code == 200 else None
    return threat_data

# Function to analyze and respond to an incident
def incident_response(ip_address):
    # Fetch threat intelligence data
    threat_data = fetch_threat_intelligence(ip_address)

    if threat_data:
        # Extract relevant information from threat data
        threat_type = threat_data.get("threat_type", "Unknown")
        description = threat_data.get("description", "No description available")

        # Perform automated actions based on threat intelligence
        if threat_type == "Malicious":
            quarantine_host(ip_address)
            notify_security_team(threat_type, description)
        elif threat_type == "Suspicious":
            log_incident(ip_address, threat_type, description)
        else:
            notify_security_team(threat_type, description)
    else:
        print(f"No threat intelligence available for {ip_address}")

# Example functions for automated actions
def quarantine_host(ip_address):
    print(f"Quarantining host with IP address: {ip_address}")

def notify_security_team(threat_type, description):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Alert: {timestamp} - Threat detected - Type: {threat_type}, Description: {description}")
    # Add code to send alerts or notifications to the security team

def log_incident(ip_address, threat_type, description):
    print(f"Incident logged - IP: {ip_address}, Type: {threat_type}, Description: {description}")
    # Add code to log the incident in your incident management system

# Example usage
incident_response("192.168.1.1")

```
### Database Security:

Purpose: Securing databases, preventing SQL injection attacks.
Languages: SQLite, Python.

**Example: Preventing SQL Injection with Parameterized Queries**

```
import sqlite3

# Function to create a users table
def create_users_table():
    # Connect to the SQLite database
    connection = sqlite3.connect('example.db')
    cursor = connection.cursor()

    try:
        # Creating the users table with username and password columns
        query = '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        '''
        cursor.execute(query)

        # Commit the changes to the database
        connection.commit()
        print("Users table created successfully.")
    except Exception as e:
        print(f"Error creating users table: {e}")
    finally:
        # Close the database connection
        connection.close()

# Function to insert user data into the database
def insert_user_data(username, password):
    # Connect to the SQLite database
    connection = sqlite3.connect('example.db')
    cursor = connection.cursor()

    try:
        # Using parameterized query to prevent SQL injection
        query = "INSERT INTO users (username, password) VALUES (?, ?)"
        cursor.execute(query, (username, password))

        # Commit the changes to the database
        connection.commit()
        print("User data inserted successfully.")
    except Exception as e:
        print(f"Error inserting user data: {e}")
    finally:
        # Close the database connection
        connection.close()

# Example usage
create_users_table()

# User inputs (potentially from a web form or another user input source)
user_input_username = "user1"
user_input_password = "password123' OR '1'='1'; --"

# Call the function with user input to demonstrate prevention of SQL injection
insert_user_data(user_input_username, user_input_password)

```
### Data Analysis and Threat Hunting:

Purpose: Analyzing large datasets for anomalies, identifying security threats.

```
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import pandas as pd

# Function to load and preprocess the dataset
def load_and_preprocess_dataset(file_path):
    # Load the dataset (replace 'your_dataset.csv' with the actual file path)
    df = pd.read_csv(file_path)

    # Extract relevant features for analysis
    features = df[['Feature1', 'Feature2', 'Feature3']]  # Replace with your actual feature names

    # Standardize the features
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)

    return scaled_features

# Function for anomaly detection using Isolation Forest
def detect_anomalies(data):
    # Apply Isolation Forest algorithm
    model = IsolationForest(contamination=0.05)  # Adjust the contamination parameter as needed
    model.fit(data)

    # Predict anomalies (1 for normal, -1 for anomaly)
    predictions = model.predict(data)

    return predictions

# Example usage
file_path = 'your_dataset.csv'  # Replace with the actual path to your dataset
dataset = load_and_preprocess_dataset(file_path)

# Detect anomalies
anomaly_predictions = detect_anomalies(dataset)

# Visualize anomalies
plt.scatter(range(len(anomaly_predictions)), dataset[:, 0], c=anomaly_predictions, cmap='viridis', marker='.')
plt.title('Anomaly Detection Results')
plt.xlabel('Data Points')
plt.ylabel('Feature1')
plt.show()

```




