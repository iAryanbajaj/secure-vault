# 🔐 SecureVault

A secure self-hosted cloud storage system designed with a security-first approach. Inspired by cloud platforms like Google Drive, this project focuses on protecting user data using modern cybersecurity practices.

---

## 🚀 Features

* 📁 Bucket-based file management (upload, download, organize)
* 🔒 AES-256 encryption for data at rest
* 🔑 Two-Factor Authentication (TOTP-based)
* 🔄 File versioning system
* 🔗 Secure file sharing via protected links
* 🐳 Dockerized deployment
* 🌐 HTTPS with session management

---

## 🛠 Tech Stack

* **Backend:** Python, Flask
* **Security:** AES-256, TOTP (2FA)
* **Database:** SQLite
* **Deployment:** Docker, Docker Compose
* **Other:** REST APIs, Session Management

---

## ⚙️ Installation & Setup

### 1. Clone the repository

```
git clone https://github.com/iAryanbajaj/secure-vault.git
cd secure-vault
```

### 2. Setup environment variables

Create a `.env` file:

```
SECRET_KEY=your_secret_key
DATABASE_URL=sqlite:///app.db
```

### 3. Run using Docker

```
docker-compose up --build
```

### 4. Access the app

```
http://localhost:5000
```

---

## 🔐 Security Highlights

* End-to-end encrypted storage using AES-256
* TOTP-based 2FA for secure authentication
* Secure session handling with HTTPS enforcement
* Designed with an attacker mindset to reduce vulnerabilities
* Containerized deployment with isolation (Docker)

---

## 📸 Screenshots (Add Here)

Add your project screenshots here (dashboard, login, etc.)

---

## 📌 Future Improvements

* Cloud deployment (AWS / Azure)
* Role-based access control (RBAC)
* File integrity verification (hashing)
* Advanced logging & monitoring

---

## 👨‍💻 Author

**Aryan Bajaj**
Cybersecurity Enthusiast | Developer

---

## ⭐ Support

If you like this project, consider giving it a ⭐ on GitHub!
