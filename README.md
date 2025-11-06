# **RSA-Based Secure File Encryption with Integrity Verification using Hash Functions**

---

## **🔒 Overview**

This project implements a **Secure Cryptographic File Exchange System** that ensures **confidentiality**, **authenticity**, and **integrity** in data transmission.

It integrates multiple modern cryptographic techniques — **Diffie–Hellman (DH)**, **AES**, **RSA**, and **SHA-512** — into a **hybrid encryption model**, tested against **Man-in-the-Middle (MITM)** attacks through a simulated adversary module (**Eve**).

---

## **🧩 System Architecture**

The system consists of **four main modules:**

### **1. Alice (Sender)**
- Selects and encrypts the file using **AES**.  
- Performs **Diffie–Hellman key exchange** with Bob to derive a shared AES key.  
- Generates a **SHA-512 hash** of the file and signs it using her **RSA private key**.  
- Sends the **encrypted file**, **signature**, and **metadata** to Bob.  

### **2. Channel**
- Simulates a **network environment** for secure or tampered transmission.  
- Can either pass the data directly or route it through **Eve**.  

### **3. Eve (Attacker)**
- Optional module that simulates **Man-in-the-Middle (MITM)** attacks.  
- Intercepts, modifies, or replaces the transmitted file.  
- Used for testing system resilience and integrity detection.  

### **4. Bob (Receiver)**
- Derives the same **AES key** via Diffie–Hellman exchange.  
- Decrypts the received file using **AES**.  
- Verifies the **RSA signature** using Alice’s public key.  
- Compares the **computed and received SHA-512 hashes** for integrity verification.  

---

## **✨ Features**

- **Hybrid Encryption:** Combines symmetric (**AES**) and asymmetric (**RSA**) encryption.  
- **Key Exchange:** Uses **Diffie–Hellman** for secure shared key generation.  
- **Integrity Verification:** Employs **SHA-512 hashing** to detect tampering.  
- **Authentication:** **RSA-based digital signature** ensures sender legitimacy.  
- **Attack Simulation:** Includes an **Eve module** to simulate MITM attacks.  
- **Web Integration:** **Flask/Django backend** with **HTML/CSS/JavaScript frontend** for user interaction.  

---

## **⚙️ Methodology**

### **System Workflow**
1. **File Selection:** User selects the file to be encrypted.  
2. **Key Exchange:** Alice and Bob perform Diffie–Hellman exchange to derive a shared AES key.  
3. **Encryption:** AES is used to encrypt the file data.  
4. **Signing:** RSA signs the file hash (**SHA-512**) for authenticity.  
5. **Transmission:** Data is sent through the channel, optionally intercepted by **Eve**.  
6. **Decryption:** Bob decrypts using the shared AES key.  
7. **Verification:** Bob verifies the RSA signature and hash to confirm integrity.  

---

## **📊 Results**

| **Test Scenario**                     | **Outcome** |
|--------------------------------------|--------------|
| Normal Transmission                  | Successful decryption, hash match |
| Tampered Transmission (Eve Enabled)  | Hash mismatch detected, integrity verification failed |
| Key Exchange Validation              | Identical AES keys generated for both sender and receiver |
| Performance                          | Fast AES encryption/decryption with negligible delay |

---

## **🔍 Key Observations**

- **SHA-512** provides strong collision resistance.  
- **RSA** ensures authentication and non-repudiation.  
- **Diffie–Hellman** prevents direct key exposure.  
- **Eve Module** effectively validates attack resilience.  

---

## **🛠️ Tools and Technologies**

| **Category** | **Tools / Frameworks** |
|---------------|-------------------------|
| Simulation | **MATLAB** |

---

---

## **👩‍💻 Team Members**

| **Name** | **Registration Number** |
|-----------|--------------------------|
| **Sunsitha Varshini Pugalaendhi** | **22BEC0738** |
| **Sanaputur Sai Charan** | **22BEC0696** |
| **Samaksh Arjani** | **22BEC0697** |
| **K. Likhitha Reddy** | **22BEC0720** |
| **S. Vamsi Krishna** | **22BEC0538** |

---

## **🎓 Under the Guidance of**

**Dr. Mugelan R K**  
**Department of Electronics and Communication Engineering**  
**Vellore Institute of Technology (VIT), Vellore)**  

---

## **🔮 Future Enhancements**

- Integration of **Elliptic Curve Cryptography (ECC)** for improved speed.  
- Implementation of **multi-user key management**.  
- Deployment on **cloud environments** with encrypted storage.  
- **Real-time attack detection and alert systems.**  

---

## **📚 References**

A detailed list of **IEEE and academic references** used in this study is available in the  
**Case Study Report**.

---
