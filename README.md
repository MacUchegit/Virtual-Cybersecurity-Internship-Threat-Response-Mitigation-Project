<img width="1536" height="1024" alt="cc4d6b55-36ee-4116-9a74-294f7379eb6b" src="https://github.com/user-attachments/assets/73fab190-d1b6-4782-8312-f0aa7648b580" />

# 🔐 Virtual Cybersecurity Internship – Threat Response & Mitigation Project

- **Role:** Information Security Analyst
- **Platform:** Forage (AIG Cyber & Information Security Simulation)
- **Skills Applied:** Vulnerability Management, Threat Communication, Python Scripting, Ransomware Response

---

### 🧭 **Project Overview**

This project simulated real-world tasks performed by Information Security Analysts, focusing on identifying, communicating, and mitigating emerging cybersecurity threats. The internship was divided into two main parts:

1. **Vulnerability Advisory Task** – Identify critical infrastructure vulnerabilities and notify appropriate internal teams.
2. **Ransomware Response Task** – Respond to a simulated ransomware incident using Python scripting to brute-force and recover an encrypted file.

---

## 🛠️ Task 1: Identifying and Reporting Log4j Vulnerability

### 🎯 **Objective:**

To assess recent cybersecurity advisories from CISA, determine vulnerable assets within AIG’s infrastructure, and notify relevant stakeholders to initiate prompt remediation.

---

### 🧠 **Background – Log4j (CVE-2021-44228)**

The **Apache Log4j** vulnerability is a critical remote code execution (RCE) flaw found in one of the most widely used logging libraries. Exploiting this vulnerability allows attackers to send specially crafted log messages that can result in full control of affected systems. CISA has issued urgent advisories urging organizations to patch or mitigate this flaw immediately.

---

### 📋 **Infrastructure Reference Table**

| Product Team            | Product Name                                | Team Lead                                                      | Services Installed                                              |
| ----------------------- | ------------------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------------- |
| IT                      | Workstation Management System               | Jane Doe ([tech@email.com](mailto:tech@email.com))             | OpenSSH, dnsmasq, lighttpd                                      |
| **Product Development** | **Product Development Staging Environment** | **John Doe ([product@email.com](mailto:product@email.com))**   | **Dovecot pop3d, Apache httpd, Log4j, Dovecot imapd, MiniServ** |
| Marketing               | Marketing Analytics Server                  | Joe Schmoe ([marketing@email.com](mailto:marketing@email.com)) | Microsoft ftpd, Indy httpd, Microsoft RPC, netbios-ssn          |
| HR                      | Human Resource Information System           | Joe Bloggs ([hr@email.com](mailto:hr@email.com))               | OpenSSH, Apache httpd, rpcbind2-4                               |

---

### 🔎 **Findings**

* **Vulnerable Infrastructure:** Product Development Staging Environment
* **Ownership:** Product Development Team (Lead: John Doe – [product@email.com](mailto:product@email.com))
* **Risk Factor:** High – Log4j is present, making the system vulnerable to remote exploitation.

---
### Next step is to draft a formal security advisory email to notify the Product Development Team about the critical Log4j vulnerability

📧 **Security Advisory Email Draft**

> **From:** AIG Cyber & Information Security Team
> **To:** [product@email.com](mailto:product@email.com)
> **Subject:** Security Advisory Concerning Apache Log4j Zero-Day Vulnerability
>
> Hello Product Development Team,
>
> AIG Cyber & Information Security Team would like to inform you that a recent Apache Log4j vulnerability (**CVE-2021-44228**) has been discovered in the security community that may affect the **Product Development Staging Environment**.
>
> **Vulnerability Description:**
> This vulnerability exists in the Log4j library’s JNDI lookup feature and allows unauthenticated remote code execution (RCE) via specially crafted log messages.
>
> **Risk/Impact:**
> This is a critical flaw actively exploited in the wild. If left unaddressed, it may lead to data exfiltration, ransomware infection, or complete system compromise.
>
> **Remediation:**
>
> * Upgrade Log4j to version **2.17.1 or later** immediately.
> * If upgrade isn’t feasible, remove the vulnerable class using:
>   `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`
> * Monitor logs for abnormal LDAP/DNS requests.
>
> Please confirm completion of remediation or request support if needed.
>
> **Kind regards**,
> *AIG Cyber & Information Security Team*

---

### ✅ **Highlights & Takeaways**

* Applied real-world CISA intelligence to internal infrastructure.
* Mapped service-to-vulnerability accurately.
* Communicated a critical risk clearly and professionally.
* Understood how to escalate and mitigate vulnerabilities responsibly.

---

## 🧑‍💻 Task 2: Ransomware Response – Brute-forcing Decryption Key

### 🎯 **Objective:**

After detecting a ransomware attempt that encrypted a single ZIP file, I was tasked with recovering the encrypted file **without paying the ransom** by brute-forcing the password using a Python script.

---

### 🧪 **Attack Scenario Recap:**

* The Log4j vulnerability was successfully exploited.
* Ransomware was deployed but contained early.
* One ZIP file was encrypted.
* We were expected to **recover the file without negotiation**.

---

### 🪛 **Steps Taken**

1. **Analyzed the Scenario**
   Based on the attacker's sloppiness and reliance on default payloads, I predicted the password would be weak and likely on the popular **RockYou** wordlist.

2. **Reviewed and Modified Python Template**
   Used the provided Python3+ script to brute-force the password using `rockyou.txt`.

3. **Execution and Validation**
   Ran the script, and after iterating through the list, successfully decrypted the ZIP file.  
5. **Password Found:**

   ```plaintext
   ✓ Password found: SPONGEBOB
   ```
Below are some screenshots showing the decryption process.
   ----
   **Updated and ran the python code**
   
   <img width="1902" height="981" alt="PYTHON CODE" src="https://github.com/user-attachments/assets/5b129431-4b31-47c1-aaca-c719e968ad73" />

   **Password Found and then used to decrypt the file**
   
   <img width="1768" height="766" alt="encrypyted" src="https://github.com/user-attachments/assets/a22fd945-7702-4812-9b7e-b0374dd8b4dd" />
   <img width="1501" height="926" alt="DECRYPYT" src="https://github.com/user-attachments/assets/91603d6b-7e0f-4924-8f4c-98d8c8a8bf8b" />

   **Decrypted File**
   
   <img width="1854" height="705" alt="OPENED FILE" src="https://github.com/user-attachments/assets/703fcc9a-01af-4f1e-9b84-f24e1433678b" />

---

### 💻 **Python Code Snippet**

```python
import os
print("[i] Current working directory:", os.getcwd())
from zipfile import ZipFile, BadZipFile
def attempt_extract(zf_handle, password):
   try:
       zf_handle.extractall(pwd=password)
       print(f"[✓] Password found: {password.decode().strip()}")
       return True
   except:
       return False
def main():
   print("[+] Beginning bruteforce...")
   with ZipFile('C:/Users/Cigold/Downloads/cyber-project/Forage Internship/sping zero day attack/EncryptedFilePack/enc.zip') as zf:
       with open('C:/Users/Cigold/Downloads/cyber-project/Forage Internship/sping zero day attack/EncryptedFilePack/rockyou.txt', 'rb') as f:
           for line in f:
               password = line.strip()
               if attempt_extract(zf, password):
                   break
           else:
               print("[-] Password not found in list.")
if __name__ == "__main__":
   main()

```

---

### ✅ **What I Did Well**

* Understood attacker behavior and adapted password-cracking strategy accordingly.
* Cleanly structured a brute-force solution with error handling.
* Demonstrated problem-solving under simulated pressure.
* Maintained secure handling of potentially sensitive files.

---

## 🔚 **Conclusion**

This virtual internship allowed me to:

* **Conduct real-world vulnerability triage** by evaluating CISA advisories.
* **Identify impacted infrastructure** and effectively escalate the threat to appropriate stakeholders.
* **Develop and implement a brute-force attack** script to recover ransomware-encrypted data using Python.
* Demonstrate **clear, structured communication and incident response skills**.

These tasks sharpened my practical cybersecurity abilities—especially in **threat detection, vulnerability reporting, scripting, and file recovery under ransomware scenarios**. I am confident these skills will serve me well as I pursue a career in cybersecurity.
