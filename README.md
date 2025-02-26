# Subdomain Finder - Advanced Version

An advanced Python-based subdomain discovery and port scanning tool with an intuitive Tkinter GUI. Designed for penetration testers, cybersecurity professionals, and developers, it offers multiple scanning techniques, real-time results, and customizable options for efficient reconnaissance.

------

## 🚀 Features

- 🔍 **Multiple Scanning Methods:**
  - DNS Bruteforce
  - Certificate Transparency Log Search (crt.sh)
  - Reverse DNS Lookup
  - Combined or Full Scan options
- ⚡ **High Performance:** Multi-threaded scanning for faster execution without performance loss.
- 📡 **Port Scanning:** Double-click any subdomain to perform a port scan on common ports.
- 🖥️ **User-Friendly GUI:** Interactive Tkinter interface displaying subdomains, IP addresses, and scanning status in real time.
- 💾 **Export Results:**
  - Save results as `.txt` files.
  - Export results as `.csv` for easy analysis.
- 🛡 **Customizable Timeout:** Adjust DNS resolver timeout settings for tailored scanning.
- ✅ **Robust Error Handling:** Ensures stable performance even during large-scale scans.

------

## 📦 Installation

### 1. **Clone the Repository**

```bash
git clone https://github.com/foefvjfev33/SubDomaime
cd subDomain.py
```

### 2. **Install Dependencies**

Ensure you have Python 3.6+ installed.

```bash
pip install -r requirements.txt
```

#### **Dependencies:**

- `dnspython`
- `requests`
- `tkinter`

Install them manually if `requirements.txt` is missing:

```bash
pip install dnspython requests
```

------

## 🚀 Usage

Run the tool using:

```bash
python subDomain.py
```

### 🔧 **How to Use:**

1. Enter the target domain in the **Domain** field.
2. Select the **Scan Method** from the dropdown menu.
3. Click **Start Scan** to begin.
4. Double-click any listed subdomain to run a **Port Scan**.
5. Use **Save Results** or **Export as CSV** to save your findings.

------

## 📝 Example

```plaintext
Domain: example.com
Scan Method: Full Scan

[✓] Scan completed. Total unique subdomains found: 12
[PTR] 93.184.216.34 -> ptr.example.com
[OPEN] Port 80 is open.
[OPEN] Port 443 is open.
```

------

## 🛠️ Project Structure

```
subdomain/
│
├── subDomain.py    # Main application script
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

------

## ⚡ Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

------

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

------

## 💡 Acknowledgements

- [dnspython](https://www.dnspython.org/)
- [Tkinter Documentation](https://docs.python.org/3/library/tkinter.html)
- [crt.sh](https://crt.sh/)

------

## 🌐 Contact

**Author:** https://github.com/foefvjfev33
 **GitHub:** https://github.com/foefvjfev33/SubDomaime

