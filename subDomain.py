import dns.resolver
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import socket

class SubdomainFinder:
    def __init__(self, root):
        self.root = root
        self.root.title("Subdomain Finder - Advanced Version")
        self.root.geometry("1300x800")

        # إدخال الدومين وخيارات الفحص
        ttk.Label(root, text="Domain:").grid(row=0, column=0, sticky=tk.W)
        self.domain_entry = ttk.Entry(root, width=40)
        self.domain_entry.grid(row=0, column=1, columnspan=2, pady=5)

        ttk.Label(root, text="Scan Method:").grid(row=0, column=3, sticky=tk.W)
        self.scan_method = ttk.Combobox(
            root, values=["DNS Bruteforce", "Certificate Search", "Reverse DNS Lookup", "Both", "Full Scan"]
        )
        self.scan_method.grid(row=0, column=4, padx=5)
        self.scan_method.set("Full Scan")

        # أزرار التحكم
        self.start_button = ttk.Button(root, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=0, column=5, padx=5)

        self.save_button = ttk.Button(root, text="Save Results", command=self.save_results)
        self.save_button.grid(row=0, column=6, padx=5)

        self.export_csv_button = ttk.Button(root, text="Export as CSV", command=self.export_csv)
        self.export_csv_button.grid(row=0, column=7, padx=5)

        # منطقة عرض النتائج
        ttk.Label(root, text="Subdomains").grid(row=1, column=0, columnspan=2)
        ttk.Label(root, text="IP Addresses").grid(row=1, column=2, columnspan=2)
        ttk.Label(root, text="Status").grid(row=1, column=4, columnspan=4)

        self.domain_listbox = tk.Listbox(root, width=40, height=35)
        self.domain_listbox.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        self.domain_listbox.bind("<Double-Button-1>", self.open_port_scan_window)

        self.ip_listbox = tk.Listbox(root, width=40, height=35)
        self.ip_listbox.grid(row=2, column=2, columnspan=2, padx=5, pady=5)

        self.status_text = scrolledtext.ScrolledText(root, width=60, height=35)
        self.status_text.grid(row=2, column=4, columnspan=4, padx=5, pady=5)

        # خيارات إضافية
        self.timeout_label = ttk.Label(root, text="Resolver Timeout (seconds):")
        self.timeout_label.grid(row=3, column=0, sticky=tk.W)
        self.timeout_entry = ttk.Entry(root, width=10)
        self.timeout_entry.grid(row=3, column=1, sticky=tk.W)
        self.timeout_entry.insert(0, "2")

        self.subdomains = {}

    def get_ip_address(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = int(self.timeout_entry.get())
            answers = resolver.resolve(domain, 'A')
            return ', '.join(sorted(set(str(rdata) for rdata in answers)))
        except:
            return "No IP found"

    def dns_lookup(self, subdomain):
        try:
            ip_address = self.get_ip_address(subdomain)
            return subdomain, ip_address
        except:
            return None

    def reverse_dns_lookup(self, ip):
        try:
            reversed_domain = dns.reversename.from_address(ip)
            resolved_domain = str(dns.resolver.resolve(reversed_domain, "PTR")[0])
            return resolved_domain
        except:
            return "PTR lookup failed"

    def check_crt_sh(self, domain):
        self.status_text.insert(tk.END, "\n[+] Checking certificate transparency logs...\n")
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry['name_value'].lower()
                    if '*' not in name and name not in self.subdomains:
                        ip_address = self.get_ip_address(name)
                        self.subdomains[name] = ip_address
                        self.update_results(name, ip_address)
                self.status_text.insert(tk.END, "[+] Certificate search completed.\n")
        except:
            self.status_text.insert(tk.END, "[-] Error accessing crt.sh\n")

    def bruteforce_subdomains(self, domain):
        self.status_text.insert(tk.END, "\n[+] Starting DNS bruteforce...\n")
        common_subdomains = [
            'www', 'mail', 'ftp', 'api', 'dev', 'test', 'blog', 'shop',
            'vpn', 'admin', 'portal', 'cdn', 'secure', 'login', 'app'
        ]
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(lambda sub: self.dns_lookup(f"{sub}.{domain}"), common_subdomains)
            for result in results:
                if result:
                    subdomain, ip = result
                    if subdomain not in self.subdomains:
                        self.subdomains[subdomain] = ip
                        self.update_results(subdomain, ip)
        self.status_text.insert(tk.END, "[+] DNS bruteforce completed.\n")

    def update_results(self, subdomain, ip):
        self.domain_listbox.insert(tk.END, subdomain)
        self.ip_listbox.insert(tk.END, ip)

    def save_results(self):
        if not self.subdomains:
            messagebox.showwarning("Warning", "No results to save!")
            return
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")]
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    for subdomain, ip in self.subdomains.items():
                        f.write(f"{subdomain} - {ip}\n")
                messagebox.showinfo("Success", f"Results saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results: {str(e)}")

    def export_csv(self):
        if not self.subdomains:
            messagebox.showwarning("Warning", "No results to export!")
            return
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")]
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("Subdomain,IP Address\n")
                    for subdomain, ip in self.subdomains.items():
                        f.write(f"{subdomain},{ip}\n")
                messagebox.showinfo("Success", f"CSV exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")

    def start_scan(self):
        self.domain_listbox.delete(0, tk.END)
        self.ip_listbox.delete(0, tk.END)
        self.status_text.delete(1.0, tk.END)
        self.subdomains.clear()

        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Warning", "Please enter a valid domain.")
            return

        def scan_thread():
            method = self.scan_method.get()
            if method in ["DNS Bruteforce", "Both", "Full Scan"]:
                self.bruteforce_subdomains(domain)
            if method in ["Certificate Search", "Both", "Full Scan"]:
                self.check_crt_sh(domain)
            if method in ["Reverse DNS Lookup", "Full Scan"]:
                for ip in set(self.subdomains.values()):
                    if ip != "No IP found":
                        ptr_result = self.reverse_dns_lookup(ip)
                        self.status_text.insert(tk.END, f"[PTR] {ip} -> {ptr_result}\n")

            self.status_text.insert(tk.END, f"\n[✓] Scan completed. Total unique subdomains found: {len(self.subdomains)}\n")

        threading.Thread(target=scan_thread).start()

    def open_port_scan_window(self, event):
        selected_index = self.domain_listbox.curselection()
        if not selected_index:
            return
        domain = self.domain_listbox.get(selected_index[0])

        port_window = tk.Toplevel(self.root)
        port_window.title(f"Port Scan - {domain}")
        port_window.geometry("800x600")

        ttk.Label(port_window, text=f"Scanning Ports for: {domain}").pack(pady=10)
        result_text = scrolledtext.ScrolledText(port_window, width=90, height=30)
        result_text.pack(padx=10, pady=10)

        def scan_ports():
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
            result_text.insert(tk.END, "[+] Starting port scan...\n")
            for port in common_ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    try:
                        sock.connect((domain, port))
                        result_text.insert(tk.END, f"[OPEN] Port {port} is open.\n")
                    except:
                        result_text.insert(tk.END, f"[CLOSED] Port {port} is closed.\n")
            result_text.insert(tk.END, "[✓] Port scan completed.\n")

        threading.Thread(target=scan_ports).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = SubdomainFinder(root)
    root.mainloop()