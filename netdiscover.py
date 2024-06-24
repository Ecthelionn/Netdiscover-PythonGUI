import os
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import ARP, Ether, srp


def scan_network(ip_range):
    # ARP Request
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send packet and get response
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


def start_scan(ip_entry, result_text):
    ip_range = ip_entry.get()
    result_text.delete('1.0', tk.END)
    devices = scan_network(ip_range)
    for device in devices:
        result_text.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}\n")


def main():
    window = tk.Tk()
    window.title("Netdiscover GUI")

    # IP Range Entry
    ip_label = tk.Label(window, text="IP Range (e.g. 192.168.1.0/24):")
    ip_label.grid(column=0, row=0)
    ip_entry = tk.Entry(window, width=30)
    ip_entry.grid(column=1, row=0)

    # Scan Button
    scan_button = tk.Button(window, text="Scan", command=lambda: start_scan(ip_entry, result_text))
    scan_button.grid(column=2, row=0)

    # Result Text Area
    result_text = scrolledtext.ScrolledText(window, width=80, height=20)
    result_text.grid(column=0, row=1, columnspan=3)

    window.mainloop()


if __name__ == "__main__":
    main()
