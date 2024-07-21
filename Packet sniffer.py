import tkinter as tk
from tkinter import scrolledtext, filedialog
from scapy.all import *
import threading

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        # Frame for GUI elements
        self.frame = tk.Frame(self.root)
        self.frame.pack(padx=10, pady=10)
        
        # ScrolledText widget to display captured packets
        self.log = scrolledtext.ScrolledText(self.frame, width=80, height=20)
        self.log.grid(row=0, column=0, columnspan=4, padx=5, pady=5)
        
        # Start button
        self.start_button = tk.Button(self.frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=1, column=0, padx=5, pady=5)
        
        # Stop button
        self.stop_button = tk.Button(self.frame, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.grid(row=1, column=1, padx=5, pady=5)
        self.stop_button.config(state=tk.DISABLED)  # Initially disabled
        
        # Save button
        self.save_button = tk.Button(self.frame, text="Save Log", command=self.save_log)
        self.save_button.grid(row=1, column=2, padx=5, pady=5)
        
        # Clear button
        self.clear_button = tk.Button(self.frame, text="Clear Log", command=self.clear_log)
        self.clear_button.grid(row=1, column=3, padx=5, pady=5)
        
        # Packet sniffing variables
        self.sniffing = False
        self.packet_count = 0
        self.packets = []

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.log.insert(tk.END, "Packet sniffing started...\n")
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log.insert(tk.END, "Packet sniffing stopped.\n")

    def clear_log(self):
        self.log.delete('1.0', tk.END)
        self.packet_count = 0
        self.packets = []

    def process_packet(self, pkt):
        if self.sniffing:
            self.packet_count += 1
            self.packets.append(pkt)
            self.log.insert(tk.END, f"Packet #{self.packet_count}\n")
            self.log.insert(tk.END, pkt.show(dump=True))
            self.log.insert(tk.END, "\n\n")
            self.log.see(tk.END)  # Scroll to the end of the text widget

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False)

    def save_log(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                for pkt in self.packets:
                    file.write(f"Packet #{self.packets.index(pkt) + 1}\n")
                    file.write(pkt.show(dump=True))
                    file.write("\n\n")
            self.log.insert(tk.END, f"Saved {len(self.packets)} packets to {file_path}\n")

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
