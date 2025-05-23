import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import logging
import sys
import io


# Redirect stdout/stderr to capture logs in the GUI
class TextRedirector(io.StringIO):
    def __init__(self, widget):
        super().__init__()
        self.widget = widget

    def write(self, s):
        self.widget.insert(tk.END, s)
        self.widget.see(tk.END)  # Auto-scroll to the end
        super().write(s)  # Write to the underlying StringIO as well


# Use the core Sender logic
from src.sender.sender import Sender


class SenderGUI:
    def __init__(self, master):
        self.master = master
        master.title("Oblivious Transfer Sender")
        master.geometry("800x600")

        self.sender_app = None  # Will hold the Sender logic instance
        self.is_running = False

        # --- Frame for Inputs ---
        input_frame = ttk.LabelFrame(master, text="Messages & Configuration", padding="10 10 10 10")
        input_frame.pack(padx=10, pady=10, fill="x", expand=True)

        # Message 0
        ttk.Label(input_frame, text="Message M0:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.msg0_entry = ttk.Entry(input_frame, width=50)
        self.msg0_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.msg0_entry.insert(0, "Secret Message Zero")  # Default value

        # Message 1
        ttk.Label(input_frame, text="Message M1:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.msg1_entry = ttk.Entry(input_frame, width=50)
        self.msg1_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.msg1_entry.insert(0, "Confidential Message One")  # Default value

        # Host and Port
        ttk.Label(input_frame, text="Host:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.host_entry = ttk.Entry(input_frame, width=20)
        self.host_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        self.host_entry.insert(0, "127.0.0.1")

        ttk.Label(input_frame, text="Port:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.port_entry = ttk.Entry(input_frame, width=10)
        self.port_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        self.port_entry.insert(0, "65432")

        # Bit Length
        ttk.Label(input_frame, text="Key Bit Length:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.bit_length_entry = ttk.Entry(input_frame, width=10)
        self.bit_length_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")
        self.bit_length_entry.insert(0, "1024")  # Default 1024 bits

        input_frame.columnconfigure(1, weight=1)  # Allow column 1 to expand

        # --- Action Buttons ---
        button_frame = ttk.Frame(master, padding="10 10 10 10")
        button_frame.pack(padx=10, pady=5, fill="x")

        self.start_button = ttk.Button(button_frame, text="Start Sender", command=self.start_sender_thread)
        self.start_button.pack(side="left", padx=5, expand=True, fill="x")

        self.reset_button = ttk.Button(button_frame, text="Reset", command=self.reset_sender_gui, state=tk.DISABLED)
        self.reset_button.pack(side="left", padx=5, expand=True, fill="x")

        # --- Log Output ---
        log_frame = ttk.LabelFrame(master, text="Protocol Log", padding="10 10 10 10")
        log_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled', height=15, width=80)
        self.log_text.pack(expand=True, fill="both")

        # Redirect logging output to the ScrolledText widget
        self.log_capture = TextRedirector(self.log_text)
        sys.stdout = self.log_capture
        sys.stderr = self.log_capture

        # Reconfigure logging to write to our custom stream
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - Sender - %(message)s',
                            stream=self.log_capture)

    def start_sender_thread(self):
        """
        Starts the sender process in a separate thread to keep the GUI responsive.
        """
        if self.is_running:
            messagebox.showwarning("Sender Status", "Sender is already running.")
            return

        m0 = self.msg0_entry.get()
        m1 = self.msg1_entry.get()
        host = self.host_entry.get()
        port_str = self.port_entry.get()
        bit_length_str = self.bit_length_entry.get()

        if not m0 or not m1:
            messagebox.showerror("Input Error", "Please enter both messages M0 and M1.")
            return

        try:
            port = int(port_str)
            if not (1024 <= port <= 65535):
                raise ValueError("Port must be between 1024 and 65535.")
            bit_length = int(bit_length_str)
            if bit_length < 100:  # As per requirement of 100 digits or more (~332 bits)
                logging.warning(
                    f"Chosen bit length ({bit_length}) is very low for cryptographic security. Recommend at least 332 bits for 100 decimal digits, or 1024 bits for general security.")
            if bit_length < 64:  # Minimum reasonable for DH parameters
                raise ValueError("Bit length must be at least 64 bits.")

        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid Port or Bit Length: {e}")
            return

        self.set_gui_state(running=True)

        logging.info("Attempting to start Sender logic...")
        self.sender_app = Sender(host=host, port=port, bit_length=bit_length)
        self.sender_app.set_messages(m0, m1)

        # Run the sender logic in a separate thread
        self.sender_thread = threading.Thread(target=self._run_sender_logic, daemon=True)
        self.sender_thread.start()

    def _run_sender_logic(self):
        """
        Private method to run the Sender's core logic. This runs in a separate thread.
        """
        try:
            self.sender_app.start()
            logging.info("Sender finished successfully.")
            messagebox.showinfo("Protocol Complete", "Oblivious Transfer protocol executed successfully!")
        except Exception as e:
            logging.error(f"Error during Sender execution: {e}")
            messagebox.showerror("Protocol Error", f"An error occurred during protocol execution: {e}")
        finally:
            self.set_gui_state(running=False)

    def set_gui_state(self, running):
        """Helper to enable/disable GUI elements based on running state."""
        self.is_running = running
        if running:
            self.start_button.config(state=tk.DISABLED)
            self.reset_button.config(state=tk.DISABLED)  # Disable reset while protocol runs
            self.msg0_entry.config(state=tk.DISABLED)
            self.msg1_entry.config(state=tk.DISABLED)
            self.host_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.bit_length_entry.config(state=tk.DISABLED)
            self.log_text.config(state='normal')  # Enable to clear
            self.log_text.delete(1.0, tk.END)
            self.log_text.config(state='disabled')  # Disable after clearing
        else:
            self.start_button.config(state=tk.NORMAL)
            self.reset_button.config(state=tk.NORMAL)  # Enable reset after protocol finishes/fails
            self.msg0_entry.config(state=tk.NORMAL)
            self.msg1_entry.config(state=tk.NORMAL)
            self.host_entry.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.NORMAL)
            self.bit_length_entry.config(state=tk.NORMAL)

    def reset_sender_gui(self):
        """Resets the GUI elements and internal state."""
        if self.is_running:
            messagebox.showwarning("Reset Warning", "Cannot reset while sender is active.")
            return

        logging.info("Resetting Sender GUI...")
        self.msg0_entry.delete(0, tk.END)
        self.msg0_entry.insert(0, "Secret Message Zero")
        self.msg1_entry.delete(0, tk.END)
        self.msg1_entry.insert(0, "Confidential Message One")
        self.host_entry.delete(0, tk.END)
        self.host_entry.insert(0, "127.0.0.1")
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, "65432")
        self.bit_length_entry.delete(0, tk.END)
        self.bit_length_entry.insert(0, "1024")

        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')

        self.sender_app = None  # Clear the sender logic instance
        self.set_gui_state(running=False)  # Ensure buttons are re-enabled


def start_gui():
    root = tk.Tk()
    app = SenderGUI(root)
    root.mainloop()


if __name__ == '__main__':
    start_gui()
