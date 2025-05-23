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


# Use the core Receiver logic
from src.receiver.receiver import Receiver


class ReceiverGUI:
    def __init__(self, master):
        self.master = master
        master.title("Oblivious Transfer Receiver")
        master.geometry("800x600")

        self.receiver_app = None  # Will hold the Receiver logic instance
        self.is_running = False

        # --- Frame for Inputs ---
        input_frame = ttk.LabelFrame(master, text="Choice & Configuration", padding="10 10 10 10")
        input_frame.pack(padx=10, pady=10, fill="x", expand=True)

        # Message Choice
        ttk.Label(input_frame, text="Choose Message:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.choice_var = tk.IntVar(value=0)  # Default to M0
        self.radio_m0 = ttk.Radiobutton(input_frame, text="M0", variable=self.choice_var, value=0)
        self.radio_m0.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.radio_m1 = ttk.Radiobutton(input_frame, text="M1", variable=self.choice_var, value=1)
        self.radio_m1.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        # Host and Port (Sender's address)
        ttk.Label(input_frame, text="Sender Host:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.host_entry = ttk.Entry(input_frame, width=20)
        self.host_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w", columnspan=2)
        self.host_entry.insert(0, "127.0.0.1")

        ttk.Label(input_frame, text="Sender Port:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.port_entry = ttk.Entry(input_frame, width=10)
        self.port_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w", columnspan=2)
        self.port_entry.insert(0, "65432")

        input_frame.columnconfigure(1, weight=1)  # Allow column 1 to expand

        # --- Action Buttons ---
        button_frame = ttk.Frame(master, padding="10 10 10 10")
        button_frame.pack(padx=10, pady=5, fill="x")

        self.start_button = ttk.Button(button_frame, text="Start Receiver", command=self.start_receiver_thread)
        self.start_button.pack(side="left", padx=5, expand=True, fill="x")

        self.reset_button = ttk.Button(button_frame, text="Reset", command=self.reset_receiver_gui, state=tk.DISABLED)
        self.reset_button.pack(side="left", padx=5, expand=True, fill="x")

        # --- Received Message Output ---
        result_frame = ttk.LabelFrame(master, text="Received Message", padding="10 10 10 10")
        result_frame.pack(padx=10, pady=10, fill="x", expand=True)

        self.received_message_label = ttk.Label(result_frame, text="No message received yet.", wraplength=750)
        self.received_message_label.pack(fill="x", expand=True)

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
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - Receiver - %(message)s',
                            stream=self.log_capture)

    def start_receiver_thread(self):
        """
        Starts the receiver process in a separate thread to keep the GUI responsive.
        """
        if self.is_running:
            messagebox.showwarning("Receiver Status", "Receiver is already running.")
            return

        host = self.host_entry.get()
        port_str = self.port_entry.get()
        chosen_index = self.choice_var.get()

        try:
            port = int(port_str)
            if not (1024 <= port <= 65535):
                raise ValueError("Port must be between 1024 and 65535.")
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid Port: {e}")
            return

        self.set_gui_state(running=True)

        logging.info(f"Attempting to start Receiver logic for message M{chosen_index}...")
        self.receiver_app = Receiver(host=host, port=port)
        self.receiver_app.set_choice(chosen_index)

        # Run the receiver logic in a separate thread
        self.receiver_thread = threading.Thread(target=self._run_receiver_logic, daemon=True)
        self.receiver_thread.start()

    def _run_receiver_logic(self):
        """
        Private method to run the Receiver's core logic. This runs in a separate thread.
        """
        try:
            self.receiver_app.start()
            received_msg = self.receiver_app.received_message
            logging.info(f"Receiver finished successfully. Message received: '{received_msg}'")
            self.received_message_label.config(text=f"RECEIVED MESSAGE: {received_msg}")
            messagebox.showinfo("Protocol Complete",
                                f"Oblivious Transfer protocol executed successfully!\nReceived: '{received_msg}'")
        except ConnectionRefusedError:
            error_msg = "Connection refused. Please ensure the Sender is running and accessible."
            logging.error(error_msg)
            messagebox.showerror("Connection Error", error_msg)
        except Exception as e:
            logging.error(f"Error during Receiver execution: {e}")
            self.received_message_label.config(text=f"ERROR: {e}")
            messagebox.showerror("Protocol Error", f"An error occurred during protocol execution: {e}")
        finally:
            self.set_gui_state(running=False)

    def set_gui_state(self, running):
        """Helper to enable/disable GUI elements based on running state."""
        self.is_running = running
        if running:
            self.start_button.config(state=tk.DISABLED)
            self.reset_button.config(state=tk.DISABLED)  # Disable reset while protocol runs
            self.radio_m0.config(state=tk.DISABLED)
            self.radio_m1.config(state=tk.DISABLED)
            self.host_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.log_text.config(state='normal')  # Enable to clear
            self.log_text.delete(1.0, tk.END)
            self.log_text.config(state='disabled')  # Disable after clearing
            self.received_message_label.config(text="Waiting for message...")
        else:
            self.start_button.config(state=tk.NORMAL)
            self.reset_button.config(state=tk.NORMAL)  # Enable reset after protocol finishes/fails
            self.radio_m0.config(state=tk.NORMAL)
            self.radio_m1.config(state=tk.NORMAL)
            self.host_entry.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.NORMAL)

    def reset_receiver_gui(self):
        """Resets the GUI elements and internal state."""
        if self.is_running:
            messagebox.showwarning("Reset Warning", "Cannot reset while receiver is active.")
            return

        logging.info("Resetting Receiver GUI...")
        self.choice_var.set(0)  # Default to M0
        self.host_entry.delete(0, tk.END)
        self.host_entry.insert(0, "127.0.0.1")
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, "65432")

        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')

        self.received_message_label.config(text="No message received yet.")
        self.receiver_app = None  # Clear the receiver logic instance
        self.set_gui_state(running=False)  # Ensure buttons are re-enabled


def start_gui():
    root = tk.Tk()
    app = ReceiverGUI(root)
    root.mainloop()


if __name__ == '__main__':
    start_gui()
