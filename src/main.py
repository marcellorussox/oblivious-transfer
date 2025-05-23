import subprocess
import os
import sys
import logging
import platform  # To handle OS-specific commands for opening new windows

# Configure basic logging for the main script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - Main - %(message)s')


def run_component(component_path, use_new_window=False):
    """
    Launches a Python script as a separate process.
    Args:
        component_path (str): The path to the Python script to run.
        use_new_window (bool): If True, attempts to open the process in a new terminal window.
    """
    cmd = [sys.executable, component_path]

    if use_new_window:
        if platform.system() == "Darwin":  # macOS
            # On macOS, `open -a Terminal` can launch in a new terminal.
            # We wrap the python command in a shell command.
            # This is a bit tricky with `subprocess.Popen` without `shell=True`.
            # A simpler way for GUIs is that they open their own window.
            # For console, we can still try:
            # os.system(f'open -a Terminal "{sys.executable}" "{component_path}"')
            # However, Popen is generally preferred for control.
            # Let's keep it simple for `Popen` for now, as GUIs manage their own windows.
            # If not GUI, the output will go to the console where main.py runs, or background.
            pass  # GUIs will handle their own windows, console versions will run in background/current.
        elif platform.system() == "Windows":
            # On Windows, `start` command opens a new command prompt.
            # `creationflags=subprocess.CREATE_NEW_CONSOLE` is often better for Popen.
            # For GUIs, `Popen` will just launch the window.
            logging.warning(
                "Note: `start` command for new console on Windows is not robust with `Popen` alone. GUI windows will open naturally.")
        else:  # Linux/other Unix-like
            # xterm, gnome-terminal, konsole etc., but requires checking if installed
            # e.g., subprocess.Popen(['xterm', '-e', sys.executable, component_path])
            pass  # Same as macOS, GUIs manage own windows.

    try:
        logging.info(f"Launching {component_path}...")
        # For GUIs, Popen directly starts the window.
        # For console processes, output might go to the same console or background,
        # depending on OS and how the child process handles stdin/stdout.
        process = subprocess.Popen(cmd)
        return process
    except FileNotFoundError:
        logging.error(f"Error: Python executable not found. Make sure Python is installed and in your PATH.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to launch {component_path}: {e}")
        sys.exit(1)


def main():
    """
    Main function to provide options for running the Sender or Receiver.
    """
    print("\n--- Oblivious Transfer Protocol ---")
    print("Choose which component to launch:")
    print("1. Sender (Console)")
    print("2. Receiver (Console)")
    print("3. Sender (GUI)")
    print("4. Receiver (GUI)")
    print("5. Launch Both GUIs")
    print("6. Exit")

    choice = input("Enter your choice (1/2/3/4/5/6): ").strip()

    # Construct paths relative to the current script's directory
    script_dir = os.path.dirname(__file__)

    # Console versions
    sender_console_path = os.path.join(script_dir, "sender", "sender.py")
    receiver_console_path = os.path.join(script_dir, "receiver", "receiver.py")

    # GUI versions
    sender_gui_path = os.path.join(script_dir, "sender", "sender_gui.py")
    receiver_gui_path = os.path.join(script_dir, "receiver", "receiver_gui.py")

    processes = []

    if choice == '1':
        logging.info("Launching Sender (Console)...")
        print("\nNOTE: You will need to manually interact with the Sender's console for messages.")
        processes.append(run_component(sender_console_path))
    elif choice == '2':
        logging.info("Launching Receiver (Console)...")
        print("\nNOTE: You will need to manually interact with the Receiver's console for choice.")
        processes.append(run_component(receiver_console_path))
    elif choice == '3':
        logging.info("Launching Sender (GUI)...")
        processes.append(run_component(sender_gui_path, use_new_window=True))
    elif choice == '4':
        logging.info("Launching Receiver (GUI)...")
        processes.append(run_component(receiver_gui_path, use_new_window=True))
    elif choice == '5':
        logging.info("Launching both Sender and Receiver GUIs.")
        print("\nNOTE: Two separate GUI windows will open for Sender and Receiver.")
        processes.append(run_component(sender_gui_path, use_new_window=True))
        processes.append(run_component(receiver_gui_path, use_new_window=True))
    elif choice == '6':
        logging.info("Exiting.")
        sys.exit(0)
    else:
        print("Invalid choice. Please enter 1, 2, 3, 4, 5, or 6.")
        main()  # Loop back if invalid input

    # For GUI applications, main.py usually just launches them and exits,
    # as the GUI applications manage their own event loops.
    # For console applications, if we wanted to keep them bound to main.py's
    # lifecycle, we'd add p.wait() for each process.
    # Given the independent process requirement, launching and letting them run
    # independently is appropriate.
    print("\nProcess(es) launched. Close the terminal windows to exit.")


if __name__ == '__main__':
    main()
