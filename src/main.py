import subprocess
import os
import sys
import logging
import platform

# Configure basic logging for the main script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - Main - %(message)s')

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)


def run_component(module_name, use_new_window=False, is_gui=False): # Added is_gui parameter
    """
    Launches a Python module as a separate process using 'python -m'.
    Args:
        module_name (str): The Python module path (e.g., 'src.sender.sender_gui').
        use_new_window (bool): If True, attempts to open the process in a new terminal window
                                (primarily for console apps).
        is_gui (bool): If True, indicates this is a GUI application, which affects
                       how 'use_new_window' is handled.
    Returns:
        subprocess.Popen: The Popen object for the launched process.
    """
    cmd = [sys.executable, '-m', module_name]
    launch_cwd = project_root

    if use_new_window and not is_gui: # Only use new terminal window for non-GUI applications
        # These are commands to open a NEW TERMINAL and run the script inside it.
        # This is suitable for console applications (options 1, 2)
        if platform.system() == "Darwin":  # macOS
            bash_command_string = f"cd {launch_cwd} && \"{sys.executable}\" -m {module_name} ; read -p 'Press Enter to close this terminal...' ENTER_KEY"
            full_cmd = ['open', '-W', '-a', 'Terminal', '--args', 'bash', '-c', bash_command_string]
            logging.info(f"Launching console app {module_name} in new macOS Terminal window.")
            process = subprocess.Popen(full_cmd)
        elif platform.system() == "Windows":  # Windows
            full_cmd = ['start', 'cmd', '/k',
                        f"cd /d \"{launch_cwd}\" && \"{sys.executable}\" -m {module_name}"]
            logging.info(f"Launching console app {module_name} in new Windows Command Prompt window.")
            process = subprocess.Popen(full_cmd, shell=True)
        elif platform.system() == "Linux":  # Linux
            full_cmd = ['gnome-terminal', '--', 'bash', '-c',
                        f"cd \"{launch_cwd}\" && \"{sys.executable}\" -m {module_name} ; read -p 'Press Enter to close this terminal...'"]
            logging.info(f"Launching console app {module_name} in new Linux Terminal window.")
            process = subprocess.Popen(full_cmd)
        else:
            logging.warning("New window launch not specifically supported on this OS for console apps. Launching in current console context.")
            process = subprocess.Popen(cmd, cwd=launch_cwd)
    else:
        # This branch handles:
        # 1. GUI applications (is_gui=True, use_new_window=True): They launch their own graphical window.
        #    We just run the Python script directly, not inside a new terminal.
        #    stdout/stderr from the GUI would still go to the main terminal, but the GUI window will appear.
        # 2. Console applications (use_new_window=False): They run in the current console (mixed output).
        #    This is the original behavior for console apps.
        # For GUIs, we'll pipe stdout/stderr to DEVNULL to suppress messages in the main console
        # if the GUI itself logs extensively to stdout.
        if is_gui:
            logging.info(f"Launching GUI {module_name}. GUI window should appear shortly.")
            process = subprocess.Popen(cmd, cwd=launch_cwd,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) # Suppress GUI output
        else: # This is for console apps *not* launched in a new window (e.g., if use_new_window=False was chosen for them)
            logging.info(f"Launching {module_name} in current console.")
            process = subprocess.Popen(cmd, cwd=launch_cwd)

    return process


def main():
    processes = []
    try:
        while True:
            print("\n--- Oblivious Transfer Protocol ---")
            print("Choose which component to launch:")
            print("1. Sender (Console)")
            print("2. Receiver (Console)")
            print("3. Sender (GUI)")
            print("4. Receiver (GUI)")
            print("5. Launch Both GUIs")
            print("6. Exit")

            choice = input("Enter your choice (1/2/3/4/5/6): ").strip()

            sender_console_module = 'src.sender.sender'
            receiver_console_module = 'src.receiver.receiver'
            sender_gui_module = 'src.sender.sender_gui'
            receiver_gui_module = 'src.receiver.receiver_gui'

            if choice == '1':
                logging.info("Launching Sender (Console)...")
                print("\nNOTE: A new console window will open for Sender interaction.")
                processes.append(run_component(sender_console_module, use_new_window=True, is_gui=False))
            elif choice == '2':
                logging.info("Launching Receiver (Console)...")
                print("\nNOTE: A new console window will open for Receiver interaction.")
                processes.append(run_component(receiver_console_module, use_new_window=True, is_gui=False))
            elif choice == '3':
                logging.info("Launching Sender (GUI)...")
                processes.append(run_component(sender_gui_module, use_new_window=True, is_gui=True)) # Mark as GUI
            elif choice == '4':
                logging.info("Launching Receiver (GUI)...")
                processes.append(run_component(receiver_gui_module, use_new_window=True, is_gui=True)) # Mark as GUI
            elif choice == '5':
                logging.info("Launching both Sender and Receiver GUIs.")
                print("\nNOTE: Two separate GUI windows will open for Sender and Receiver.")
                processes.append(run_component(sender_gui_module, use_new_window=True, is_gui=True)) # Mark as GUI
                processes.append(run_component(receiver_gui_module, use_new_window=True, is_gui=True)) # Mark as GUI
            elif choice == '6':
                logging.info("Exiting.")
                break
            else:
                print("Invalid choice. Please enter 1, 2, 3, 4, 5, or 6.")

            if processes and choice in ['1', '2', '3', '4', '5']:
                print("\nProcess(es) launched. Close the terminal window(s) to exit them, or press Ctrl+C here to terminate all.")

    except KeyboardInterrupt:
        logging.info("Ctrl+C detected. Terminating all launched processes.")
    finally:
        for p in processes:
            if p.poll() is None:
                logging.info(f"Terminating process {p.pid}...")
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.warning(f"Process {p.pid} did not terminate gracefully, killing it.")
                    p.kill()
                    p.wait(timeout=2)
        logging.info("All processes terminated.")


if __name__ == '__main__':
    main()