import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import threading
import queue
import socket
import serial # For USB/Serial communication
import serial.tools.list_ports # For listing serial ports
import nmap # For network scanning (requires Nmap installed on system)
import ssl # For potential SSL/TLS connections (requires specific implementation)
import time # Added time for potential small sleep in receiver loop
import errno # To check socket errors like EWOULDBLOCK
# import subprocess # Might be needed for platform-specific Wi-Fi scanning commands
# import your_wifi_library # e.g., import pywifi # You might need a library like this

# --- Connection Functions (Actual Implementations for USB/Network, Placeholder for Bluetooth/Wi-Fi) ---

def connect_to_bluetooth(address, port_str):
    """
    Connects to a Bluetooth device.
    REPLACE the code inside this function with your actual Bluetooth connection logic.

    Args:
        address (str): The Bluetooth address of the device (e.g., MAC address).
        port_str (str): The port number (as a string). This might be the channel ID or RFCOMM port.

    Returns:
        object: Return the connection object (e.g., socket) on success.
                Return None or raise Exception on failure.

    Raises:
        Exception: Raise an Exception if the connection fails for any reason.
    """
    print(f"Attempting Bluetooth connection to {address}:{port_str}")
    # --- START: REPLACE THIS SECTION WITH YOUR ACTUAL BLUETOOTH CONNECTION CODE ---
    # Bluetooth implementation is highly platform-dependent in Python.
    # You will likely need to install a specific library:
    # - For Windows: You might need to use a library like 'pybluez' (can be tricky to install)
    #                or potentially interact with Windows APIs.
    # - For Linux: 'python-bluetooth' is a common option.
    # - For macOS: Bluetooth support in Python can be limited or require platform-specific tools.
    #
    # Example structure (using hypothetical library calls):
    # import your_bluetooth_library # e.g., import bluetooth
    # try:
    #     # Convert port string to integer if your library requires it (often for RFCOMM channels)
    #     port = int(port_str)
    #     # Replace with your library's connection call. This varies greatly by library.
    #     # Example using a hypothetical socket-like approach:
    #     # bluetooth_socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    #     # bluetooth_socket.settimeout(1.0) # IMPORTANT: Set a timeout for reading!
    #     # bluetooth_socket.connect((address, port))
    #     # print("Bluetooth connection successful.")
    #     # return bluetooth_socket # Return the connection object
    #
    # except ValueError:
    #     raise ValueError(f"Invalid port number for Bluetooth: '{port_str}'")
    # except your_bluetooth_library.BluetoothError as e: # Catch specific Bluetooth errors
    #     raise Exception(f"Bluetooth connection failed: {e}")
    # except Exception as e:
    #     # Catch any other potential errors during connection
    #     raise Exception(f"An unexpected error occurred during Bluetooth connection: {e}")

    # Placeholder raising NotImplementedError if you haven't added your code yet
    raise NotImplementedError("Bluetooth connection logic not implemented. Replace this with your code using a platform-specific library.")

    # --- END: REPLACE THIS SECTION WITH YOUR ACTUAL BLUETOOTH CONNECTION CODE ---


def connect_to_usb(port_name):
    """
    Connects to a USB device (typically via Serial) using pyserial.

    Args:
        port_name (str): The name of the serial port (e.g., 'COM1', '/dev/ttyUSB0').

    Returns:
        serial.Serial: Return the serial.Serial instance on success.
                       Return None or raise Exception on failure.

    Raises:
        Exception: Raise an Exception if the connection fails for any reason.
    """
    print(f"Attempting USB connection to port {port_name}")
    # --- START: ACTUAL USB/SERIAL CONNECTION CODE (using pyserial) ---

    try:
        # Replace with your desired serial port settings (baudrate, timeout, etc.)
        # Common baudrates: 9600, 19200, 38400, 57600, 115200
        # timeout=1 means read calls will block for at most 1 second. This is important!
        ser = serial.Serial(port_name, baudrate=9600, timeout=1) # Ensure timeout is set
        print(f"Opened serial port {port_name}")
        return ser # Return the serial port object
    except serial.SerialException as e:
         # Catch specific serial port errors (e.g., port not found, permission denied)
         raise Exception(f"Failed to open serial port {port_name}: {e}")
    except Exception as e:
        # Catch any other potential errors during connection
        raise Exception(f"An unexpected error occurred during USB connection: {e}")

    # --- END: ACTUAL USB/SERIAL CONNECTION CODE ---


def connect_to_network(address, port_str):
    """
    Connects to a network device via TCP/IP using Python's socket library.

    Args:
        address (str): The IP address or hostname of the device.
        port_str (str): The port number (as a string).

    Returns:
        socket.socket: Return the socket object on success. Return None or raise Exception on failure.
        ssl.SSLSocket: Return the SSL socket object if using SSL/TLS.

    Raises:
        Exception: Raise an Exception if the connection fails for any reason.
    """
    print(f"Attempting Network connection to {address}:{port_str}")
    # --- START: ACTUAL NETWORK CONNECTION CODE (using socket) ---

    try:
        port = int(port_str) # Convert port string to integer
        if not (0 < port < 65536):
             raise ValueError("Port number out of valid range")

        # Create a TCP socket
        network_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # IMPORTANT: Set a timeout for both connection and subsequent reads
        network_socket.settimeout(5) # Set a timeout for the connection attempt (in seconds)

        print(f"Connecting to {address}:{port}... (Timeout: 5s)")
        network_socket.connect((address, port)) # Connect to the address and port

        # Set a timeout for reading data after connection. Adjust as needed.
        # A small timeout (e.g., 0.1 to 1 second) is crucial for the receiver thread
        # to be able to check the stop flag periodically without blocking too long.
        network_socket.settimeout(0.5) # Set timeout for reads

        print(f"Network connection successful to {address}:{port}")

        # --- START: OPTIONAL SSL/TLS WRAPPER ---
        # If you need to establish an SSL/TLS connection on top of the TCP socket,
        # uncomment and implement the following section.
        # You will need to handle certificates, protocols, etc.
        # try:
        #     # Create an SSL context (adjust settings as needed for your application)
        #     # ssl.Purpose.SERVER_AUTH is for verifying the server's certificate
        #     ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        #     # If you have specific CA certificates to trust, load them:
        #     # ssl_context.load_verify_locations(cafile="path/to/ca.crt")
        #     # If the client needs to present a certificate for mutual authentication:
        #     # ssl_context.load_cert_chain(certfile="path/to/client.crt", keyfile="path/to/client.key")
        #
        #     print("Wrapping socket with SSL/TLS...")
        #     # server_hostname is used for certificate verification (should match the certificate)
        #     ssl_socket = ssl_context.wrap_socket(network_socket, server_hostname=address)
        #     # Perform the SSL handshake
        #     ssl_socket.do_handshake()
        #     print("SSL/TLS handshake successful.")
        #     # IMPORTANT: Set a timeout on the SSL socket as well for reading
        #     ssl_socket.settimeout(0.5) # Set timeout for reads on SSL socket
        #     return ssl_socket # Return the SSL socket
        # except ssl.SSLError as e:
        #     # Handle SSL/TLS specific errors
        #     network_socket.close() # Close the underlying socket
        #     raise Exception(f"SSL/TLS connection failed: {e}")
        # except Exception as e:
        #     # Catch any other errors during SSL wrapping
        #     network_socket.close()
        #     raise Exception(f"An unexpected error occurred during SSL/TLS wrap: {e}")
        # --- END: OPTIONAL SSL/TLS WRAPPER ---


        return network_socket # Return the plain TCP socket if not using SSL/TLS

    except ValueError:
        raise ValueError(f"Invalid port number: '{port_str}'")
    except socket.gaierror:
         raise Exception(f"Network connection failed: Address or hostname '{address}' not found.")
    except ConnectionRefusedError:
         raise Exception(f"Network connection failed: Connection refused by {address}:{port}.")
    except socket.timeout:
         # This catches the timeout during the connect() call
         raise Exception(f"Network connection failed: Connection timed out to {address}:{port}.")
    except Exception as e:
        # Catch any other potential errors during connection
        raise Exception(f"An unexpected error occurred during Network connection: {e}")

    # --- END: ACTUAL NETWORK CONNECTION CODE ---

# Note: Wi-Fi Scan is a detection feature, not a direct connection type like the above.
# There is no 'connect_to_wifi_scan' function needed in the same way.


# --- Detection Functions (Actual Implementations for USB/Network, Placeholder for Bluetooth/Wi-Fi) ---

def detect_bluetooth_devices():
    """
    Detects available Bluetooth devices.
    REPLACE the code inside this function with your actual Bluetooth scanning logic.

    Returns:
        list: A list of detected device identifiers (e.g., tuples of (name, address, port)).
              Return an empty list if no devices are found or detection fails.
              The 'port' might be a default port or a discovered service port.
    Raises:
        Exception: Raise an Exception if detection fails.
    """
    print("Attempting Bluetooth device detection...")
    # --- START: REPLACE THIS SECTION WITH YOUR ACTUAL BLUETOOTH DETECTION CODE ---
    # Bluetooth implementation is highly platform-dependent in Python.
    # You will likely need to install a specific library:
    # - For Windows: You might need to use a library like 'pybluez' (can be tricky to install)
    #                or potentially interact with Windows APIs.
    # - For Linux: 'python-bluetooth' is a common option.
    # - For macOS: Bluetooth support in Python can be limited or require platform-specific tools.
    #
    # Example structure (using hypothetical library calls):
    # import your_bluetooth_library # e.g., import bluetooth
    # try:
    #     # Replace with your library's discovery call. This varies greatly.
    #     # The format of returned devices also varies. Aim for a list of tuples
    #     # like (name, address, default_port).
    #     # Example: devices = bluetooth.discover_devices(lookup_names=True)
    #     # You might then need to find services on each device to get a port/channel.
    #     # Example: services = bluetooth.find_service(address=device_address)
    #     # detected_list = [(name, address, service.port) for name, address in devices for service in services if 'RFCOMM' in service.protocol]
    #     # print(f"Detected Bluetooth devices: {detected_list}")
    #     # return detected_list
    #
    # except your_bluetooth_library.BluetoothError as e: # Catch specific Bluetooth errors
    #     raise Exception(f"Bluetooth detection failed: {e}")
    # except Exception as e:
    #     # Catch any other potential errors during detection
    #     raise Exception(f"An unexpected error occurred during Bluetooth detection: {e}")

    # Placeholder raising NotImplementedError if you haven't added your code yet
    raise NotImplementedError("Bluetooth detection logic not implemented. Replace this with your code using a platform-specific library.")

    # --- END: REPLACE THIS SECTION WITH YOUR ACTUAL BLUETOOTH DETECTION CODE ---


def detect_usb_ports():
    """
    Detects available USB Serial ports using pyserial.

    Returns:
        list: A list of available serial port names (e.g., ['COM1', '/dev/ttyUSB0']).
              Return an empty list if no ports is found or detection fails.
    Raises:
        Exception: Raise an Exception if detection fails.
    """
    print("Attempting USB port detection (using pyserial)...")
    # --- START: ACTUAL USB/SERIAL DETECTION CODE (using pyserial) ---

    try:
        # Use serial.tools.list_ports to get a list of available ports
        ports = [port.device for port in serial.tools.list_ports.comports()]
        print(f"Detected USB ports: {ports}")
        return ports # Return a list of port names
    except Exception as e:
        # Catch any errors during port listing
        raise Exception(f"USB port detection failed: {e}")

    # --- END: ACTUAL USB/SERIAL DETECTION CODE ---

def detect_network_devices(network_range, scan_ports):
    """
    Detects available network devices using Nmap via python-nmap.
    Requires Nmap to be installed and accessible in the system's PATH.

    Args:
        network_range (str): The target network range (e.g., '192.168.1.0/24', '10.0.0.1-254').
        scan_ports (str): The ports to scan (e.g., '20-100', '80,443,8080').

    Returns:
        list: A list of detected device identifiers (e.g., tuples of (ip_address, open_ports_list)).
              Return an empty list if no devices are found or detection fails.
    Raises:
        Exception: Raise an Exception if detection fails (e.g., Nmap not found, scan error).
    """
    print(f"Attempting Network device detection (using Nmap via python-nmap) on {network_range} ports {scan_ports}...")
    # --- START: ACTUAL NETWORK DETECTION CODE (using python-nmap) ---

    if not network_range:
        raise ValueError("Network range cannot be empty for scanning.")
    # No need to check scan_ports here, python-nmap handles empty port lists

    try:
        nm = nmap.PortScanner()
        # Perform the scan. Arguments can be adjusted based on needs (e.g., '-sT' for TCP connect scan)
        # '-n' avoids reverse DNS lookup, which can speed up the scan.
        # '-T4' is a common timing template for faster execution.
        # For more detailed scans, you might add arguments like '-sV' for service version detection.
        arguments = f'-n -T4 -p {scan_ports}' if scan_ports else '-n -T4' # Add -p if ports are specified
        print(f"Running Nmap scan with arguments: {arguments}")
        nm.scan(hosts=network_range, arguments=arguments)

        detected = []
        for host in nm.all_hosts():
            # Check if the host is reported as 'up' by Nmap
            if nm[host].state() == 'up':
                open_ports = []
                # Check TCP ports (Nmap can scan other protocols too, like UDP)
                if 'tcp' in nm[host]:
                    for port in nm[host]['tcp']:
                        if nm[host]['tcp'][port]['state'] == 'open':
                            open_ports.append(port)
                # Add other protocols if needed (UDP etc.)
                # if 'udp' in nm[host]:
                #     for port in nm[host]['udp']:
                #         if nm[host]['udp'][port]['state'] == 'open':
                #              open_ports.append(port)

                # Append the host IP and its list of open ports if any ports were open
                # Or append if you want to list all 'up' hosts regardless of open ports,
                # you would remove the 'if open_ports:' check.
                if open_ports:
                     detected.append((host, open_ports)) # Store IP and list of open ports

        print(f"Detected Network devices: {detected}")
        return detected

    except nmap.PortScannerError as e:
        # Catch errors specifically from the nmap.PortScanner
        raise Exception(f"Nmap scan failed: {e}. Make sure Nmap is installed and in your system's PATH.")
    except Exception as e:
        # Catch any other potential errors during the scan process
        raise Exception(f"An unexpected error occurred during Network detection: {e}")

    # --- END: ACTUAL NETWORK DETECTION CODE ---

def scan_wifi_networks():
    """
    Scans for available Wi-Fi networks (SSIDs).
    REPLACE the code inside this function with your actual Wi-Fi scanning logic.

    Returns:
        list: A list of detected network identifiers (e.g., tuples of (ssid, bssid, channel, security)).
              Return an empty list if no networks are found or scanning fails.
    Raises:
        Exception: Raise an Exception if scanning fails.
    """
    print("Attempting Wi-Fi network scanning...")
    # --- START: REPLACE THIS SECTION WITH YOUR ACTUAL WI-FI SCANNING CODE ---
    # Wi-Fi scanning is highly platform-dependent and often requires elevated privileges.
    # You will likely need to use:
    # - A library like 'pywifi' (cross-platform, but might require system dependencies)
    # - Subprocess calls to system commands:
    #   - Windows: `netsh wlan show networks mode=ssid` or `netsh wlan show networks mode=bssid`
    #   - Linux: `iwlist <interface> scan` (requires wireless-tools) or `nmcli device wifi list` (requires NetworkManager)
    #   - macOS: `airport -s` (usually in /System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/)
    #
    # Example using subprocess (Windows `netsh`):
    # import subprocess
    # try:
    #     # Run the command and capture output
    #     # check=True will raise CalledProcessError if the command returns a non-zero exit code
    #     result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], capture_output=True, text=True, check=True)
    #     output = result.stdout
    #     print(f"netsh output:\n{output}")
    #     # --- Parse the output ---
    #     # This parsing logic is complex and depends heavily on the command output format.
    #     # You'll need to write code to extract SSID, BSSID, Channel, Authentication, etc.
    #     detected_list = []
    #     current_network = {}
    #     for line in output.splitlines():
    #         line = line.strip()
    #         if line.startswith("SSID"):
    #             if current_network: # Save previous network if exists
    #                 detected_list.append(current_network)
    #             current_network = {'ssid': line.split(":", 1)[1].strip()}
    #         elif line.startswith("BSSID"):
    #             current_network['bssid'] = line.split(":", 1)[1].strip()
    #         elif line.startswith("Channel"):
    #             current_network['channel'] = line.split(":", 1)[1].strip()
    #         elif line.startswith("Authentication"):
    #              current_network['security'] = line.split(":", 1)[1].strip()
    #         # Add more parsing for other relevant fields
    #     if current_network: # Add the last network
    #          detected_list.append(current_network)
    #
    #     # The formatted list for the combobox will be created in _detect_devices_thread
    #     print(f"Parsed Wi-Fi networks (raw): {detected_list}")
    #     return detected_list # Return raw data, format in _detect_devices_thread
    #
    # except subprocess.CalledProcessError as e:
    #     # This includes cases where the command requires admin privileges and isn't run as admin
    #     raise Exception(f"netsh command failed: {e}\nOutput: {e.stdout}\nError: {e.stderr}. You might need to run the script as administrator.")
    # except FileNotFoundError:
    #     raise Exception("netsh command not found. Make sure it's in your system's PATH.")
    # except Exception as e:
    #     raise Exception(f"An unexpected error occurred during Wi-Fi scan: {e}")


    # Placeholder raising NotImplementedError if you haven't added your code yet
    raise NotImplementedError("Wi-Fi scanning logic not implemented. Replace this with your code using a platform-specific method.")

    # --- END: REPLACE THIS SECTION WITH YOUR ACTUAL WI-FI SCANNING CODE ---


# --- MultiConnectGUI Class ---
class MultiConnectGUI:
    def __init__(self, master):
        self.master = master
        master.title("Multi-Device Connector")

        self.is_connected = False
        self.active_connection = None # Stores the connection object (e.g., serial.Serial, socket, ssl.SSLSocket)
        self.connection_thread = None # Thread for connect/disconnect/detection operations
        self.receiver_thread = None # Thread for receiving data
        self.receive_queue = queue.Queue() # Queue for data received by the receiver thread

        # Flag to signal the receiver thread to stop
        self._stop_receiver_flag = threading.Event()


        self.create_widgets()

        # --- Create and place the status bar ---
        # Placed below all other main content frames
        status_bar_row = 10 # Adjust this row number if needed based on your layout
        self.status_label = tk.Label(
            self.master,
            text="Status: Disconnected",
            bd=1, relief=tk.SUNKEN, anchor=tk.W
        )
        # Spans across all main columns
        self.status_label.grid(
            row=status_bar_row, column=0, columnspan=3, padx=0, pady=0, sticky="ew"
        )

        # --- Configure grid weights for the main window ---
        # This tells the grid how to resize columns/rows when the window resizes.
        # Columns 0, 1, and 2 get weight 1, so they share horizontal expansion space.
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_columnconfigure(1, weight=1)
        self.master.grid_columnconfigure(2, weight=1)
        # Row 0 (containing type/settings/detection frames) gets weight 1 so it expands vertically.
        self.master.grid_rowconfigure(0, weight=1)
        # Row 1 (control buttons) and status_bar_row should NOT expand vertically
        self.master.grid_rowconfigure(1, weight=0)
        self.master.grid_rowconfigure(status_bar_row, weight=0)


        # Set initial button states
        # Call _on_connection_type_change first to set up the initial UI state correctly
        self._on_connection_type_change()
        self._update_button_states()


        # Set a protocol handler for when the window is closed
        self.master.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Start checking the receive queue periodically
        self._check_receive_queue()


    def create_widgets(self):
        # --- Main Layout Frames (using grid) ---
        type_frame = ttk.LabelFrame(self.master, text="Connection Type")
        type_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")

        settings_frame = ttk.LabelFrame(self.master, text="Settings")
        settings_frame.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")

        # Frame for Auto-Detection and Network Scan Range
        detection_frame = ttk.LabelFrame(self.master, text="Device Detection / Scan")
        detection_frame.grid(row=0, column=2, padx=10, pady=5, sticky="nsew") # Placed in column 2

        control_frame = ttk.Frame(self.master)
        control_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=5, sticky="ew") # Spans all 3 columns

        # Frame for Communications IO
        self.io_frame = ttk.LabelFrame(self.master, text="Communications I/O")
        # Initially hidden, will be gridded when connected
        # self.io_frame.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")


        # --- Widgets inside type_frame (using pack) ---
        self.connection_type_var = tk.StringVar(value="Bluetooth")
        self.bluetooth_radio = ttk.Radiobutton(type_frame, text="Bluetooth", variable=self.connection_type_var, value="Bluetooth")
        self.usb_radio = ttk.Radiobutton(type_frame, text="USB", variable=self.connection_type_var, value="USB")
        self.network_radio = ttk.Radiobutton(type_frame, text="Network (IP/Port)", variable=self.connection_type_var, value="Network") # Clarified Network type
        self.wifi_scan_radio = ttk.Radiobutton(type_frame, text="Wi-Fi Scan (SSID)", variable=self.connection_type_var, value="WiFi Scan") # Added Wi-Fi Scan radio button

        self.bluetooth_radio.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=2)
        self.usb_radio.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=2)
        self.network_radio.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=2)
        self.wifi_scan_radio.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=2) # Pack Wi-Fi Scan radio button

        # Bind radio button changes to update settings fields and detection options
        self.connection_type_var.trace_add("write", self._on_connection_type_change)


        # --- Widgets inside settings_frame (using grid) ---
        ttk.Label(settings_frame, text="Address:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.address_entry = ttk.Entry(settings_frame)
        self.address_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(settings_frame, text="Port:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.port_entry = ttk.Entry(settings_frame)
        self.port_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)

        settings_frame.grid_columnconfigure(1, weight=1)


        # --- Widgets inside detection_frame (using grid) ---
        # Input for Network Scan Range (only visible for Network type)
        self.network_range_label = ttk.Label(detection_frame, text="Network Range:")
        self.network_range_entry = ttk.Entry(detection_frame)
        self.network_range_entry.insert(0, "192.168.1.0/24") # Default example range

        # Input for Ports to Scan (only visible for Network type)
        self.scan_ports_label = ttk.Label(detection_frame, text="Scan Ports:")
        self.scan_ports_entry = ttk.Entry(detection_frame)
        self.scan_ports_entry.insert(0, "20-100,443,8080") # Default example ports

        # Input for Wi-Fi Interface (only visible for Wi-Fi Scan type)
        self.wifi_interface_label = ttk.Label(detection_frame, text="Wi-Fi Interface:")
        self.wifi_interface_entry = ttk.Entry(detection_frame)
        self.wifi_interface_entry.insert(0, "wlan0") # Example default interface (adjust for your OS)


        # Button to trigger detection
        self.detect_button = ttk.Button(detection_frame, text="Detect Devices", command=self._start_detection_thread)
        # This button will be gridded dynamically based on the selected type

        # Combobox to display detected devices
        ttk.Label(detection_frame, text="Detected:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.detected_devices_combobox = ttk.Combobox(detection_frame, state="readonly")
        self.detected_devices_combobox.grid(row=3, column=1, padx=5, pady=2, sticky="ew")
        # Bind combobox selection to update settings fields
        self.detected_devices_combobox.bind("<<ComboboxSelected>>", self._on_device_selected)

        # Configure detection_frame columns to expand
        detection_frame.grid_columnconfigure(1, weight=1)


        # --- Widgets inside control_frame (using pack) ---
        self.connect_button = ttk.Button(control_frame, text="Connect", command=self._start_connection_thread)
        self.disconnect_button = ttk.Button(control_frame, text="Disconnect", command=self._start_disconnection_thread)

        self.connect_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.disconnect_button.pack(side=tk.LEFT, padx=5, pady=5)


        # --- Widgets inside io_frame (using grid) ---
        # Text widget for receiving data
        self.receive_text = tk.Text(self.io_frame, wrap=tk.WORD, state=tk.DISABLED, width=60, height=15)
        self.receive_text.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        # Scrollbar for the text widget
        receive_scrollbar = ttk.Scrollbar(self.io_frame, command=self.receive_text.yview)
        receive_scrollbar.grid(row=0, column=2, sticky="ns")
        self.receive_text['yscrollcommand'] = receive_scrollbar.set

        # Entry for sending data
        self.send_entry = ttk.Entry(self.io_frame, state=tk.DISABLED)
        self.send_entry.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        self.send_entry.bind("<Return>", lambda event=None: self._send_data()) # Send on Enter key

        # Button to send data
        self.send_button = ttk.Button(self.io_frame, text="Send", command=self._send_data, state=tk.DISABLED)
        self.send_button.grid(row=1, column=1, padx=5, pady=5)

        # Configure io_frame grid weights
        self.io_frame.grid_columnconfigure(0, weight=1)
        self.io_frame.grid_rowconfigure(0, weight=1)

        # Initial call to set up the detection frame based on default type
        self._on_connection_type_change()


    def update_status(self, message):
        """Updates the status label with the given message and prints to console."""
        # Use after() to update GUI from a separate thread safely
        # This is crucial because update_status can be called from the connection/disconnection/detection threads
        self.master.after(0, lambda: self.status_label.config(text=f"Status: {message}"))
        print(f"Status: {message}")


    def _update_button_states(self):
        """Enables/disables buttons and inputs based on connection status. Called from GUI thread."""
        selected_type = self.connection_type_var.get()

        if self.is_connected:
            self.connect_button.config(state=tk.DISABLED)
            self.disconnect_button.config(state=tk.NORMAL)
            self.detect_button.config(state=tk.DISABLED) # Disable detect when connected
            self.detected_devices_combobox.config(state=tk.DISABLED) # Disable combobox when connected
            self.network_range_entry.config(state=tk.DISABLED) # Disable network range entry
            self.scan_ports_entry.config(state=tk.DISABLED) # Disable scan ports entry
            self.wifi_interface_entry.config(state=tk.DISABLED) # Disable wifi interface entry


            # Disable entry fields and radio buttons when connected
            self.address_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.bluetooth_radio.config(state=tk.DISABLED)
            self.usb_radio.config(state=tk.DISABLED)
            self.network_radio.config(state=tk.DISABLED)
            self.wifi_scan_radio.config(state=tk.DISABLED)


            # Enable IO widgets when connected
            self.receive_text.config(state=tk.NORMAL) # Enable text widget for writing
            self.send_entry.config(state=tk.NORMAL)
            self.send_button.config(state=tk.NORMAL)

            # Grid the IO frame if not already visible
            if not self.io_frame.winfo_ismapped():
                 self.io_frame.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")


        else: # Not connected
            self.connect_button.config(state=tk.NORMAL)
            self.disconnect_button.config(state=tk.DISABLED)
            self.detect_button.config(state=tk.NORMAL) # Enable detect when disconnected
            self.detected_devices_combobox.config(state="readonly") # Enable combobox

            # Enable entry fields and radio buttons based on selected type
            self.bluetooth_radio.config(state=tk.NORMAL)
            self.usb_radio.config(state=tk.NORMAL)
            self.network_radio.config(state=tk.NORMAL)
            self.wifi_scan_radio.config(state=tk.NORMAL)

            # Note: We no longer call _on_connection_type_change here to avoid recursion.
            # The _on_connection_type_change method is responsible for setting
            # the state of the type-specific entry fields when the radio button changes.


            # Disable IO widgets when disconnected
            self.receive_text.config(state=tk.DISABLED)
            self.send_entry.config(state=tk.DISABLED)
            self.send_button.config(state=tk.DISABLED)

            # Hide the IO frame if visible
            if self.io_frame.winfo_ismapped():
                self.io_frame.grid_remove()


    def _on_connection_type_change(self, *args):
        """Handles changes in the selected connection type."""
        selected_type = self.connection_type_var.get()
        print(f"Connection type changed to: {selected_type}")
        # Clear detected devices list and entry fields
        self.detected_devices_combobox.set('')
        self.detected_devices_combobox['values'] = []
        self.address_entry.delete(0, tk.END)
        self.port_entry.delete(0, tk.END)

        # Hide all type-specific detection/settings widgets first
        self.network_range_label.grid_remove()
        self.network_range_entry.grid_remove()
        self.scan_ports_label.grid_remove()
        self.scan_ports_entry.grid_remove()
        self.wifi_interface_label.grid_remove()
        self.wifi_interface_entry.grid_remove()
        self.detect_button.grid_remove() # Hide the button initially

        # Update labels and entry field states based on type
        address_label = self.master.nametowidget(self.address_entry.winfo_parent()).grid_slaves(row=0, column=0)[0]
        port_label = self.master.nametowidget(self.port_entry.winfo_parent()).grid_slaves(row=1, column=0)[0]

        # Enable/Disable Address/Port entries and grid type-specific detection widgets
        if selected_type == "Bluetooth":
            address_label.config(text="Address:")
            port_label.config(text="Port:")
            self.address_entry.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.NORMAL)
            self.network_range_entry.config(state=tk.DISABLED)
            self.scan_ports_entry.config(state=tk.DISABLED)
            self.wifi_interface_entry.config(state=tk.DISABLED)
            self.detect_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew") # Grid detect button


        elif selected_type == "USB":
            address_label.config(text="N/A:")
            port_label.config(text="Port Name:")
            self.address_entry.config(state=tk.DISABLED) # Address not needed for USB
            self.port_entry.config(state=tk.NORMAL)
            self.network_range_entry.config(state=tk.DISABLED)
            self.scan_ports_entry.config(state=tk.DISABLED)
            self.wifi_interface_entry.config(state=tk.DISABLED)
            self.detect_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew") # Grid detect button


        elif selected_type == "Network":
            address_label.config(text="IP Address:")
            port_label.config(text="Port:")
            self.address_entry.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.NORMAL)
            # Grid network-specific detection widgets
            self.network_range_label.grid(row=0, column=0, sticky="w", padx=5, pady=2)
            self.network_range_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
            self.scan_ports_label.grid(row=1, column=0, sticky="w", padx=5, pady=2)
            self.scan_ports_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
            self.wifi_interface_entry.config(state=tk.DISABLED) # Disable wifi interface entry
            self.detect_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew") # Grid detect button


        elif selected_type == "WiFi Scan":
            address_label.config(text="N/A:") # Address not needed for Wi-Fi Scan (connecting to AP is OS job)
            port_label.config(text="N/A:") # Port not needed for Wi-Fi Scan
            self.address_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.network_range_entry.config(state=tk.DISABLED) # Disable network range entry
            self.scan_ports_entry.config(state=tk.DISABLED) # Disable scan ports entry
            # Grid Wi-Fi specific detection widgets
            self.wifi_interface_label.grid(row=0, column=0, sticky="w", padx=5, pady=2)
            self.wifi_interface_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
            self.detect_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew") # Grid detect button (higher row)

            # Wi-Fi Scan is primarily for detection, disable Connect button for this type
            self.connect_button.config(state=tk.DISABLED)
            self.disconnect_button.config(state=tk.DISABLED) # Disconnect also not applicable


        # Add more conditions for other types

        # Ensure Connect/Disconnect buttons are updated based on *overall* connection state,
        # but respect the disabled state if the type is Wi-Fi Scan
        # We don't call _update_button_states here to avoid recursion.
        # The initial call in __init__ and calls from connect/disconnect threads
        # are sufficient to manage the overall state.
        pass # Removed the recursive call


    def _on_device_selected(self, event):
        """Handles selection from the detected devices combobox."""
        selected_device_str = self.detected_devices_combobox.get()
        print(f"Selected device: {selected_device_str}")

        # Parse the selected string to populate address/port fields
        # This parsing logic depends on how you format the device list in the detection functions
        selected_type = self.connection_type_var.get()

        # Clear fields before populating
        self.address_entry.delete(0, tk.END)
        self.port_entry.delete(0, tk.END)

        if selected_type == "Bluetooth":
            # Assuming Bluetooth devices are listed as "Name (Address:Port)"
            try:
                # Find the last colon to split address and port
                parts = selected_device_str.rsplit(":", 1)
                if len(parts) == 2:
                    address_part, port_str = parts
                    # Extract address from "Name (Address" part
                    address = address_part.split(" (", 1)[-1]
                    self.address_entry.insert(0, address.strip())
                    self.port_entry.insert(0, port_str.strip(")"))
                else:
                     print(f"Could not parse Bluetooth device string format: {selected_device_str}")
                     self.update_status(f"Warning: Could not parse selected Bluetooth device.")

            except Exception as e:
                print(f"Error parsing Bluetooth device string: {e}")
                self.update_status(f"Warning: Error parsing selected Bluetooth device.")


        elif selected_type == "USB":
            # Assuming USB ports are listed as just the port name
            self.port_entry.insert(0, selected_device_str)
            # Address field is disabled for USB, no need to clear/set

        elif selected_type == "Network":
            # Assuming Network devices are listed as "IP_Address (Port1, Port2, ...)"
            try:
                parts = selected_device_str.split(" (", 1)
                if len(parts) == 2:
                    ip_address = parts[0].strip()
                    ports_str = parts[1].strip(")")
                    open_ports = [p.strip() for p in ports_str.split(',')]

                    self.address_entry.insert(0, ip_address)
                    # You might want to select a default port or let the user choose
                    if open_ports:
                        self.port_entry.insert(0, open_ports[0]) # Default to the first open port
                    else:
                        self.port_entry.insert(0, "") # Leave port empty if no open ports found

                else:
                    print(f"Could not parse Network device string format: {selected_device_str}")
                    self.update_status(f"Warning: Could not parse selected Network device.")

            except Exception as e:
                print(f"Error parsing Network device string: {e}")
                self.update_status(f"Warning: Error parsing selected Network device.")

        elif selected_type == "WiFi Scan":
            # Assuming Wi-Fi networks are listed as "SSID (BSSID) - Channel: X - Security: Y"
            # For Wi-Fi Scan, we just display info, no address/port to populate for connection
            print(f"Wi-Fi network selected: {selected_device_str}")
            # You could parse this string to show details elsewhere if needed
            pass # No address/port to set for connection


        # Add parsing logic for other connection types


    def _start_detection_thread(self):
        """Starts the device detection process in a separate thread."""
        if self.connection_thread and self.connection_thread.is_alive():
            print("Another connection/disconnection process is already running.")
            self.update_status("Busy with another operation.")
            return

        selected_type = self.connection_type_var.get()
        network_range = self.network_range_entry.get()
        scan_ports = self.scan_ports_entry.get()
        wifi_interface = self.wifi_interface_entry.get()


        # Basic validation based on selected type
        if selected_type == "Network" and not network_range:
             messagebox.showwarning("Input Error", "Please enter a network range to scan.")
             self.update_status("Detection failed: Missing network range.")
             return
        if selected_type == "WiFi Scan" and not wifi_interface:
             messagebox.showwarning("Input Error", "Please enter a Wi-Fi interface name.")
             self.update_status("Detection failed: Missing Wi-Fi interface.")
             return
        # Add validation for other types if needed

        self.update_status(f"Detecting {selected_type} devices...")
        self.detect_button.config(state=tk.DISABLED) # Disable detect button during detection
        self.detected_devices_combobox.config(state=tk.DISABLED) # Disable combobox
        self.detected_devices_combobox.set('') # Clear previous selection/values
        self.detected_devices_combobox['values'] = []


        # Create and start the detection thread
        self.connection_thread = threading.Thread(
            target=self._detect_devices_thread,
            args=(selected_type, network_range, scan_ports, wifi_interface), # Pass all relevant args
            daemon=True
        )
        self.connection_thread.start()


    def _detect_devices_thread(self, selected_type, network_range, scan_ports, wifi_interface):
        """Runs the device detection logic in a separate thread."""
        detected_devices_raw = []
        formatted_devices = []
        try:
            if selected_type == "Bluetooth":
                # --- CALL YOUR ACTUAL BLUETOOTH DETECTION CODE HERE ---
                # Replace the call below with your function.
                # Your function should return a list of device identifiers (e.g., list of tuples (name, address, port)).
                detected_devices_raw = detect_bluetooth_devices()
                # Format the list for the combobox (e.g., "Name (Address:Port)")
                # Adjust formatting based on what your detect_bluetooth_devices function returns
                formatted_devices = [f"{name} ({address}:{port})" for name, address, port in detected_devices_raw] if detected_devices_raw else []


            elif selected_type == "USB":
                # --- CALL YOUR ACTUAL USB (SERIAL) DETECTION CODE HERE ---
                # Replace the call below with your function.
                # Your function should return a list of port names (e.g., ['COM1', '/dev/ttyUSB0']).
                detected_devices_raw = detect_usb_ports()
                formatted_devices = detected_devices_raw # USB ports are usually just names

            elif selected_type == "Network":
                 # --- CALL YOUR ACTUAL NETWORK DETECTION CODE HERE (using Nmap via python-nmap) ---
                 # Replace the call below with your function.
                 # Pass the network range and scan ports from the GUI.
                 # Your function should return a list of device identifiers (e.g., list of tuples (ip_address, [open_ports])).
                 detected_devices_raw = detect_network_devices(network_range, scan_ports)
                 # Format the list for the combobox (e.g., "IP_Address (Port1, Port2, ...)")
                 formatted_devices = [f"{ip} ({', '.join(map(str, ports))})" for ip, ports in detected_devices_raw] # Map ports to string

            elif selected_type == "WiFi Scan":
                 # --- CALL YOUR ACTUAL WI-FI SCANNING CODE HERE ---
                 # Replace the call below with your function.
                 # Pass the Wi-Fi interface name from the GUI.
                 # Your function should return a list of network identifiers (e.g., list of tuples (ssid, bssid, channel, security)).
                 detected_devices_raw = scan_wifi_networks()
                 # Format the list for the combobox (e.g., "SSID (BSSID) - Channel: X - Security: Y")
                 # Adjust formatting based on what your scan_wifi_networks function returns
                 formatted_devices = [
                     f"{n.get('ssid', 'N/A')} ({n.get('bssid', 'N/A')}) - Channel: {n.get('channel', 'N/A')} - Security: {n.get('security', 'N/A')}"
                     for n in detected_devices_raw
                 ] if detected_devices_raw else []


            # --- Add 'elif' blocks here for other detection types ---
            # elif selected_type == "Another Type":
            #     detected_devices_raw = your_detection_function(...)
            #     formatted_devices = [...] # Format for combobox


            else:
                error_message = f"Unsupported detection type selected: {selected_type}"
                self.update_status(f"Error: {error_message}")
                self.master.after(0, lambda: messagebox.showerror("Detection Error", error_message))
                formatted_devices = [] # Clear list on error


            self.update_status(f"Detection complete. Found {len(detected_devices_raw)} devices/networks.")
            # Update the combobox values in the GUI thread
            self.master.after(0, lambda: self._update_detected_devices_combobox(formatted_devices))


        except NotImplementedError as e:
             self.update_status(f"Error: Detection feature not implemented: {e}")
             self.master.after(0, lambda: messagebox.showinfo("Not Implemented", str(e)))

        except Exception as e:
            error_message = f"Device detection failed: {e}"
            self.update_status(f"Error: {error_message}")
            self.master.after(0, lambda: messagebox.showerror("Detection Error", error_message))

        finally:
            # Re-enable the detect button and combobox in the GUI thread
            self.master.after(0, lambda: self.detect_button.config(state=tk.NORMAL))
            self.master.after(0, lambda: self.detected_devices_combobox.config(state="readonly"))


    def _update_detected_devices_combobox(self, device_list):
        """Updates the combobox with the list of detected devices. Called from GUI thread."""
        self.detected_devices_combobox['values'] = device_list
        if device_list:
            self.detected_devices_combobox.set(device_list[0]) # Select the first device by default
            self._on_device_selected(None) # Trigger selection logic for the first item
        else:
            self.detected_devices_combobox.set('') # Clear the combobox text


    def _start_connection_thread(self):
        """Starts the connection process in a separate thread."""
        if self.connection_thread and self.connection_thread.is_alive():
            print("Another connection/disconnection process is already running.")
            self.update_status("Busy with another operation.")
            return

        selected_type = self.connection_type_var.get()
        address = self.address_entry.get()
        port = self.port_entry.get()

        # Basic input validation before attempting connection
        # Wi-Fi Scan type doesn't involve a direct connection via Address/Port,
        # so we only validate for types that do.
        if selected_type in ["Bluetooth", "Network"] and (not address or not port):
            messagebox.showwarning("Input Error", f"Please enter both address/IP and port for {selected_type}.")
            self.update_status("Connection attempt failed: Missing input.")
            return
        if selected_type == "USB" and not port: # Assuming Port is the name/path for USB
             messagebox.showwarning("Input Error", "Please enter the port name for USB.")
             self.update_status("Connection attempt failed: Missing input.")
             return
        # Add validation for other connection types

        # For Wi-Fi Scan, the "Connect" button is not applicable in the same way.
        # We should prevent starting a connection thread for this type.
        if selected_type == "WiFi Scan":
             self.update_status("Connect is not applicable for Wi-Fi Scan. Use Detect to find networks.")
             print("Attempted to connect with 'WiFi Scan' type selected.")
             return


        self.update_status(f"Attempting to connect via {selected_type}...")
        # Disable buttons and inputs immediately in the GUI thread
        self.is_connected = False # Temporarily set to False to disable buttons
        self._update_button_states()


        # Create and start the connection thread
        self.connection_thread = threading.Thread(
            target=self._connect_device_thread,
            args=(selected_type, address, port),
            daemon=True
        )
        self.connection_thread.start()


    def _connect_device_thread(self, selected_type, address, port):
        """Runs the connection logic in a separate thread."""
        connection_object = None
        try:
            if selected_type == "Bluetooth":
                # --- CALL YOUR ACTUAL BLUETOOTH CONNECTION CODE HERE ---
                # Replace the call below with your function.
                # Your function should return the connection object on success,
                # and raise an Exception on failure.
                connection_object = connect_to_bluetooth(address, port)

            elif selected_type == "USB":
                # --- CALL YOUR ACTUAL USB (SERIAL) CONNECTION CODE HERE ---
                # Replace the call below with your function.
                # Your function should return the connection object (serial.Serial instance) on success,
                # and raise an Exception on failure.
                connection_object = connect_to_usb(port) # Assuming 'port' holds the USB port name (like COM1 or /dev/ttyUSB0)

            elif selected_type == "Network":
                # --- CALL YOUR ACTUAL NETWORK CONNECTION CODE HERE (using socket) ---
                # Replace the call below with your function.
                # Your function should return the socket object (or SSL socket) on success,
                # and raise an Exception on failure.
                connection_object = connect_to_network(address, port)

            # --- Add 'elif' blocks here for other connection types ---
            # elif selected_type == "Another Type":
            #     connection_object = your_connection_function(address, port, ...)


            else:
                # This case should ideally be caught by input validation before threading
                error_message = f"Unsupported connection type selected: {selected_type}"
                self.update_status(f"Error: {error_message}")
                self.master.after(0, lambda: messagebox.showerror("Connection Error", error_message))
                return # Exit thread function

            # If the connection function returned a connection object:
            if connection_object is not None:
                 self.is_connected = True
                 self.active_connection = connection_object # Store the connection object
                 self.update_status(f"Successfully connected via {selected_type}.")
                 # Start the receiver thread if connection was successful
                 self._start_receiver_thread()

            else:
                 # If the function returned None without raising an exception
                 raise Exception(f"{selected_type} connection failed (function returned None).")


        except NotImplementedError as e:
             self.update_status(f"Error: Connection feature not implemented: {e}")
             self.master.after(0, lambda: messagebox.showinfo("Not Implemented", str(e)))
             self.is_connected = False

        except Exception as e:
            error_message = f"Connection failed: {e}"
            self.update_status(f"Error: {error_message}")
            self.master.after(0, lambda: messagebox.showerror("Connection Error", error_message))
            self.is_connected = False
            self.active_connection = None

        finally:
            # Always update button states in the GUI thread after connection attempt finishes
            self.master.after(0, self._update_button_states)


    def _start_disconnection_thread(self):
        """Starts the disconnection process in a separate thread."""
        if not self.is_connected:
            self.update_status("Not currently connected.")
            self._update_button_states()
            return

        if self.connection_thread and self.connection_thread.is_alive():
             print("Another connection/disconnection process is already running.")
             self.update_status("Busy with another operation.")
             return

        self.update_status("Attempting to disconnect...")
        self.disconnect_button.config(state=tk.DISABLED) # Disable disconnect button immediately

        # Stop the receiver thread first
        self._stop_receiver_thread()

        # Create and start the disconnection thread
        self.connection_thread = threading.Thread(
            target=self._disconnect_device_thread,
            daemon=True
        )
        self.connection_thread.start()


    def _disconnect_device_thread(self):
        """Runs the disconnection logic in a separate thread."""
        try:
            # --- ADD YOUR ACTUAL DISCONNECTION CODE HERE ---
            # If you stored a connection object in self.active_connection during connection:
            if self.active_connection:
                print("Closing active connection...")
                try:
                    # Check the type of connection object and close accordingly
                    if hasattr(self.active_connection, 'close'):
                         self.active_connection.close()
                         print("Connection object closed.")
                    # Add specific closing logic for other types if needed
                    # elif isinstance(self.active_connection, YourCustomConnectionType):
                    #     your_library.disconnect(self.active_connection)
                    else:
                         print("Warning: Active connection object does not have a standard .close() method.")

                except Exception as e:
                    print(f"Error during connection closing: {e}")
                    # Decide if this error means the device is still connected or not
                    pass # Continue with setting states even if closing failed

            # --- End of Actual Disconnection Code ---


            self.active_connection = None # Clear the stored connection object
            self.is_connected = False # Update state

            self.update_status("Disconnected.")

        except Exception as e:
            error_message = f"Disconnection error: {e}"
            self.update_status(f"Error: {error_message}")
            self.master.after(0, lambda: messagebox.showerror("Disconnection Error", error_message))
            self.is_connected = False
            self.active_connection = None

        finally:
            self.master.after(0, self._update_button_states)


    def _start_receiver_thread(self):
        """Starts the data receiving thread."""
        # Ensure no receiver thread is already running
        if self.receiver_thread and self.receiver_thread.is_alive():
            print("Receiver thread is already running.")
            return
        if not self.is_connected or self.active_connection is None:
             print("Not connected, cannot start receiver thread.")
             return

        print("Starting receiver thread...")
        # Clear the stop flag before starting the thread
        self._stop_receiver_flag.clear()

        # Create and start the receiver thread
        self.receiver_thread = threading.Thread(
            target=self._receive_data_thread,
            daemon=True # Daemon threads exit when the main program exits
        )
        self.receiver_thread.start()


    def _stop_receiver_thread(self):
        """Signals the receiver thread to stop and waits for it to finish."""
        if self.receiver_thread and self.receiver_thread.is_alive():
            print("Signaling receiver thread to stop...")
            # Set the stop flag to signal the thread
            self._stop_receiver_flag.set()
            # Wait for the thread to finish (with a timeout to avoid freezing)
            self.receiver_thread.join(timeout=2) # Wait for up to 2 seconds
            if self.receiver_thread.is_alive():
                print("Warning: Receiver thread did not stop gracefully.")
            else:
                print("Receiver thread stopped.")

        self.receiver_thread = None # Clear the thread reference


    def _receive_data_thread(self):
        """
        Runs in a separate thread to receive data from the active connection.
        Contains logic for different connection object types (socket, serial).
        Includes robust error handling and sleep to prevent busy-wait loops.
        """
        print("Receiver thread started.")
        # --- ACTUAL DATA RECEIVING LOOP ---
        # This loop continuously reads data from self.active_connection
        # and puts it into self.receive_queue.
        # IMPORTANT: The loop must check self._stop_receiver_flag.is_set()
        # periodically and break if it's True to allow graceful shutdown.

        # Check if the connection object is a socket (TCP/IP)
        if isinstance(self.active_connection, (socket.socket, ssl.SSLSocket)):
            print("Receiver thread: Handling socket connection.")
            sock = self.active_connection
            # Ensure a timeout is set on the socket for reading
            # If you set it during connect_to_network, it should be active here.
            # If not, you might need to set it here:
            # try:
            #     sock.settimeout(0.5) # Example timeout
            # except Exception as e:
            #     print(f"Warning: Could not set timeout on socket: {e}")


            while self.is_connected and sock and not self._stop_receiver_flag.is_set():
                try:
                    # Read data from the socket. Adjust read size as needed.
                    # If using settimeout, this will raise socket.timeout if no data arrives.
                    data = sock.recv(1024) # Example read call (reads up to 1024 bytes)
                    if data:
                        # Put received data (decoded to string) into the queue
                        self.receive_queue.put(data.decode('utf-8', errors='ignore'))
                        # print(f"Received: {data.decode('utf-8', errors='ignore').strip()}") # Optional: print to console
                    elif data == b'': # recv returns empty bytes when the connection is closed
                         print("Connection closed by remote device.")
                         self.update_status("Connection closed by device.")
                         # Signal disconnection (needs to be done safely from thread)
                         self.master.after(0, self._start_disconnection_thread)
                         break # Exit the loop

                except socket.timeout:
                    # Handle read timeouts. This is expected if no data arrives within the timeout period.
                    # Just continue the loop to check the stop flag.
                    pass
                except BlockingIOError as e:
                     # Handle non-blocking socket returning immediately (EWOULDBLOCK)
                     if e.errno != errno.EWOULDBLOCK:
                         print(f"Error in socket receiver thread (BlockingIOError): {e}")
                         self.update_status(f"Receive Error: {e}")
                         self.master.after(0, self._start_disconnection_thread)
                         break # Exit the loop on unexpected BlockingIOError
                     # If EWOULDBLOCK, no data was available, continue loop, maybe add a small sleep
                     time.sleep(0.01) # Small sleep to prevent busy-wait if non-blocking
                except Exception as e:
                    print(f"Error in socket receiver thread: {e}")
                    self.update_status(f"Receive Error: {e}")
                    # Signal disconnection on error
                    self.master.after(0, self._start_disconnection_thread)
                    break # Exit the loop on error

        # Check if the connection object is a serial port
        elif isinstance(self.active_connection, serial.Serial):
             print("Receiver thread: Handling serial connection.")
             ser = self.active_connection
             # The serial.Serial read method often blocks with a timeout set during initialization.
             # Ensure the timeout was set when creating the serial.Serial object.

             while self.is_connected and ser and not self._stop_receiver_flag.is_set():
                try:
                    # Read data from the serial port. Adjust read size/timeout.
                    # read() will block for 'timeout' seconds if no data is available.
                    # read(size) reads up to 'size' bytes.
                    # read_until(terminator) reads until a terminator character is found or timeout occurs.
                    # Using ser.in_waiting or 1 is good to read available data immediately,
                    # but if in_waiting is 0 and timeout is None, this would block forever.
                    # With timeout set, it will block for the timeout period.
                    data = ser.read(ser.in_waiting or 1) # Read available bytes or at least 1
                    if data:
                         self.receive_queue.put(data.decode('utf-8', errors='ignore'))
                         # print(f"Received: {data.decode('utf-8', errors='ignore').strip()}") # Optional: print to console
                    # Add a small sleep here if your read calls are non-blocking or have very short timeouts,
                    # to prevent a tight CPU loop. If timeout is > 0, it's usually not necessary.
                    # If ser.timeout is None and ser.in_waiting is 0, this loop would busy-wait without a sleep.
                    if ser.timeout is None and ser.in_waiting == 0:
                         time.sleep(0.01) # Prevent busy-wait if non-blocking/no timeout


                except Exception as e:
                    print(f"Error in serial receiver thread: {e}")
                    self.update_status(f"Receive Error: {e}")
                    self.master.after(0, self._start_disconnection_thread)
                    break # Exit the loop on error

        else:
             print("Warning: Active connection object type not recognized for receiving.")
             self.update_status("Error: Cannot receive data from this connection type.")


        print("Receiver thread finished.")
        # --- END OF ACTUAL DATA RECEIVING LOOP ---


    def _check_receive_queue(self):
        """
        Checks the receive queue for new data and updates the text widget.
        Called periodically by the Tkinter event loop.
        """
        try:
            while True:
                # Get data from the queue without blocking
                data = self.receive_queue.get_nowait()
                # Append data to the receive text widget
                self.receive_text.insert(tk.END, data)
                # Auto-scroll to the end
                self.receive_text.see(tk.END)
        except queue.Empty:
            # No data in the queue, do nothing
            pass
        except Exception as e:
             print(f"Error checking receive queue: {e}")
        finally:
            # Schedule the next check
            self.master.after(100, self._check_receive_queue) # Check every 100ms


    def _send_data(self):
        """
        Sends data from the send entry field through the active connection.
        Contains logic for different connection object types (socket, serial).
        """
        if not self.is_connected or self.active_connection is None:
            self.update_status("Not connected. Cannot send data.")
            return

        data_to_send = self.send_entry.get()
        if not data_to_send:
            print("Send entry is empty.")
            return # Don't send empty data

        print(f"Attempting to send: {data_to_send}")
        self.update_status(f"Sending: {data_to_send[:30]}...") # Show first 30 chars

        try:
            # --- ACTUAL DATA SENDING CODE ---
            # Use self.active_connection to send the data.
            # Remember to encode the string to bytes if your connection requires bytes.
            data_bytes = data_to_send.encode('utf-8') # Encode string to bytes

            # Check the type of connection object and send accordingly
            if hasattr(self.active_connection, 'send'): # For sockets (including SSL sockets)
                bytes_sent = self.active_connection.send(data_bytes)
                print(f"Sent {bytes_sent} bytes via socket.")
            elif hasattr(self.active_connection, 'write'): # For serial ports
                 bytes_sent = self.active_connection.write(data_bytes)
                 print(f"Sent {bytes_sent} bytes via serial.")
            # Add sending logic for other connection types if needed
            # elif isinstance(self.active_connection, YourCustomConnectionType):
            #     your_library.send(self.active_connection, data_bytes)
            else:
                 raise Exception("Active connection object does not have standard send/write methods.")

            # --- End of Actual Data Sending Code ---

            self.update_status(f"Data sent.")
            self.send_entry.delete(0, tk.END) # Clear the send entry after sending

        except Exception as e:
            error_message = f"Failed to send data: {e}"
            self.update_status(f"Error: {error_message}")
            self.master.after(0, lambda: messagebox.showerror("Send Error", error_message))


    def _on_closing(self):
        """Handles closing the window, ensuring disconnection."""
        if self.is_connected:
            if messagebox.askokcancel("Quit", "Device is connected. Disconnect and Quit?"):
                # Start disconnection in a thread
                self._start_disconnection_thread()
                # Wait briefly for the disconnection thread to finish before destroying the window
                # Joining with a timeout is safer than just using after()
                if self.connection_thread and self.connection_thread.is_alive():
                    print("Waiting for disconnection thread to finish...")
                    self.connection_thread.join(timeout=5) # Wait for up to 5 seconds

                self.master.destroy() # Destroy the window

            # else: user cancelled, do nothing
        else:
            # If not connected, just destroy the window immediately
            self.master.destroy()


# --- Main application entry point ---
if __name__ == "__main__":
    root = tk.Tk()
    app = MultiConnectGUI(root)
    root.mainloop()
