import customtkinter as ctk

class advance_monitor_ui(ctk.CTkToplevel):
    def __init__(self, parent, interface, update_log):
        super().__init__(parent)

        self.interface = interface
        self.update_log = update_log

        self.title(f"NetSpy - Advanced Inspector ({self.interface})")
        self.geometry("900x700")
        self.configure(fg_color="#0f0f0f")
        self.attributes("-topmost", True)

        self.header = ctk.CTkLabel(
            self,
            text=f"🔍 DEEP INSPECTION: {self.interface}",
            font=("Roboto", 18, "bold"),
            text_color="#3498db"
        )
        self.header.pack(pady=20)

        #  Target Network Selection Frame
        self.selection_frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        self.selection_frame.pack(fill="x", padx=30, pady=10)

        ctk.CTkLabel(self.selection_frame, text="Select WiFi Target:", font=("Roboto", 13)).pack(side="left", padx=10,pady=10)

        # Network Dropdown
        self.network_selector = ctk.CTkComboBox(
            self.selection_frame,
            values=["Searching for networks..."],
            width=300
        )
        self.network_selector.pack(side="left", padx=10, pady=10)

        # Attack/Action Buttons
        self.button_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.button_frame.pack(pady=20)

        # Handshake Capture Button
        self.handshake_btn = ctk.CTkButton(
            self.button_frame,
            text="📥 CAPTURE HANDSHAKE",
            fg_color="#e67e22",
            hover_color="#d35400",
            #command=self.start_handshake_capture
        )
        self.handshake_btn.grid(row=0, column=0, padx=10)

        # Password Brute-force/Decrypt Button
        self.bruteforce_btn = ctk.CTkButton(
            self.button_frame,
            text="🔓 START DECRYPTION",
            fg_color="#27ae60",
            hover_color="#219150",
            #command=self.start_decryption
        )
        self.bruteforce_btn.grid(row=0, column=1, padx=10)

        # --- Live Terminal/Log Output ---
        self.terminal_display = ctk.CTkTextbox(
            self,
            height=300,
            fg_color="#000000",
            font=("Consolas", 12),
            text_color="#00FF00",
            border_width=1,
            border_color="#333333"
        )
        self.terminal_display.pack(fill="both", expand=True, padx=30, pady=20)

        # Initial Message
        # self.write_to_terminal("System Ready. Select a target SSID and click Capture.")
        self.terminal_display.configure(state="disabled")



