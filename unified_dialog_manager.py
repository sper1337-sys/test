"""
UNIFIED DIALOG MANAGER
Single, consistent dialog system for all UI interactions
Eliminates multiple different GUI implementations
"""

import tkinter as tk
from professional_modern_theme import ProfessionalModernTheme, ProfessionalModernComponents


class UnifiedDialogManager:
    """SINGLE dialog system for ALL UI interactions - No more multiple GUIs"""

    def __init__(self, parent_window, theme=None, components=None):
        self.parent = parent_window
        self.theme = theme or ProfessionalModernTheme()
        self.components = components or ProfessionalModernComponents(self.theme)
        self.colors = self.theme.get_color_palette()

        # Track open dialogs to prevent duplicates
        self.open_dialogs = {}

    def create_dialog(self, title, width=500, height=400, modal=True):
        """Create a new themed dialog window - UNIVERSAL method"""
        dialog = tk.Toplevel(self.parent)
        dialog.title(title)
        dialog.geometry(f"{width}x{height}")
        dialog.configure(bg=self.colors['bg'])

        if modal:
            dialog.transient(self.parent)
            dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (width // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (height // 2)
        dialog.geometry(f"+{x}+{y}")

        return dialog

    def show_dialog(self, title, message, dialog_type='info', buttons=None, callback=None):
        """UNIVERSAL dialog for info, success, warning, error messages"""
        if buttons is None:
            buttons = ['OK']

        dialog_id = f"message_{id(message)}"

        # Icon mapping
        icons = {
            'info': 'â„¹ï¸',
            'success': 'âœ…',
            'warning': 'âš ï¸',
            'error': 'âŒ'
        }

        # Color mapping
        icon_colors = {
            'info': self.colors.get('primary', '#2196F3'),
            'success': self.colors.get('success', '#4CAF50'),
            'warning': self.colors.get('warning', '#FF9800'),
            'error': self.colors.get('error', '#F44336')
        }

        result = {'value': None}

        def create_content(content_frame, dialog):
            # Icon
            icon_label = tk.Label(
                content_frame,
                text=icons.get(dialog_type, 'â„¹ï¸'),
                font=self.theme.get_font_config('display_small'),
                bg=self.colors['surface'],
                fg=icon_colors.get(dialog_type, self.colors['primary'])
            )
            icon_label.pack(pady=(0, 16))

            # Message
            msg_label = tk.Label(
                content_frame,
                text=message,
                font=self.theme.get_font_config('body_medium'),
                bg=self.colors['surface'],
                fg=self.colors['on_surface'],
                wraplength=350,
                justify='center'
            )
            msg_label.pack(pady=(0, 24))

            # Buttons
            button_frame = tk.Frame(content_frame, bg=self.colors['surface'])
            button_frame.pack(fill=tk.X)

            def on_button(btn_text):
                result['value'] = btn_text
                if callback:
                    callback(btn_text)
                self._close_dialog(dialog_id)

            for i, btn_text in enumerate(buttons):
                style = 'primary' if i == len(buttons) - 1 else 'secondary'
                self.components.create_enterprise_button(
                    button_frame,
                    btn_text,
                    command=lambda t=btn_text: on_button(t),
                    style=style
                ).pack(side=tk.RIGHT if i == len(buttons) - 1 else tk.LEFT, padx=4)

            dialog.bind('<Return>', lambda e: on_button(buttons[-1]))
            dialog.bind('<Escape>', lambda e: on_button(buttons[0]))

        dialog = self._create_dialog(dialog_id, title, create_content, 400, 250)
        dialog.wait_window()
        return result['value']

    def show_master_password_dialog(self, password_manager, callback=None):
        """SINGLE master password dialog - replaces ALL duplicate implementations"""
        dialog_id = 'master_password'

        if dialog_id in self.open_dialogs:
            self.open_dialogs[dialog_id].lift()
            return

        result = {'password': None, 'is_decoy': False}

        def create_content(content_frame, dialog):
            # Header section
            header_frame = tk.Frame(content_frame, bg=self.colors['surface'])
            header_frame.pack(fill=tk.X, pady=(0, 24))

            # Security icon
            self.components.create_styled_label(
                header_frame, "ðŸ”’", style='display_small'
            ).pack(pady=(0, 16))

            # Title
            self.components.create_styled_label(
                header_frame, "CLASSIFIED ACCESS CONTROL", style='headline_medium'
            ).pack(pady=(0, 8))

            # Subtitle
            self.components.create_styled_label(
                header_frame, "Enter Master Password to Access Classified Data", style='body_medium'
            ).pack()

            # Password input
            password_section = self.components.create_enterprise_input(
                content_frame,
                label="MASTER PASSWORD",
                input_type='password'
            )
            password_section.pack(fill=tk.X, pady=(0, 16))
            password_entry = password_section.entry

            # Show password toggle
            show_var = tk.BooleanVar()
            def toggle_password():
                password_entry.configure(show="" if show_var.get() else "*")

            self.components.create_styled_checkbox(
                content_frame,
                "Show Password",
                variable=show_var,
                command=toggle_password
            ).pack(anchor='w', pady=(0, 16))

            # Attempts warning
            attempts_left = password_manager.max_attempts - password_manager.failed_attempts
            if password_manager.failed_attempts > 0:
                warning_frame = tk.Frame(content_frame, bg=self.colors.get('warning_bg', '#FFF3E0'))
                warning_frame.pack(fill=tk.X, pady=(0, 16))
                tk.Label(
                    warning_frame,
                    text=f"âš ï¸ WARNING: {attempts_left} attempts remaining before self-destruct",
                    font=self.theme.get_font_config('body_small'),
                    bg=self.colors.get('warning_bg', '#FFF3E0'),
                    fg=self.colors.get('warning', '#FF9800'),
                    pady=8
                ).pack()

            # Buttons
            button_frame = tk.Frame(content_frame, bg=self.colors['surface'])
            button_frame.pack(fill=tk.X, pady=(24, 0))

            def authenticate():
                password = password_entry.get()

                if not password:
                    self.show_dialog("ERROR", "Master password required", "error")
                    return

                # Check for decoy password
                if password_manager.is_decoy_password(password):
                    result['password'] = password
                    result['is_decoy'] = True
                    password_manager.is_decoy_mode = True
                    self._close_dialog(dialog_id)
                    if callback:
                        callback(result)
                    return

                # First-time setup
                if not hasattr(password_manager, 'master_password_hash') or password_manager.master_password_hash is None:
                    password_manager.master_password_hash = password_manager.hash_password(password)
                    password_manager.reset_failed_attempts()
                    result['password'] = password
                    self._close_dialog(dialog_id)
                    if callback:
                        callback(result)
                    return

                # Verify password
                if password_manager.verify_password(password, password_manager.master_password_hash):
                    password_manager.reset_failed_attempts()
                    result['password'] = password
                    self._close_dialog(dialog_id)
                    if callback:
                        callback(result)
                else:
                    # Failed authentication
                    should_destruct = password_manager.record_failed_attempt()
                    attempts_left = password_manager.max_attempts - password_manager.failed_attempts

                    if should_destruct:
                        self.show_dialog(
                            "SELF-DESTRUCT ACTIVATED",
                            "ðŸ”¥ Maximum attempts exceeded!\n\nAll classified data will be destroyed for security.",
                            "error"
                        )
                        password_manager.self_destruct("host_chat_history.json")
                    else:
                        self.show_dialog(
                            "ACCESS DENIED",
                            f"âŒ Invalid master password\n\nAttempts remaining: {attempts_left}\nFile will self-destruct after {attempts_left} more failed attempts",
                            "error"
                        )
                        password_entry.delete(0, tk.END)
                        password_entry.focus()

            def cancel():
                result['password'] = None
                self._close_dialog(dialog_id)
                if callback:
                    callback(result)

            self.components.create_enterprise_button(
                button_frame, "CANCEL", command=cancel, style='danger'
            ).pack(side=tk.RIGHT, padx=(12, 0))

            self.components.create_enterprise_button(
                button_frame, "ACCESS CLASSIFIED DATA", command=authenticate, style='primary'
            ).pack(side=tk.RIGHT)

            # Emergency info
            self.components.create_styled_label(
                content_frame, "Emergency Wipe: Ctrl+Shift+W", style='body_small'
            ).pack(side=tk.BOTTOM, pady=(24, 0))

            # Focus and bindings
            password_entry.focus_set()
            password_entry.bind('<Return>', lambda e: authenticate())
            dialog.bind('<Escape>', lambda e: cancel())

        dialog = self._create_dialog(dialog_id, "CLASSIFIED ACCESS - MASTER PASSWORD", create_content, 500, 450)
        return dialog

    def show_pin_dialog(self, title="PIN AUTHENTICATION", callback=None, max_length=6):
        """SINGLE PIN dialog for ALL PIN inputs"""
        dialog_id = 'pin'

        if dialog_id in self.open_dialogs:
            self.open_dialogs[dialog_id].lift()
            return

        result = {'pin': None}

        def create_content(content_frame, dialog):
            # Header
            self.components.create_styled_label(
                content_frame, "ðŸ”", style='display_small'
            ).pack(pady=(0, 16))

            self.components.create_styled_label(
                content_frame, "Enter PIN Code", style='headline_medium'
            ).pack(pady=(0, 24))

            # PIN input
            pin_section = self.components.create_enterprise_input(
                content_frame,
                label="PIN CODE",
                input_type='password'
            )
            pin_section.pack(fill=tk.X, pady=(0, 24))
            pin_entry = pin_section.entry

            # Limit PIN length
            def validate_pin(*args):
                value = pin_entry.get()
                if len(value) > max_length:
                    pin_entry.delete(max_length, tk.END)

            pin_entry.bind('<KeyRelease>', validate_pin)

            # Buttons
            button_frame = tk.Frame(content_frame, bg=self.colors['surface'])
            button_frame.pack(fill=tk.X)

            def submit():
                result['pin'] = pin_entry.get()
                if callback:
                    callback(result['pin'])
                self._close_dialog(dialog_id)

            def cancel():
                result['pin'] = None
                if callback:
                    callback(None)
                self._close_dialog(dialog_id)

            self.components.create_enterprise_button(
                button_frame, "CANCEL", command=cancel, style='secondary'
            ).pack(side=tk.LEFT)

            self.components.create_enterprise_button(
                button_frame, "VERIFY", command=submit, style='primary'
            ).pack(side=tk.RIGHT)

            pin_entry.focus_set()
            pin_entry.bind('<Return>', lambda e: submit())
            dialog.bind('<Escape>', lambda e: cancel())

        dialog = self._create_dialog(dialog_id, title, create_content, 350, 300)
        return dialog

    def show_confirmation_dialog(self, title, message, callback=None, confirm_text="CONFIRM", cancel_text="CANCEL"):
        """SINGLE confirmation dialog for ALL confirmations"""
        if 'confirmation' in self.open_dialogs:
            self.open_dialogs['confirmation'].lift()
            return

        def create_content(content_frame, dialog):
            # Message
            self.components.create_styled_label(
                content_frame, message, style='body_medium'
            ).pack(pady=(20, 30))

            # Buttons
            button_frame = tk.Frame(content_frame, bg=self.colors['surface'])
            button_frame.pack(fill=tk.X)

            def confirm():
                if callback:
                    callback(True)
                self._close_dialog('confirmation')

            def cancel():
                if callback:
                    callback(False)
                self._close_dialog('confirmation')

            self.components.create_enterprise_button(
                button_frame, cancel_text, command=cancel, style='secondary'
            ).pack(side=tk.LEFT)

            self.components.create_enterprise_button(
                button_frame, confirm_text, command=confirm, style='primary'
            ).pack(side=tk.RIGHT)

            dialog.bind('<Return>', lambda e: confirm())
            dialog.bind('<Escape>', lambda e: cancel())

        dialog = self._create_dialog('confirmation', title, create_content, 400, 250)
        return dialog

    def show_input_dialog(self, title, fields, callback=None):
        """SINGLE input dialog for ALL form inputs"""
        if 'input' in self.open_dialogs:
            self.open_dialogs['input'].lift()
            return

        entries = {}

        def create_content(content_frame, dialog):
            # Create input fields
            for field_name, field_config in fields.items():
                field_container = self.components.create_enterprise_input(
                    content_frame,
                    label=field_config.get('label', field_name.title()),
                    placeholder=field_config.get('placeholder', ''),
                    input_type=field_config.get('type', 'text')
                )
                field_container.pack(fill=tk.X, pady=(0, 16))
                entries[field_name] = field_container.entry

            # Buttons
            button_frame = tk.Frame(content_frame, bg=self.colors['surface'])
            button_frame.pack(fill=tk.X, pady=(20, 0))

            def submit():
                if callback:
                    values = {name: entry.get() for name, entry in entries.items()}
                    callback(values)
                self._close_dialog('input')

            def cancel():
                if callback:
                    callback(None)
                self._close_dialog('input')

            self.components.create_enterprise_button(
                button_frame, "CANCEL", command=cancel, style='secondary'
            ).pack(side=tk.LEFT)

            self.components.create_enterprise_button(
                button_frame, "SUBMIT", command=submit, style='primary'
            ).pack(side=tk.RIGHT)

            # Focus first field
            if entries:
                first_entry = list(entries.values())[0]
                first_entry.focus_set()
                first_entry.bind('<Return>', lambda e: submit())

            dialog.bind('<Escape>', lambda e: cancel())

        dialog = self._create_dialog('input', title, create_content, 500, 400)
        return dialog

    def show_info_dialog(self, title, message, callback=None):
        """SINGLE info dialog for ALL information displays"""
        if 'info' in self.open_dialogs:
            self.open_dialogs['info'].lift()
            return

        def create_content(content_frame, dialog):
            # Message
            self.components.create_styled_label(
                content_frame, message, style='body_medium'
            ).pack(pady=(20, 30))

            # OK button
            def ok():
                if callback:
                    callback()
                self._close_dialog('info')

            self.components.create_enterprise_button(
                content_frame, "OK", command=ok, style='primary'
            ).pack()

            dialog.bind('<Return>', lambda e: ok())
            dialog.bind('<Escape>', lambda e: ok())

        dialog = self._create_dialog('info', title, create_content, 400, 200)
        return dialog

    def show_custom_dialog(self, dialog_id, title, content_callback, width=500, height=400):
        """SINGLE custom dialog system for ALL special dialogs"""
        if dialog_id in self.open_dialogs:
            self.open_dialogs[dialog_id].lift()
            return

        dialog = self._create_dialog(dialog_id, title, content_callback, width, height)
        return dialog

    def show_history_password_dialog(self, callback=None):
        """SINGLE history password dialog"""
        dialog_id = 'history_password'

        if dialog_id in self.open_dialogs:
            self.open_dialogs[dialog_id].lift()
            return

        result = {'password': None}

        def create_content(content_frame, dialog):
            # Header
            self.components.create_styled_label(
                content_frame, "ðŸ“", style='display_small'
            ).pack(pady=(0, 16))

            self.components.create_styled_label(
                content_frame, "CLASSIFIED HISTORY ACCESS", style='headline_medium'
            ).pack(pady=(0, 8))

            self.components.create_styled_label(
                content_frame, "Enter password to access encrypted history", style='body_medium'
            ).pack(pady=(0, 24))

            # Password input
            password_section = self.components.create_enterprise_input(
                content_frame,
                label="HISTORY PASSWORD",
                input_type='password'
            )
            password_section.pack(fill=tk.X, pady=(0, 24))
            password_entry = password_section.entry

            # Buttons
            button_frame = tk.Frame(content_frame, bg=self.colors['surface'])
            button_frame.pack(fill=tk.X)

            def submit():
                result['password'] = password_entry.get()
                if callback:
                    callback(result['password'])
                self._close_dialog(dialog_id)

            def cancel():
                result['password'] = None
                if callback:
                    callback(None)
                self._close_dialog(dialog_id)

            self.components.create_enterprise_button(
                button_frame, "CANCEL", command=cancel, style='secondary'
            ).pack(side=tk.LEFT)

            self.components.create_enterprise_button(
                button_frame, "ACCESS", command=submit, style='primary'
            ).pack(side=tk.RIGHT)

            password_entry.focus_set()
            password_entry.bind('<Return>', lambda e: submit())
            dialog.bind('<Escape>', lambda e: cancel())

        dialog = self._create_dialog(dialog_id, "CLASSIFIED HISTORY ACCESS", create_content, 450, 350)
        return dialog

    def show_change_password_dialog(self, title="CHANGE PASSWORD", callback=None, require_current=True):
        """SINGLE change password dialog"""
        dialog_id = 'change_password'

        if dialog_id in self.open_dialogs:
            self.open_dialogs[dialog_id].lift()
            return

        result = {'current': None, 'new': None, 'confirm': None}

        def create_content(content_frame, dialog):
            # Header
            self.components.create_styled_label(
                content_frame, "ðŸ”‘", style='display_small'
            ).pack(pady=(0, 16))

            self.components.create_styled_label(
                content_frame, title, style='headline_medium'
            ).pack(pady=(0, 24))

            entries = {}

            # Current password (if required)
            if require_current:
                current_section = self.components.create_enterprise_input(
                    content_frame,
                    label="CURRENT PASSWORD",
                    input_type='password'
                )
                current_section.pack(fill=tk.X, pady=(0, 16))
                entries['current'] = current_section.entry

            # New password
            new_section = self.components.create_enterprise_input(
                content_frame,
                label="NEW PASSWORD",
                input_type='password'
            )
            new_section.pack(fill=tk.X, pady=(0, 16))
            entries['new'] = new_section.entry

            # Confirm password
            confirm_section = self.components.create_enterprise_input(
                content_frame,
                label="CONFIRM NEW PASSWORD",
                input_type='password'
            )
            confirm_section.pack(fill=tk.X, pady=(0, 24))
            entries['confirm'] = confirm_section.entry

            # Buttons
            button_frame = tk.Frame(content_frame, bg=self.colors['surface'])
            button_frame.pack(fill=tk.X)

            def submit():
                result['new'] = entries['new'].get()
                result['confirm'] = entries['confirm'].get()
                if require_current:
                    result['current'] = entries['current'].get()

                # Validate
                if result['new'] != result['confirm']:
                    self.show_dialog("ERROR", "Passwords do not match!", "error")
                    return

                if len(result['new']) < 8:
                    self.show_dialog("ERROR", "Password must be at least 8 characters!", "error")
                    return

                if callback:
                    callback(result)
                self._close_dialog(dialog_id)

            def cancel():
                if callback:
                    callback(None)
                self._close_dialog(dialog_id)

            self.components.create_enterprise_button(
                button_frame, "CANCEL", command=cancel, style='secondary'
            ).pack(side=tk.LEFT)

            self.components.create_enterprise_button(
                button_frame, "CHANGE PASSWORD", command=submit, style='primary'
            ).pack(side=tk.RIGHT)

            # Focus first field
            first_entry = entries.get('current') or entries['new']
            first_entry.focus_set()
            dialog.bind('<Escape>', lambda e: cancel())

        height = 500 if require_current else 400
        dialog = self._create_dialog(dialog_id, title, create_content, 500, height)
        return dialog

    def show_user_details_dialog(self, session_data, title="USER DETAILS"):
        """SINGLE user details dialog"""
        dialog_id = f'user_details_{session_data.get("username", "unknown")}'

        if dialog_id in self.open_dialogs:
            self.open_dialogs[dialog_id].lift()
            return

        def create_content(content_frame, dialog):
            # Header
            self.components.create_styled_label(
                content_frame, "ðŸ‘¤", style='display_small'
            ).pack(pady=(0, 16))

            self.components.create_styled_label(
                content_frame, session_data.get('username', 'Unknown User'), style='headline_medium'
            ).pack(pady=(0, 24))

            # Details grid
            details = [
                ("Status", session_data.get('status', 'Unknown')),
                ("IP Address", session_data.get('ip_address', 'Unknown')),
                ("Location", f"{session_data.get('location', {}).get('city', 'Unknown')}, {session_data.get('location', {}).get('country', 'Unknown')}"),
                ("Session Start", session_data.get('session_start', 'Unknown')),
                ("Last Activity", session_data.get('last_activity', 'Unknown')),
                ("Connection Count", str(session_data.get('connection_count', 0))),
            ]

            for label, value in details:
                row_frame = tk.Frame(content_frame, bg=self.colors['surface'])
                row_frame.pack(fill=tk.X, pady=4)

                tk.Label(
                    row_frame,
                    text=f"{label}:",
                    font=self.theme.get_font_config('body_medium'),
                    bg=self.colors['surface'],
                    fg=self.colors['on_surface_variant'],
                    width=15,
                    anchor='w'
                ).pack(side=tk.LEFT)

                tk.Label(
                    row_frame,
                    text=value,
                    font=self.theme.get_font_config('body_medium'),
                    bg=self.colors['surface'],
                    fg=self.colors['on_surface']
                ).pack(side=tk.LEFT, fill=tk.X, expand=True)

            # Close button
            self.components.create_enterprise_button(
                content_frame, "CLOSE", command=lambda: self._close_dialog(dialog_id), style='primary'
            ).pack(pady=(24, 0))

            dialog.bind('<Escape>', lambda e: self._close_dialog(dialog_id))

        dialog = self._create_dialog(dialog_id, title, create_content, 500, 450)
        return dialog

    def _create_dialog(self, dialog_id, title, content_callback, width, height):
        """Internal method to create consistent dialogs"""
        dialog = tk.Toplevel(self.parent)
        dialog.title(title)
        dialog.geometry(f"{width}x{height}")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.parent)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (width // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (height // 2)
        dialog.geometry(f"+{x}+{y}")

        # Track dialog
        self.open_dialogs[dialog_id] = dialog

        # Handle close
        def on_close():
            self._close_dialog(dialog_id)

        dialog.protocol("WM_DELETE_WINDOW", on_close)

        # Main container
        main_container = tk.Frame(dialog, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=24, pady=24)

        # Header
        header_frame = tk.Frame(main_container, bg=self.colors['bg'])
        header_frame.pack(fill=tk.X, pady=(0, 20))

        self.components.create_styled_label(
            header_frame, title, style='headline_medium'
        ).pack()

        # Content area
        content_frame = self.components.create_scrollable_container(main_container)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Call content callback
        content_callback(content_frame.get_frame(), dialog)

        return dialog

    def _close_dialog(self, dialog_id):
        """Close and cleanup dialog"""
        if dialog_id in self.open_dialogs:
            try:
                self.open_dialogs[dialog_id].destroy()
            except:
                pass
            del self.open_dialogs[dialog_id]

    def close_all_dialogs(self):
        """Close all open dialogs"""
        for dialog_id in list(self.open_dialogs.keys()):
            self._close_dialog(dialog_id)
