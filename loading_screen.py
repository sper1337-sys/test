"""
Loading Screen System for Polly Tunnels Applications
Shows progress during Tor connection and application initialization
"""

import tkinter as tk
from tkinter import ttk
import threading
import time

class LoadingScreen:
    """Professional loading screen with progress indication"""
    
    def __init__(self, app_name="Polly Tunnels", app_type="Client"):
        self.app_name = app_name
        self.app_type = app_type
        self.root = None
        self.progress_var = None
        self.status_var = None
        self.progress_bar = None
        self.is_closed = False
        
    def show(self):
        """Display the loading screen"""
        self.root = tk.Tk()
        self.root.title(f"{self.app_name} - Loading...")
        self.root.geometry("500x300")
        self.root.resizable(False, False)
        
        # Center the window
        self.root.eval('tk::PlaceWindow . center')
        
        # Configure colors
        bg_color = "#2c3e50"
        text_color = "#ecf0f1"
        accent_color = "#3498db"
        
        self.root.configure(bg=bg_color)
        
        # Main frame
        main_frame = tk.Frame(self.root, bg=bg_color)
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Title
        title_label = tk.Label(main_frame, 
                              text=f"{self.app_name}",
                              font=("Arial", 18, "bold"),
                              fg=text_color, bg=bg_color)
        title_label.pack(pady=(0, 5))
        
        # Subtitle
        subtitle_label = tk.Label(main_frame,
                                 text=f"{self.app_type} Application",
                                 font=("Arial", 12),
                                 fg="#bdc3c7", bg=bg_color)
        subtitle_label.pack(pady=(0, 20))
        
        # Status text
        self.status_var = tk.StringVar()
        self.status_var.set("Initializing secure connection...")
        status_label = tk.Label(main_frame,
                               textvariable=self.status_var,
                               font=("Arial", 10),
                               fg=text_color, bg=bg_color)
        status_label.pack(pady=(0, 15))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame,
                                           variable=self.progress_var,
                                           maximum=100,
                                           length=400,
                                           mode='determinate')
        self.progress_bar.pack(pady=(0, 10))
        
        # Progress percentage
        self.progress_text = tk.Label(main_frame,
                                     text="0%",
                                     font=("Arial", 9),
                                     fg="#95a5a6", bg=bg_color)
        self.progress_text.pack()
        
        # Security notice
        security_label = tk.Label(main_frame,
                                 text="🔒 Establishing secure Tor connection...",
                                 font=("Arial", 9),
                                 fg="#e74c3c", bg=bg_color)
        security_label.pack(side='bottom', pady=(20, 0))
        
        # Make window stay on top during loading
        self.root.attributes('-topmost', True)
        
        return self.root
    
    def update_progress(self, percentage, status_text):
        """Update progress bar and status text"""
        if self.is_closed or not self.root:
            return
            
        try:
            self.progress_var.set(percentage)
            self.status_var.set(status_text)
            self.progress_text.config(text=f"{int(percentage)}%")
            self.root.update()
        except tk.TclError:
            # Window was closed
            self.is_closed = True
    
    def close(self):
        """Close the loading screen"""
        if self.root and not self.is_closed:
            self.is_closed = True
            try:
                self.root.destroy()
            except tk.TclError:
                pass
            self.root = None

class LoadingManager:
    """Manages loading screen during application startup"""
    
    def __init__(self, app_name, app_type):
        self.loading_screen = LoadingScreen(app_name, app_type)
        self.loading_root = None
        
    def start_loading(self):
        """Start the loading screen in a separate thread"""
        self.loading_root = self.loading_screen.show()
        return self.loading_screen
    
    def update_status(self, percentage, message):
        """Update loading progress"""
        if self.loading_screen:
            self.loading_screen.update_progress(percentage, message)
    
    def finish_loading(self):
        """Close loading screen"""
        if self.loading_screen:
            self.loading_screen.close()
            self.loading_screen = None