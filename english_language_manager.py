"""
English Language Manager for Security Enhancements
Centralized English-only interface text management system
"""

import re
import tkinter as tk
from typing import Dict, Any, Optional

class EnglishLanguageManager:
    """Centralized English language management system"""
    
    def __init__(self):
        self.text_constants = self._initialize_text_constants()
        self.english_pattern = re.compile(r'^[a-zA-Z0-9\s\-_.,!?()[\]{}:;"\'@#$%^&*+=<>/\\|`~★🔒🔐🌸📊⚠️❌🔥💀]*$')
        self.non_english_pattern = re.compile(r'[А-Яа-я\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff]')
    
    def _initialize_text_constants(self) -> Dict[str, str]:
        """Initialize all English text constants"""
        return {
            # Application Titles
            'APP_TITLE_HOST': "POLLY'S TUNNELS - SECURE CHAT HOST",
            'APP_TITLE_CLIENT': "Polly Tunnels - Secure Communication Client",
            'APP_SUBTITLE_HOST': "Creates secure chat rooms and shares credentials",
            'APP_SUBTITLE_CLIENT': "Professional secure messaging application with end-to-end encryption",
            'APP_FEATURES': "WITH REGISTRATION & APPROVAL SYSTEM\nWITH CHAT HISTORY & FILE SHARING & VIDEO CHAT\nMAXIMUM SECURITY - TOR ONLY - ZERO TRACE",
            
            # Main Interface
            'CLASSIFIED_BANNER': "★ ★ ★ CLASSIFIED - SECURE OPERATIONS - TOP SECRET ★ ★ ★",
            'HOST': "HOST",
            'COMMAND_CENTER': "COMMAND CENTER",
            'OPERATIONS': "OPERATIONS",
            'RECENT_OPERATIONS': "RECENT OPERATIONS",
            
            # Buttons
            'NEW_SECURE_CHANNEL': "NEW SECURE CHANNEL",
            'USER_MONITORING': "USER MONITORING",
            'MISSION_HISTORY': "MISSION HISTORY",
            'INITIATE': "INITIATE",
            'RETURN_TO_BASE': "RETURN TO BASE",
            'ACCESS_CLASSIFIED_DATA': "ACCESS CLASSIFIED DATA",
            'CANCEL': "CANCEL",
            'AUTHENTICATE': "AUTHENTICATE",
            
            # Menu Items
            'NEW_OPERATION': "New Operation",
            'DISCONNECT': "Disconnect",
            'SECURE_EXIT': "Secure Exit",
            'SECURITY': "SECURITY",
            'AUTO_DECRYPT': "Auto-Decrypt Intel",
            
            # Main Content
            'SECURE_COMMAND_HOST': "SECURE COMMAND HOST",
            'CLASSIFIED_COMM_SYSTEM': "CLASSIFIED COMMUNICATION SYSTEM",
            'ACTIVE_CHANNELS': "ACTIVE CHANNELS",
            'MILITARY_ENCRYPTION': "MILITARY ENCRYPTION",
            'ANONYMOUS_ROUTING': "ANONYMOUS ROUTING",
            'CLASSIFIED_OPERATIONS': "CLASSIFIED OPERATIONS",
            
            # Action Cards
            'CREATE_SECURE_CHANNEL': "CREATE SECURE CHANNEL",
            'CREATE_CHANNEL_DESC': "Establish new encrypted communication channel with agent registration",
            'MANAGE_AGENTS': "MANAGE AGENTS",
            'MANAGE_AGENTS_DESC': "Approve or deny agent access requests to classified channels",
            'ACCESS_CHANNELS': "ACCESS CHANNELS",
            'ACCESS_CHANNELS_DESC': "Access existing secure communication channels",
            
            # Status
            'SYSTEM_READY': "SYSTEM READY - SECURE CHANNELS OPERATIONAL",
            
            # Authentication
            'ENTER_PASSWORD': "Enter Master Password:",
            'MASTER_PASSWORD': "MASTER PASSWORD:",
            'CLASSIFIED_ACCESS_CONTROL': "CLASSIFIED ACCESS CONTROL",
            'ENTER_MASTER_PASSWORD_ACCESS': "Enter Master Password to Access Classified Data",
            'SHOW_PASSWORD': "Show Password",
            'ACCESS_DENIED': "ACCESS DENIED",
            'INVALID_PASSWORD': "Invalid password!",
            'AUTHENTICATION_FAILED': "Authentication failed",
            'MASTER_PASSWORD_REQUIRED': "Master password required",
            
            # Security Messages
            'EMERGENCY_WIPE': "EMERGENCY WIPE",
            'DATA_DESTROYED': "🔥 All classified data has been securely destroyed!",
            'DISCONNECTED': "DISCONNECTED",
            'SECURE_CHANNEL_TERMINATED': "Secure channel terminated.",
            'SELF_DESTRUCT_ACTIVATED': "SELF-DESTRUCT ACTIVATED",
            'MAX_ATTEMPTS_EXCEEDED': "🔥 Maximum attempts exceeded!\n\nAll classified data will be destroyed for security.",
            'INVALID_MASTER_PASSWORD': "❌ Invalid master password\n\nAttempts remaining: {attempts}\nFile will self-destruct after {attempts} more failed attempts",
            'WARNING_ATTEMPTS_REMAINING': "⚠️ WARNING: {attempts} attempts remaining before self-destruct",
            
            # Setup and Configuration
            'SECURITY_SETUP_REQUIRED': "★ ★ ★ SECURITY SETUP REQUIRED - FIRST TIME SETUP ★ ★ ★",
            'SECURITY_SETUP': "🔐 SECURITY SETUP",
            'CONFIGURE_MULTILAYER_SECURITY': "Configure multi-layer security for maximum protection",
            'STARTUP_PASSWORD_REQUIRED': "STARTUP PASSWORD (Required)",
            'PIN_CODE_OPTIONAL': "PIN CODE (4-6 digits, Optional)",
            'SETUP_ERROR': "SETUP ERROR",
            'STARTUP_PASSWORD_REQUIRED_ERROR': "Startup password is required!",
            'STARTUP_PASSWORD_LENGTH_ERROR': "Startup password must be at least 8 characters!",
            'PIN_DIGITS_ERROR': "PIN must be 4-6 digits!",
            'SETUP_COMPLETE': "SETUP COMPLETE",
            'SETUP_COMPLETE_MESSAGE': "Security setup completed successfully!\n\nRemember your passwords - they cannot be recovered!",
            
            # Authentication Screens
            'CLASSIFIED_ACCESS_AUTH_REQUIRED': "★ ★ ★ CLASSIFIED ACCESS - AUTHENTICATION REQUIRED ★ ★ ★",
            'SECURE_ACCESS': "🔐 SECURE ACCESS",
            'FAILED_ATTEMPTS_WARNING': "⚠️ {attempts} failed attempts. {remaining} attempts remaining.",
            'INVALID_PASSWORD_ATTEMPTS': "Invalid password!\n{attempts} attempts remaining.",
            'SECURITY_BREACH': "SECURITY BREACH",
            'MAX_ATTEMPTS_SECURITY_WIPE': "Maximum attempts exceeded. Initiating security wipe...",
            'INVALID_PIN': "Invalid PIN!",
            
            # Session Management
            'SESSION_LOCKED_TIMEOUT': "★ ★ ★ SESSION LOCKED - TIMEOUT EXCEEDED ★ ★ ★",
            'SESSION_LOCKED': "🔒 SESSION LOCKED",
            'SESSION_TIMEOUT': "SESSION TIMEOUT",
            'SESSION_TIMEOUT_MESSAGE': "Session has timed out for security.\nPlease re-authenticate.",
            
            # Emergency Operations
            'EMERGENCY_WIPE_ACTIVATED': "🔥 EMERGENCY WIPE ACTIVATED!\n\nThis will permanently destroy ALL classified data.\nThis action cannot be undone.\n\nContinue with emergency wipe?",
            'WIPE_COMPLETE': "WIPE COMPLETE",
            'WIPE_FAILED': "WIPE FAILED",
            'WIPE_FAILED_MESSAGE': "Emergency wipe failed. Manual deletion may be required.",
            
            # Authorization and Access
            'SECRET_AUTHORIZATION_REQUEST': "SECRET - AUTHORIZATION REQUEST - AUTHORIZED PERSONNEL ONLY",
            'AUTHORIZATION_ERROR': "AUTHORIZATION ERROR",
            'COMMAND_REGISTRY_ID_REQUIRED': "COMMAND REGISTRY ID REQUIRED",
            'INCOMPLETE_CREDENTIALS': "INCOMPLETE CREDENTIALS",
            'AUTHORIZATION_APPROVED_MISSING_CREDENTIALS': "Authorization approved but chat credentials missing.\nContact intelligence command for channel details.",
            'ACCESS_DENIED_COMPROMISED': "AGENT DESIGNATION COMPROMISED - ACCESS REVOKED",
            'ACCESS_DENIED_REJECTED': "AUTHORIZATION REQUEST REJECTED",
            'NO_REQUEST': "NO REQUEST",
            'NO_ACTIVE_AUTHORIZATION': "NO ACTIVE AUTHORIZATION REQUEST",
            'ERROR': "ERROR",
            'INVALID_COMMAND_REGISTRY': "INVALID COMMAND REGISTRY",
            'ACCESS_DENIED_REQUEST_REJECTED': "AUTHORIZATION REQUEST REJECTED",
            'PENDING': "PENDING",
            'AUTHORIZATION_UNDER_REVIEW': "AUTHORIZATION REQUEST STILL UNDER REVIEW",
            'STATUS_CHECK_FAILED': "STATUS CHECK FAILED: {error}",
            
            # Connection and Communication
            'AUTHORIZATION_GRANTED': "AUTHORIZATION GRANTED",
            'AUTHORIZATION_GRANTED_MESSAGE': "AUTHORIZATION GRANTED\n\nAGENT: {username}\nCLEARANCE LEVEL: {user_role}\nCHANNEL: {channel}\n\nOPERATION SAVED TO ARCHIVE\nSECURE CHANNEL ACCESS ACTIVATED",
            'CONNECTION_ESTABLISHED': "CONNECTION ESTABLISHED",
            'SUCCESSFUL_CHANNEL_CONNECTION': "SUCCESSFUL CONNECTION TO CHANNEL\n\nAGENT: {username}\nCHANNEL: {channel}\nSTATUS: ACTIVE\n\nSecure communication channel is now active.",
            'ACCESS_REVOKED': "ACCESS REVOKED",
            'AUTHORIZATION_REVOKED_MESSAGE': "Authorization for this channel has been revoked.\nContact command.",
            'CONNECTION_ERROR': "CONNECTION ERROR",
            'CHANNEL_STATUS_CHECK_FAILED': "Unable to check channel status",
            'VERIFICATION_UNAVAILABLE': "VERIFICATION UNAVAILABLE",
            'VERIFICATION_UNAVAILABLE_MESSAGE': "Unable to verify authorization status.\nChannel connection may be unsafe.\n\nError: {error}",
            'CONNECTION_FAILED': "CONNECTION FAILED",
            'UNABLE_TO_CONNECT': "Unable to connect to channel:\n{error}",
            
            # Archive and History
            'REMOVE_FROM_ARCHIVE': "REMOVE FROM ARCHIVE",
            'REMOVE_FROM_ARCHIVE_MESSAGE': "Remove this channel from your secure archive?\n\nChannel: {channel}\nAgent: {agent}\n\nThis will permanently delete the local record.",
            'ACCESS_DENIED_HISTORY_PASSWORD': "Invalid history password",
            
            # Archive and History Interface
            'SECRET_WAITING_AUTHORIZATION': "SECRET - AWAITING AUTHORIZATION - MAINTAIN SECRECY",
            'SECRET_OPERATIONS_ARCHIVE': "★ ★ ★ SECRET - OPERATIONS ARCHIVE - TOP SECRET ★ ★ ★",
            'OPERATIONS_ARCHIVE': "OPERATIONS ARCHIVE",
            'RETURN_TO_TERMINAL': "← RETURN TO TERMINAL",
            'NEW_AUTHORIZATION': "NEW AUTHORIZATION",
            'ARCHIVE_STATUS': "ARCHIVE STATUS",
            'TOTAL_OPERATIONS': "TOTAL OPERATIONS: {count}",
            'APPROVED_COUNT': "APPROVED: {count}",
            'AGENT_STATUS': "AGENT: {username}",
            'SECRET_OPERATIONS_ARCHIVE_TITLE': "SECRET OPERATIONS ARCHIVE",
            'APPROVED_COMMUNICATION_CHANNELS': "APPROVED COMMUNICATION CHANNELS ({count} available)",
            'NO_APPROVED_OPERATIONS': "NO APPROVED OPERATIONS",
            'REQUEST_AUTHORIZATION_ACCESS': "REQUEST AUTHORIZATION FOR ACCESS TO SECRET CHANNELS",
            'REQUEST_AUTHORIZATION': "REQUEST AUTHORIZATION",
            'CHANNEL_ID': "CHANNEL ID",
            'REGISTRY_ID': "REGISTRY ID", 
            'ACTIONS': "ACTIONS",
            'CONNECT': "CONNECT",
            'DELETE': "DELETE",
            'SECRET_OPERATIONS_ARCHIVE_PERSONNEL': "SECRET - OPERATIONS ARCHIVE - AUTHORIZED PERSONNEL ONLY",
            
            # Theme and Interface
            'WINTER_CHERRY_BLOSSOM_DEFAULT': "✓ Winter Cherry Blossom (Default)",
            
            # Errors and Warnings
            'SYSTEM_ERROR': "System Error",
            'ERROR_GENERIC': "ERROR",
            
            # Symbols and Icons
            'CHERRY_BLOSSOM': "🌸",
            'LOCK_ICON': "🔒",
            'SECURITY_ICON': "🔐",
            'STATS_ICON': "📊",
            'WARNING_ICON': "⚠️",
            'DENIED_ICON': "❌",
            'FIRE_ICON': "🔥",
            'SKULL_ICON': "💀"
        }
    
    def get_text_constant(self, key: str) -> str:
        """Get English text constant by key"""
        return self.text_constants.get(key, key)  # Return key if not found
    
    def validate_english_text(self, text: str) -> bool:
        """Validate that text contains only English characters and common symbols"""
        if not isinstance(text, str):
            return True  # Non-string values are acceptable
        
        # Allow empty strings
        if not text.strip():
            return True
            
        # Check for non-English characters
        return not self.non_english_pattern.search(text)
    
    def apply_english_labels(self, widget: tk.Widget) -> None:
        """Apply English labels to a widget if it has text configuration"""
        if hasattr(widget, 'configure') and hasattr(widget, 'cget'):
            try:
                # Check if widget has text configuration
                current_text = widget.cget('text')
                if current_text and not self.validate_english_text(current_text):
                    # Try to find English equivalent or use placeholder
                    english_text = self._convert_to_english(current_text)
                    widget.configure(text=english_text)
            except:
                pass  # Widget doesn't support text configuration
    
    def _convert_to_english(self, text: str) -> str:
        """Convert non-English text to English equivalent"""
        # Russian to English translations
        russian_translations = {
            'СЕКРЕТНО - ЗАПРОС АВТОРИЗАЦИИ - ТОЛЬКО УПОЛНОМОЧЕННЫЙ ПЕРСОНАЛ': 'SECRET - AUTHORIZATION REQUEST - AUTHORIZED PERSONNEL ONLY',
            'АВТОРИЗАЦИЯ ОДОБРЕНА': 'AUTHORIZATION GRANTED',
            'АВТОРИЗАЦИЯ ПРЕДОСТАВЛЕНА': 'AUTHORIZATION GRANTED',
            'АГЕНТ': 'AGENT',
            'КАНАЛ': 'CHANNEL',
            'ДОПУСК': 'CLEARANCE',
            'СОВЕРШЕННО СЕКРЕТНО': 'TOP SECRET',
            'Соединение установлено с защищенным каналом.': 'Connection established to secure channel.',
            'ПОДКЛЮЧЕНИЕ УСТАНОВЛЕНО': 'CONNECTION ESTABLISHED',
            'УСПЕШНОЕ ПОДКЛЮЧЕНИЕ К КАНАЛУ': 'SUCCESSFUL CONNECTION TO CHANNEL',
            'СТАТУС': 'STATUS',
            'АКТИВЕН': 'ACTIVE',
            'Защищенный канал связи теперь активен.': 'Secure communication channel is now active.',
            'ДОСТУП ОТОЗВАН': 'ACCESS REVOKED',
            'Авторизация для данного канала была отозвана.': 'Authorization for this channel has been revoked.',
            'Обратитесь к командованию.': 'Contact command.',
            'ОШИБКА СОЕДИНЕНИЯ': 'CONNECTION ERROR',
            'Не удается проверить статус канала': 'Unable to check channel status',
            'ПРОВЕРКА НЕДОСТУПНА': 'VERIFICATION UNAVAILABLE',
            'Не удается проверить статус авторизации.': 'Unable to verify authorization status.',
            'Подключение к каналу может быть небезопасным.': 'Channel connection may be unsafe.',
            'ОШИБКА ПОДКЛЮЧЕНИЯ': 'CONNECTION FAILED',
            'Не удается подключиться к каналу:': 'Unable to connect to channel:',
            'УДАЛИТЬ ИЗ АРХИВА': 'REMOVE FROM ARCHIVE',
            'Удалить этот канал из вашего защищенного архива?': 'Remove this channel from your secure archive?',
            'Это навсегда удалит локальную запись.': 'This will permanently delete the local record.'
        }
        
        # Check for exact matches first
        if text in russian_translations:
            return russian_translations[text]
        
        # Check for partial matches or patterns
        for russian, english in russian_translations.items():
            if russian in text:
                text = text.replace(russian, english)
        
        # If still contains non-English characters, provide generic English text
        if not self.validate_english_text(text):
            return "SECURE OPERATION"  # Generic fallback
        
        return text
    
    def get_all_text_constants(self) -> Dict[str, str]:
        """Get all text constants for reference"""
        return self.text_constants.copy()
    
    def add_text_constant(self, key: str, value: str) -> bool:
        """Add a new text constant if it's valid English"""
        if self.validate_english_text(value):
            self.text_constants[key] = value
            return True
        return False
    
    def update_text_constant(self, key: str, value: str) -> bool:
        """Update an existing text constant if it's valid English"""
        if key in self.text_constants and self.validate_english_text(value):
            self.text_constants[key] = value
            return True
        return False

# Global instance for easy access
english_manager = EnglishLanguageManager()