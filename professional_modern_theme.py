"""
ENTERPRISE PROFESSIONAL THEME SYSTEM
Premium government-grade UI theme for classified software systems
Microsoft-level design quality with enterprise polish and sophistication
"""

import tkinter as tk
from tkinter import ttk
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, List, Any


@dataclass
class EnterpriseThemeConfig:
    """Enterprise theme configuration data model"""
    name: str
    version: str
    colors: Dict[str, str]
    fonts: Dict[str, Tuple[str, int, str]]
    spacing: Dict[str, int]
    animations: Dict[str, Dict[str, Any]]


@dataclass
class EnterpriseComponentStyle:
    """Enterprise component style configuration model"""
    background: str
    foreground: str
    border: str
    padding: Tuple[int, int]
    border_radius: int
    font: Tuple[str, int, str]
    hover_state: Optional[Dict[str, str]] = None
    focus_state: Optional[Dict[str, str]] = None


class ProfessionalModernTheme:
    """ENTERPRISE PROFESSIONAL MODERN THEME - Government-grade design system"""

    def __init__(self):
        self.name = "Enterprise Professional"
        self.version = "2.0"

    def get_color_palette(self):
        """Get the ENTERPRISE Professional Modern color palette - Microsoft-level quality"""
        return {
            # ENTERPRISE PRIMARY COLORS - Government grade
            'bg': '#f8f9fa',                    # Microsoft-style light background
            'surface': '#ffffff',               # Pure white surfaces
            'surface_elevated': '#ffffff',      # Elevated surfaces with shadows
            'surface_variant': '#f1f3f4',       # Variant surface color

            # ENTERPRISE TEXT COLORS - Maximum readability
            'on_surface': '#202124',            # Primary text - Google/Microsoft standard
            'on_surface_variant': '#5f6368',    # Secondary text
            'on_surface_disabled': '#4b5563',   # Disabled text - better contrast

            # ENTERPRISE BRAND COLORS - Professional blue system
            'primary': '#1a73e8',               # Google Blue / Microsoft Blue
            'primary_variant': '#1557b0',       # Darker primary
            'on_primary': '#ffffff',            # Text on primary
            'primary_container': '#e8f0fe',     # Light primary container
            'on_primary_container': '#041e49',  # Text on primary container

            # ENTERPRISE SECONDARY COLORS - Professional gray system
            'secondary': '#5f6368',             # Professional gray
            'secondary_variant': '#3c4043',     # Darker secondary
            'on_secondary': '#ffffff',          # Text on secondary
            'secondary_container': '#e8eaed',   # Light secondary container
            'on_secondary_container': '#1f1f1f', # Text on secondary container

            # ENTERPRISE STATUS COLORS - Government standard
            'success': '#137333',               # Google Green
            'success_container': '#e6f4ea',     # Light success container
            'on_success': '#ffffff',            # Text on success
            'on_success_container': '#002111',  # Text on success container

            'warning': '#f9ab00',               # Google Yellow
            'warning_container': '#fef7e0',     # Light warning container
            'on_warning': '#000000',            # Text on warning
            'on_warning_container': '#3d2e00',  # Text on warning container

            'error': '#d93025',                 # Google Red
            'error_container': '#fce8e6',       # Light error container
            'on_error': '#ffffff',              # Text on error
            'on_error_container': '#410e0b',    # Text on error container

            'info': '#1a73e8',                  # Information blue
            'info_container': '#e8f0fe',        # Light info container
            'on_info': '#ffffff',               # Text on info
            'on_info_container': '#041e49',     # Text on info container

            # ENTERPRISE INTERACTIVE COLORS - Premium button system
            'interactive': '#1a73e8',           # Primary interactive
            'interactive_hover': '#1557b0',     # Hover state
            'interactive_pressed': '#1142a0',   # Pressed state
            'interactive_disabled': '#f1f3f4',  # Disabled state
            'on_interactive_disabled': '#4b5563', # Text on disabled - better contrast

            # ENTERPRISE OUTLINE COLORS - Professional borders
            'outline': '#6b7280',               # Standard outline - better contrast
            'outline_variant': '#6b7280',       # Variant outline - better contrast
            'outline_focus': '#1a73e8',         # Focus outline

            # ENTERPRISE SHADOW COLORS - Depth and elevation
            'shadow': 'rgba(60, 64, 67, 0.3)',     # Standard shadow
            'shadow_light': 'rgba(60, 64, 67, 0.15)', # Light shadow
            'shadow_heavy': 'rgba(60, 64, 67, 0.5)',  # Heavy shadow

            # CLASSIFIED SYSTEM COLORS - Government security levels
            'classified_top_secret': '#d93025',     # Top Secret Red
            'classified_secret': '#f9ab00',         # Secret Yellow
            'classified_confidential': '#1a73e8',   # Confidential Blue
            'classified_unclassified': '#137333',   # Unclassified Green

            # LEGACY COMPATIBILITY COLORS - For backward compatibility
            'accent': '#1a73e8',                # Maps to primary
            'accent_light': '#e8f0fe',          # Maps to primary_container
            'fg': '#202124',                    # Maps to on_surface
            'card_bg': '#ffffff',               # Maps to surface
            'sidebar_bg': '#f8f9fa',            # Maps to bg
            'sidebar_fg': '#5f6368',            # Maps to on_surface_variant
            'button_bg': '#1a73e8',             # Maps to primary
            'button_fg': '#ffffff',             # Maps to on_primary
            'button_hover': '#1557b0',          # Maps to primary_variant
            'button_active': '#1142a0',         # Maps to interactive_pressed
            'button_secondary_bg': '#f1f3f4',   # Maps to surface_variant
            'button_secondary_fg': '#202124',   # Maps to on_surface
            'button_secondary_hover': '#e8eaed', # Maps to secondary_container
            'button_danger_bg': '#d93025',      # Maps to error
            'button_danger_fg': '#ffffff',      # Maps to on_error
            'button_danger_hover': '#b52d20',   # Darker error
            'entry_bg': '#ffffff',              # Maps to surface
            'entry_fg': '#202124',              # Maps to on_surface
            'entry_border': '#dadce0',          # Maps to outline
            'entry_focus': '#1a73e8',           # Maps to outline_focus
            'entry_placeholder': '#4b5563',     # Maps to on_surface_disabled - better contrast
            'success': '#137333',               # Maps to success
            'warning': '#f9ab00',               # Maps to warning
            'danger': '#d93025',                # Maps to error
            'info': '#1a73e8',                  # Maps to info
            'border': '#6b7280',                # Maps to outline - better contrast
            'separator': '#6b7280',             # Maps to outline_variant - better contrast
            'border_focus': '#1a73e8',          # Maps to outline_focus
            'primary_light': '#e8f0fe',         # Maps to primary_container
            'secondary': '#5f6368',             # Maps to secondary
            'gray_50': '#f8f9fa',              # Light gray
            'gray_100': '#f1f3f4',             # Very light gray
            'gray_200': '#e8eaed',             # Light gray
            'gray_300': '#dadce0',             # Medium light gray
            'gray_400': '#bdc1c6',             # Medium gray
            'gray_500': '#4b5563',             # Medium dark gray - better contrast
            'gray_600': '#80868b',             # Dark gray
            'gray_700': '#5f6368',             # Very dark gray
            'gray_800': '#3c4043',             # Almost black
            'gray_900': '#202124',             # Darkest gray
            'classified': '#d93025',            # Maps to classified_top_secret
        }

    def get_font_config(self, font_type='body'):
        """Get ENTERPRISE Professional typography configuration - Microsoft-level quality"""
        fonts = {
            # ENTERPRISE DISPLAY FONTS - Premium hierarchy
            'display': ('Segoe UI', 40, 'normal'),         # Large display text
            'display_large': ('Segoe UI', 48, 'normal'),   # Extra large display
            'display_medium': ('Segoe UI', 36, 'normal'),  # Medium display
            'display_small': ('Segoe UI', 32, 'normal'),   # Small display

            # ENTERPRISE HEADLINE FONTS - Professional headings
            'headline_large': ('Segoe UI', 28, 'normal'),  # Large headlines
            'headline_medium': ('Segoe UI', 24, 'normal'), # Medium headlines
            'headline_small': ('Segoe UI', 20, 'normal'),  # Small headlines

            # ENTERPRISE TITLE FONTS - Section titles
            'title_large': ('Segoe UI', 18, 'bold'),       # Large titles
            'title_medium': ('Segoe UI', 16, 'bold'),      # Medium titles
            'title_small': ('Segoe UI', 14, 'bold'),       # Small titles

            # ENTERPRISE BODY FONTS - Content text
            'body_large': ('Segoe UI', 16, 'normal'),      # Large body text
            'body_medium': ('Segoe UI', 14, 'normal'),     # Medium body text
            'body_small': ('Segoe UI', 12, 'normal'),      # Small body text

            # ENTERPRISE LABEL FONTS - UI labels
            'label_large': ('Segoe UI', 14, 'bold'),       # Large labels
            'label_medium': ('Segoe UI', 12, 'bold'),      # Medium labels
            'label_small': ('Segoe UI', 11, 'bold'),       # Small labels

            # ENTERPRISE MONOSPACE FONTS - Technical content
            'monospace_large': ('Consolas', 14, 'normal'), # Large monospace
            'monospace_medium': ('Consolas', 12, 'normal'), # Medium monospace
            'monospace_small': ('Consolas', 10, 'normal'), # Small monospace

            # LEGACY COMPATIBILITY FONTS - For backward compatibility
            'title': ('Segoe UI', 24, 'bold'),             # Maps to headline_medium
            'heading': ('Segoe UI', 20, 'normal'),         # Maps to headline_small
            'heading_1': ('Segoe UI', 20, 'bold'),         # Maps to title_large
            'heading_2': ('Segoe UI', 18, 'bold'),         # Maps to title_large
            'heading_3': ('Segoe UI', 16, 'bold'),         # Maps to title_medium
            'subheading': ('Segoe UI', 14, 'bold'),        # Maps to title_small
            'body': ('Segoe UI', 14, 'normal'),            # Maps to body_medium
            'caption': ('Segoe UI', 12, 'normal'),         # Maps to body_small
            'button': ('Segoe UI', 14, 'bold'),            # Button text
            'input': ('Segoe UI', 14, 'normal'),           # Input text
            'label': ('Segoe UI', 12, 'bold'),             # Form labels
            'status': ('Segoe UI', 12, 'normal'),          # Status text
            'monospace': ('Consolas', 12, 'normal'),       # Code text
            'terminal': ('Consolas', 12, 'normal'),        # Terminal text
        }
        return fonts.get(font_type, fonts['body_medium'])

    def get_spacing_config(self):
        """Get ENTERPRISE Professional spacing configuration - Microsoft Design System"""
        return {
            # ENTERPRISE BASE SPACING - 8px grid system (Microsoft standard)
            'xs': 4,      # Extra small spacing
            'sm': 8,      # Small spacing
            'md': 16,     # Medium spacing
            'lg': 24,     # Large spacing
            'xl': 32,     # Extra large spacing
            'xxl': 48,    # Double extra large spacing
            'xxxl': 64,   # Triple extra large spacing

            # ENTERPRISE COMPONENT SPACING - Premium measurements
            'component_padding_xs': 8,      # Extra small component padding
            'component_padding_sm': 12,     # Small component padding
            'component_padding_md': 16,     # Medium component padding
            'component_padding_lg': 24,     # Large component padding
            'component_padding_xl': 32,     # Extra large component padding

            # ENTERPRISE BUTTON SPACING - Professional button measurements
            'button_padding_horizontal': 24,    # Button horizontal padding
            'button_padding_vertical': 12,      # Button vertical padding
            'button_min_width': 120,            # Minimum button width
            'button_height': 48,                # Standard button height

            # ENTERPRISE INPUT SPACING - Form field measurements
            'input_padding_horizontal': 16,     # Input horizontal padding
            'input_padding_vertical': 12,       # Input vertical padding
            'input_height': 48,                 # Standard input height

            # ENTERPRISE CARD SPACING - Card and container measurements
            'card_padding': 24,                 # Card content padding
            'card_margin': 16,                  # Card margins
            'section_spacing': 32,              # Section spacing
            'content_max_width': 1200,          # Maximum content width

            # ENTERPRISE BORDER RADIUS - Modern rounded corners
            'border_radius_xs': 4,              # Extra small radius
            'border_radius_sm': 8,              # Small radius
            'border_radius_md': 12,             # Medium radius
            'border_radius_lg': 16,             # Large radius
            'border_radius_xl': 24,             # Extra large radius

            # ENTERPRISE ELEVATION - Shadow and depth
            'elevation_1': 2,                   # Subtle elevation
            'elevation_2': 4,                   # Standard elevation
            'elevation_3': 8,                   # Medium elevation
            'elevation_4': 16,                  # High elevation
            'elevation_5': 24,                  # Maximum elevation
        }

    def apply_theme(self, widget, widget_type='default'):
        """Apply ENTERPRISE Professional Modern theme to a widget"""
        colors = self.get_color_palette()

        if isinstance(widget, tk.Button):
            widget.configure(
                bg=colors['interactive'],
                fg=colors['on_primary'],
                font=self.get_font_config('button'),
                relief='flat',
                borderwidth=0,
                highlightthickness=0,
                activebackground=colors['interactive_hover'],
                activeforeground=colors['on_primary'],
                cursor='hand2',
                padx=24,
                pady=12
            )
        elif isinstance(widget, tk.Entry):
            widget.configure(
                bg=colors['surface'],
                fg=colors['on_surface'],
                font=self.get_font_config('body_medium'),
                relief='solid',
                borderwidth=1,
                highlightthickness=2,
                highlightcolor=colors['outline_focus'],
                highlightbackground=colors['outline'],
                insertbackground=colors['on_surface'],
                selectbackground=colors['primary_container'],
                selectforeground=colors['on_primary_container'],
                bd=1
            )
        elif isinstance(widget, tk.Text):
            widget.configure(
                bg=colors['surface'],
                fg=colors['on_surface'],
                font=self.get_font_config('body_medium'),
                relief='solid',
                borderwidth=1,
                highlightthickness=2,
                highlightcolor=colors['outline_focus'],
                highlightbackground=colors['outline'],
                insertbackground=colors['on_surface'],
                selectbackground=colors['primary_container'],
                selectforeground=colors['on_primary_container'],
                wrap=tk.WORD,
                padx=16,
                pady=12
            )
        elif isinstance(widget, tk.Frame):
            widget.configure(bg=colors['surface'])
        elif isinstance(widget, tk.Label):
            widget.configure(
                bg=colors['surface'],
                fg=colors['on_surface'],
                font=self.get_font_config('body_medium')
            )
        elif isinstance(widget, tk.Toplevel) or isinstance(widget, tk.Tk):
            widget.configure(bg=colors['bg'])
        elif isinstance(widget, tk.Listbox):
            widget.configure(
                bg=colors['surface'],
                fg=colors['on_surface'],
                font=self.get_font_config('body_medium'),
                selectbackground=colors['primary_container'],
                selectforeground=colors['on_primary_container'],
                relief='solid',
                borderwidth=1,
                highlightcolor=colors['outline_focus'],
                highlightbackground=colors['outline'],
                activestyle='none'
            )
        elif isinstance(widget, tk.Scrollbar):
            widget.configure(
                bg=colors['surface_variant'],
                troughcolor=colors['bg'],
                activebackground=colors['outline'],
                relief='flat',
                borderwidth=0,
                highlightthickness=0
            )


class ProfessionalModernComponents:
    """ENTERPRISE PROFESSIONAL MODERN COMPONENTS - Government-grade UI components"""

    def __init__(self, theme):
        self.theme = theme
        self.colors = theme.get_color_palette()
        self.spacing = theme.get_spacing_config()

    def get_font_config(self, font_type='body'):
        """Delegate to theme's font config"""
        return self.theme.get_font_config(font_type)

    def create_enterprise_button(self, parent, text, command=None, style='primary', size='medium', **kwargs):
        """Create ENTERPRISE-GRADE styled button - Microsoft/Government quality"""
        if command is None:
            print(f"WARNING: Enterprise Button '{text}' created without command!")

        button = tk.Button(parent, text=text, command=command, **kwargs)

        # ENTERPRISE SIZE CONFIGURATIONS
        size_configs = {
            'small': {
                'font': self.theme.get_font_config('label_medium'),
                'padx': 16, 'pady': 8, 'height': 32
            },
            'medium': {
                'font': self.theme.get_font_config('label_large'),
                'padx': 24, 'pady': 12, 'height': 48
            },
            'large': {
                'font': self.theme.get_font_config('title_small'),
                'padx': 32, 'pady': 16, 'height': 56
            }
        }

        size_config = size_configs.get(size, size_configs['medium'])

        # ENTERPRISE STYLE CONFIGURATIONS - Premium button variants
        if style == 'primary':
            button.configure(
                bg=self.colors['primary'],
                fg=self.colors['on_primary'],
                activebackground=self.colors['primary_variant'],
                activeforeground=self.colors['on_primary']
            )
        elif style == 'secondary':
            button.configure(
                bg=self.colors['secondary_container'],
                fg=self.colors['on_secondary_container'],
                activebackground=self.colors['outline'],
                activeforeground=self.colors['on_secondary_container']
            )
        elif style == 'danger':
            button.configure(
                bg=self.colors['error'],
                fg=self.colors['on_error'],
                activebackground=self.colors['error_container'],
                activeforeground=self.colors['on_error']
            )
        elif style == 'success':
            button.configure(
                bg=self.colors['success'],
                fg=self.colors['on_success'],
                activebackground=self.colors['success_container'],
                activeforeground=self.colors['on_success']
            )
        elif style == 'ghost':
            button.configure(
                bg=self.colors['surface'],
                fg=self.colors['primary'],
                activebackground=self.colors['primary_container'],
                activeforeground=self.colors['on_primary_container'],
                relief='solid',
                borderwidth=2,
                highlightbackground=self.colors['primary'],
                highlightcolor=self.colors['primary']
            )
        elif style == 'outline':
            button.configure(
                bg=self.colors['surface'],
                fg=self.colors['on_surface'],
                activebackground=self.colors['surface_variant'],
                activeforeground=self.colors['on_surface'],
                relief='solid',
                borderwidth=2,
                highlightbackground=self.colors['outline'],
                highlightcolor=self.colors['outline_focus']
            )

        # Apply ENTERPRISE base styling
        button.configure(
            font=size_config['font'],
            relief='flat',
            borderwidth=0,
            highlightthickness=0,
            cursor='hand2',
            padx=size_config['padx'],
            pady=size_config['pady']
        )

        # ENTERPRISE DISABLED STATE HANDLING
        def update_disabled_state():
            """Update button appearance based on disabled state"""
            if button['state'] == 'disabled':
                # Apply disabled styling
                button.configure(
                    bg=self.colors['interactive_disabled'],
                    fg=self.colors['on_interactive_disabled'],
                    cursor='',  # Remove hand cursor for disabled buttons
                    activebackground=self.colors['interactive_disabled'],
                    activeforeground=self.colors['on_interactive_disabled']
                )
            else:
                # Restore normal styling based on style
                if style == 'primary':
                    button.configure(
                        bg=self.colors['primary'],
                        fg=self.colors['on_primary'],
                        cursor='hand2',
                        activebackground=self.colors['primary_variant'],
                        activeforeground=self.colors['on_primary']
                    )
                elif style == 'secondary':
                    button.configure(
                        bg=self.colors['secondary_container'],
                        fg=self.colors['on_secondary_container'],
                        cursor='hand2',
                        activebackground=self.colors['outline'],
                        activeforeground=self.colors['on_secondary_container']
                    )
                elif style == 'danger':
                    button.configure(
                        bg=self.colors['error'],
                        fg=self.colors['on_error'],
                        cursor='hand2',
                        activebackground=self.colors['error_container'],
                        activeforeground=self.colors['on_error']
                    )
                elif style == 'success':
                    button.configure(
                        bg=self.colors['success'],
                        fg=self.colors['on_success'],
                        cursor='hand2',
                        activebackground=self.colors['success_container'],
                        activeforeground=self.colors['on_success']
                    )
                elif style == 'ghost':
                    button.configure(
                        bg=self.colors['surface'],
                        fg=self.colors['primary'],
                        cursor='hand2',
                        activebackground=self.colors['primary_container'],
                        activeforeground=self.colors['on_primary_container']
                    )
                elif style == 'outline':
                    button.configure(
                        bg=self.colors['surface'],
                        fg=self.colors['on_surface'],
                        cursor='hand2',
                        activebackground=self.colors['surface_variant'],
                        activeforeground=self.colors['on_surface']
                    )

        # Override the configure method to handle state changes
        original_configure = button.configure
        def enhanced_configure(**kwargs):
            result = original_configure(**kwargs)
            if 'state' in kwargs:
                update_disabled_state()
            return result
        button.configure = enhanced_configure

        # Initial state setup
        update_disabled_state()

        # ENTERPRISE HOVER EFFECTS - Premium interactions
        def on_enter(e):
            if button['state'] != 'disabled':
                if style == 'primary':
                    button.configure(bg=self.colors['primary_variant'])
                elif style == 'secondary':
                    button.configure(bg=self.colors['outline'])
                elif style == 'danger':
                    button.configure(bg='#b52d20')  # Darker error
                elif style == 'success':
                    button.configure(bg='#0f5132')  # Darker success
                elif style == 'ghost':
                    button.configure(bg=self.colors['primary_container'])
                elif style == 'outline':
                    button.configure(bg=self.colors['surface_variant'])

        def on_leave(e):
            if button['state'] != 'disabled':
                if style == 'primary':
                    button.configure(bg=self.colors['primary'])
                elif style == 'secondary':
                    button.configure(bg=self.colors['secondary_container'])
                elif style == 'danger':
                    button.configure(bg=self.colors['error'])
                elif style == 'success':
                    button.configure(bg=self.colors['success'])
                elif style == 'ghost':
                    button.configure(bg=self.colors['surface'])
                elif style == 'outline':
                    button.configure(bg=self.colors['surface'])

        def on_press(e):
            if button['state'] != 'disabled':
                if style == 'primary':
                    button.configure(bg=self.colors['interactive_pressed'])
                elif style in ['secondary', 'ghost', 'outline']:
                    button.configure(bg=self.colors['outline_variant'])
                elif style == 'danger':
                    button.configure(bg='#a02622')  # Even darker error
                elif style == 'success':
                    button.configure(bg='#0d4429')  # Even darker success

        def on_release(e):
            if button['state'] != 'disabled':
                on_enter(e)  # Return to hover state

        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)
        button.bind("<Button-1>", on_press)
        button.bind("<ButtonRelease-1>", on_release)

        return button

    def create_enterprise_card(self, parent, title=None, elevation=2, **kwargs):
        """Create REFINED ENTERPRISE CARD - Modern design with subtle shadows"""
        # REFINED CARD CONTAINER - Clean, modern
        card_container = tk.Frame(parent, bg=self.colors['bg'], **kwargs)

        # REFINED SHADOW EFFECT - Subtle depth
        if elevation > 0:
            shadow = tk.Frame(card_container, bg='#e0e0e0', height=elevation)
            shadow.place(x=elevation, y=elevation, relwidth=1.0, relheight=1.0)

        # REFINED MAIN CARD - Clean styling
        card = tk.Frame(card_container, bg=self.colors['surface'], relief='flat', bd=0)
        card.pack(fill=tk.BOTH, expand=True)
        card.lift()  # Ensure card is above shadow

        # REFINED CARD BORDER - Subtle professional outline
        card.configure(highlightbackground=self.colors['outline'], highlightthickness=1)

        if title:
            # REFINED CARD HEADER - Clean typography
            header = tk.Frame(card, bg=self.colors['surface'])
            header.pack(fill=tk.X, padx=24, pady=(20, 0))

            title_label = tk.Label(
                header,
                text=title,
                bg=self.colors['surface'],
                fg=self.colors['on_surface'],
                font=('Segoe UI', 14, 'bold')
            )
            title_label.pack(anchor='w')

            # REFINED SEPARATOR - Subtle divider
            separator = tk.Frame(card, height=1, bg=self.colors['outline_variant'])
            separator.pack(fill=tk.X, padx=24, pady=(12, 0))

        return card_container

    def create_enterprise_input(self, parent, label=None, placeholder="", input_type='text', **kwargs):
        """Create ENTERPRISE-GRADE input field - Government quality"""
        container = tk.Frame(parent, bg=self.colors['surface'])

        if label:
            label_widget = tk.Label(
                container,
                text=label,
                bg=self.colors['surface'],
                fg=self.colors['on_surface'],
                font=self.theme.get_font_config('label_medium')
            )
            label_widget.pack(anchor='w', pady=(0, self.spacing['xs']))

        if input_type == 'password':
            entry = tk.Entry(container, show="*", **kwargs)
        else:
            entry = tk.Entry(container, **kwargs)

        # ENTERPRISE INPUT STYLING
        entry.configure(
            bg=self.colors['surface'],
            fg=self.colors['on_surface'],
            font=self.theme.get_font_config('body_medium'),
            relief='solid',
            borderwidth=2,
            highlightthickness=0,
            insertbackground=self.colors['on_surface'],
            selectbackground=self.colors['primary_container'],
            selectforeground=self.colors['on_primary_container'],
            bd=0
        )

        # Set initial border color
        entry.configure(highlightbackground=self.colors['outline'])

        # ENTERPRISE PLACEHOLDER FUNCTIONALITY
        if placeholder:
            entry.insert(0, placeholder)
            entry.configure(fg=self.colors['on_surface_disabled'])

            def on_focus_in(e):
                if entry.get() == placeholder:
                    entry.delete(0, tk.END)
                    entry.configure(fg=self.colors['on_surface'])
                entry.configure(highlightbackground=self.colors['outline_focus'])

            def on_focus_out(e):
                if not entry.get():
                    entry.insert(0, placeholder)
                    entry.configure(fg=self.colors['on_surface_disabled'])
                entry.configure(highlightbackground=self.colors['outline'])

            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)
        else:
            def on_focus_in(e):
                entry.configure(highlightbackground=self.colors['outline_focus'])

            def on_focus_out(e):
                entry.configure(highlightbackground=self.colors['outline'])

            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)

        entry.pack(fill=tk.X, pady=(0, self.spacing['sm']))
        container.entry = entry  # Store reference for easy access

        return container

    def create_enterprise_text_area(self, parent, label=None, height=6, **kwargs):
        """Create ENTERPRISE-GRADE text area - Premium multi-line input"""
        container = tk.Frame(parent, bg=self.colors['surface'])

        if label:
            label_widget = tk.Label(
                container,
                text=label,
                bg=self.colors['surface'],
                fg=self.colors['on_surface'],
                font=self.theme.get_font_config('label_medium')
            )
            label_widget.pack(anchor='w', pady=(0, self.spacing['xs']))

        # Create text widget with scrollbar
        text_frame = tk.Frame(container, bg=self.colors['surface'])
        text_frame.pack(fill=tk.BOTH, expand=True)

        text = tk.Text(text_frame, height=height, **kwargs)
        scrollbar = tk.Scrollbar(text_frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)

        # ENTERPRISE TEXT AREA STYLING
        text.configure(
            bg=self.colors['surface'],
            fg=self.colors['on_surface'],
            font=self.theme.get_font_config('body_medium'),
            relief='solid',
            borderwidth=2,
            highlightthickness=0,
            insertbackground=self.colors['on_surface'],
            selectbackground=self.colors['primary_container'],
            selectforeground=self.colors['on_primary_container'],
            wrap=tk.WORD,
            padx=self.spacing['input_padding_horizontal'],
            pady=self.spacing['input_padding_vertical']
        )

        # Set initial border color
        text.configure(highlightbackground=self.colors['outline'])

        # ENTERPRISE FOCUS EFFECTS
        def on_focus_in(e):
            text.configure(highlightbackground=self.colors['outline_focus'])

        def on_focus_out(e):
            text.configure(highlightbackground=self.colors['outline'])

        text.bind("<FocusIn>", on_focus_in)
        text.bind("<FocusOut>", on_focus_out)

        # Pack text and scrollbar
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        container.text = text  # Store reference for easy access

        return container

    def create_enterprise_status_badge(self, parent, text, status_type='info', **kwargs):
        """Create ENTERPRISE-GRADE status badge - Government security levels"""
        badge = tk.Label(parent, text=text, **kwargs)

        # ENTERPRISE STATUS CONFIGURATIONS
        status_configs = {
            'success': {
                'bg': self.colors['success_container'],
                'fg': self.colors['on_success_container']
            },
            'warning': {
                'bg': self.colors['warning_container'],
                'fg': self.colors['on_warning_container']
            },
            'error': {
                'bg': self.colors['error_container'],
                'fg': self.colors['on_error_container']
            },
            'info': {
                'bg': self.colors['info_container'],
                'fg': self.colors['on_info_container']
            },
            'top_secret': {
                'bg': self.colors['classified_top_secret'],
                'fg': '#ffffff'
            },
            'secret': {
                'bg': self.colors['classified_secret'],
                'fg': '#000000'
            },
            'confidential': {
                'bg': self.colors['classified_confidential'],
                'fg': '#ffffff'
            },
            'unclassified': {
                'bg': self.colors['classified_unclassified'],
                'fg': '#ffffff'
            }
        }

        config = status_configs.get(status_type, status_configs['info'])

        badge.configure(
            bg=config['bg'],
            fg=config['fg'],
            font=self.theme.get_font_config('label_small'),
            padx=self.spacing['component_padding_sm'],
            pady=self.spacing['component_padding_xs'],
            relief='flat'
        )

        return badge

    def create_enterprise_navigation_rail(self, parent, items, **kwargs):
        """Create ENTERPRISE-GRADE navigation rail - Microsoft-style sidebar"""
        rail = tk.Frame(parent, **kwargs)
        rail.configure(
            bg=self.colors['surface_variant'],
            width=280,
            relief='flat',
            borderwidth=0
        )

        # Navigation header
        header = tk.Frame(rail, bg=self.colors['surface_variant'])
        header.pack(fill=tk.X, padx=self.spacing['component_padding_lg'], pady=(self.spacing['component_padding_lg'], self.spacing['component_padding_md']))

        # Navigation items
        nav_container = tk.Frame(rail, bg=self.colors['surface_variant'])
        nav_container.pack(fill=tk.BOTH, expand=True, padx=self.spacing['component_padding_md'])

        for item in items:
            if isinstance(item, dict):
                text = item.get('text', '')
                command = item.get('command', None)
                style = item.get('style', 'secondary')

                nav_button = self.create_enterprise_button(
                    nav_container,
                    text,
                    command=command,
                    style=style,
                    size='medium'
                )
                nav_button.pack(fill=tk.X, pady=self.spacing['xs'])

        return rail

    def create_enterprise_stats_grid(self, parent, stats_data, **kwargs):
        """Create ENTERPRISE-GRADE statistics grid - Premium dashboard cards"""
        grid = tk.Frame(parent, **kwargs)
        grid.configure(bg=self.colors['bg'])

        for i, (icon, value, label, accent_color) in enumerate(stats_data):
            # ENTERPRISE STAT CARD
            stat_card = self.create_enterprise_card(grid)

            if i == 0:
                stat_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, self.spacing['md']))
            elif i == len(stats_data) - 1:
                stat_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(self.spacing['md'], 0))
            else:
                stat_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=self.spacing['md'])

            # Card content with ENTERPRISE spacing
            content = tk.Frame(stat_card, bg=self.colors['surface_elevated'])
            content.pack(fill=tk.BOTH, expand=True, padx=self.spacing['card_padding'], pady=self.spacing['card_padding'])

            # Icon with ENTERPRISE styling
            icon_label = tk.Label(
                content,
                text=icon,
                bg=self.colors['surface_elevated'],
                fg=accent_color,
                font=self.theme.get_font_config('headline_small')
            )
            icon_label.pack()

            # Value with ENTERPRISE typography
            value_label = tk.Label(
                content,
                text=value,
                bg=self.colors['surface_elevated'],
                fg=self.colors['primary'],
                font=self.theme.get_font_config('headline_medium')
            )
            value_label.pack(pady=(self.spacing['md'], self.spacing['sm']))

            # Label with ENTERPRISE styling
            desc_label = tk.Label(
                content,
                text=label,
                bg=self.colors['surface_elevated'],
                fg=self.colors['on_surface_variant'],
                font=self.theme.get_font_config('label_medium')
            )
            desc_label.pack()

        return grid

    # Legacy compatibility methods - redirect to new enterprise methods
    def create_styled_button(self, parent, text, command=None, style='primary', **kwargs):
        """Legacy compatibility - redirects to enterprise button"""
        return self.create_enterprise_button(parent, text, command, style, **kwargs)

    def create_styled_frame(self, parent, style='card', **kwargs):
        """Legacy compatibility - redirects to enterprise card"""
        if style == 'card':
            return self.create_enterprise_card(parent, **kwargs)
        else:
            frame = tk.Frame(parent, **kwargs)
            if style == 'sidebar':
                frame.configure(bg=self.colors['surface_variant'])
            elif style == 'section':
                frame.configure(bg=self.colors['bg'])
            else:
                frame.configure(bg=self.colors['surface'])
            return frame

    def create_styled_label(self, parent, text, style='body_medium', **kwargs):
        """Legacy compatibility - redirects to enterprise label"""
        label = tk.Label(parent, text=text, **kwargs)
        label.configure(
            bg=self.colors['surface'],
            fg=self.colors['on_surface'],
            font=self.theme.get_font_config(style)
        )
        return label

    def create_styled_checkbox(self, parent, text, variable=None, command=None, **kwargs):
        """Create ENTERPRISE-GRADE styled checkbox"""
        if variable is None:
            variable = tk.BooleanVar()

        checkbox = tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            command=command,
            bg=self.colors['surface'],
            fg=self.colors['on_surface'],
            selectcolor=self.colors['surface'],
            activebackground=self.colors['surface'],
            activeforeground=self.colors['primary'],
            font=self.get_font_config('body_small'),
            cursor='hand2',
            **kwargs
        )
        return checkbox

    def create_styled_entry(self, parent, placeholder="", **kwargs):
        """Legacy compatibility - redirects to enterprise input"""
        container = self.create_enterprise_input(parent, placeholder=placeholder, **kwargs)
        return container.entry  # Return just the entry widget for compatibility

    def create_styled_text(self, parent, **kwargs):
        """Legacy compatibility - redirects to enterprise text area"""
        container = self.create_enterprise_text_area(parent, **kwargs)
        return container.text  # Return just the text widget for compatibility

    def create_status_label(self, parent, text, status_type='info', **kwargs):
        """Legacy compatibility - redirects to enterprise status badge"""
        # Map legacy status types to enterprise types
        status_mapping = {
            'success': 'success',
            'warning': 'warning',
            'danger': 'error',  # Map danger to error for enterprise system
            'info': 'info',
            'classified': 'top_secret'
        }

        enterprise_type = status_mapping.get(status_type, 'info')
        return self.create_enterprise_status_badge(parent, text, enterprise_type, **kwargs)

    def create_success_feedback(self, parent, message="Success!", **kwargs):
        """Create ENTERPRISE success feedback with animation"""
        frame = tk.Frame(parent, **kwargs)
        frame.configure(bg=self.colors['success_container'])

        # Success icon
        icon_label = tk.Label(
            frame,
            text="âœ“",
            bg=self.colors['success_container'],
            fg=self.colors['success'],
            font=self.theme.get_font_config('headline_small')
        )
        icon_label.pack(side='left', padx=self.spacing['sm'])

        # Success message
        message_label = tk.Label(
            frame,
            text=message,
            bg=self.colors['success_container'],
            fg=self.colors['on_success_container'],
            font=self.theme.get_font_config('body_medium')
        )
        message_label.pack(side='left', padx=self.spacing['sm'])

        # Add fade-in animation effect
        def fade_in():
            try:
                frame.configure(relief='solid', borderwidth=1)
                frame.after(100, lambda: frame.configure(relief='flat', borderwidth=0))
            except:
                pass  # Widget destroyed

        frame.after(50, fade_in)

        return frame

    def create_error_feedback(self, parent, message="Error occurred", **kwargs):
        """Create ENTERPRISE error feedback with animation"""
        frame = tk.Frame(parent, **kwargs)
        frame.configure(bg=self.colors['error_container'])

        # Error icon
        icon_label = tk.Label(
            frame,
            text="âœ—",
            bg=self.colors['error_container'],
            fg=self.colors['error'],
            font=self.theme.get_font_config('headline_small')
        )
        icon_label.pack(side='left', padx=self.spacing['sm'])

        # Error message
        message_label = tk.Label(
            frame,
            text=message,
            bg=self.colors['error_container'],
            fg=self.colors['on_error_container'],
            font=self.theme.get_font_config('body_medium')
        )
        message_label.pack(side='left', padx=self.spacing['sm'])

        return frame

    def create_form_validation_label(self, parent, validation_type='error', message="", **kwargs):
        """Create ENTERPRISE form validation styling"""
        label = tk.Label(parent, text=message, **kwargs)

        if validation_type == 'error':
            label.configure(
                bg=self.colors['surface'],
                fg=self.colors['error'],
                font=self.theme.get_font_config('body_small')
            )
        elif validation_type == 'success':
            label.configure(
                bg=self.colors['surface'],
                fg=self.colors['success'],
                font=self.theme.get_font_config('body_small')
            )
        elif validation_type == 'warning':
            label.configure(
                bg=self.colors['surface'],
                fg=self.colors['warning'],
                font=self.theme.get_font_config('body_small')
            )
        else:  # info
            label.configure(
                bg=self.colors['surface'],
                fg=self.colors['info'],
                font=self.theme.get_font_config('body_small')
            )

        return label

    def create_scrollable_container(self, parent, height=None, **kwargs):
        """Create ENTERPRISE scrollable container"""
        scrollable = ProfessionalScrollableFrame(parent, theme_colors=self.colors, **kwargs)
        if height:
            scrollable.configure(height=height)
        return scrollable

    def apply_window_theme(self, window):
        """Apply ENTERPRISE theme to window"""
        self.theme.apply_theme(window)
        window.configure(bg=self.colors['bg'])

        # Configure window properties for professional appearance
        if hasattr(window, 'configure'):
            try:
                window.configure(highlightcolor=self.colors['primary'])
            except:
                pass

    def create_loading_indicator(self, parent, size='medium', **kwargs):
        """Create ENTERPRISE loading indicator with animation"""
        frame = tk.Frame(parent, **kwargs)
        frame.configure(bg=self.colors['surface'])

        # Create loading text with animation effect
        loading_label = tk.Label(
            frame,
            text="Loading...",
            bg=self.colors['surface'],
            fg=self.colors['on_surface_variant'],
            font=self.theme.get_font_config('body_medium')
        )
        loading_label.pack(pady=self.spacing['md'])

        # Add animated dots effect
        def animate_loading():
            try:
                current_text = loading_label.cget('text')
                if current_text.endswith('...'):
                    loading_label.configure(text='Loading')
                elif current_text.endswith('..'):
                    loading_label.configure(text='Loading...')
                elif current_text.endswith('.'):
                    loading_label.configure(text='Loading..')
                else:
                    loading_label.configure(text='Loading.')

                # Schedule next animation frame
                frame.after(500, animate_loading)
            except:
                pass  # Widget destroyed

        # Start animation
        animate_loading()

        return frame

    def create_progress_bar(self, parent, width=200, height=8, **kwargs):
        """Create ENTERPRISE progress bar"""
        frame = tk.Frame(parent, **kwargs)
        frame.configure(bg=self.colors['surface'])

        # Create progress bar background
        bg_frame = tk.Frame(
            frame,
            width=width,
            height=height,
            bg=self.colors['outline_variant'],
            relief='flat'
        )
        bg_frame.pack(pady=self.spacing['sm'])
        bg_frame.pack_propagate(False)

        # Create progress bar fill
        progress_frame = tk.Frame(
            bg_frame,
            width=0,
            height=height,
            bg=self.colors['primary'],
            relief='flat'
        )
        progress_frame.place(x=0, y=0)

        def update_progress(percentage):
            """Update progress bar to show percentage (0-100)"""
            fill_width = int((percentage / 100) * width)
            progress_frame.configure(width=fill_width)

        # Add update method to frame
        frame.update_progress = update_progress

        return frame

    def create_enterprise_dialog(self, parent, title, content_callback, width=500, height=400, **kwargs):
        """Create ENTERPRISE-GRADE unified dialog system - Single consistent UI"""
        dialog = tk.Toplevel(parent)
        dialog.title(title)
        dialog.geometry(f"{width}x{height}")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(parent)
        dialog.grab_set()

        # Center dialog on parent window
        dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (width // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (height // 2)
        dialog.geometry(f"+{x}+{y}")

        # ENTERPRISE MAIN CONTAINER - Consistent layout
        main_container = tk.Frame(dialog, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=24, pady=24)

        # ENTERPRISE HEADER - Professional title section
        header_frame = tk.Frame(main_container, bg=self.colors['bg'])
        header_frame.pack(fill=tk.X, pady=(0, 20))

        title_label = self.create_styled_label(
            header_frame, title, style='headline_medium'
        )
        title_label.pack()

        # ENTERPRISE CONTENT AREA - Scrollable content
        content_frame = self.create_scrollable_container(main_container)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

        # Call the content callback to populate the dialog
        content_callback(content_frame.get_frame(), dialog)

        return dialog

    def create_enterprise_confirmation_dialog(self, parent, title, message, callback=None, **kwargs):
        """Create ENTERPRISE-GRADE confirmation dialog - Consistent confirmation UI"""
        def create_content(content_frame, dialog):
            # Message
            self.create_styled_label(
                content_frame, message, style='body_medium'
            ).pack(pady=(20, 30))

            # Button frame
            button_frame = tk.Frame(content_frame, bg=self.colors['surface'])
            button_frame.pack(fill=tk.X, pady=(20, 0))

            # Cancel button
            self.create_enterprise_button(
                button_frame, "CANCEL",
                command=lambda: dialog.destroy(),
                style='secondary', size='medium'
            ).pack(side=tk.LEFT, padx=(0, 10))

            # Confirm button
            def confirm_action():
                if callback:
                    callback()
                dialog.destroy()

            self.create_enterprise_button(
                button_frame, "CONFIRM",
                command=confirm_action,
                style='primary', size='medium'
            ).pack(side=tk.RIGHT)

        return self.create_enterprise_dialog(parent, title, create_content, 400, 250, **kwargs)

    def create_enterprise_input_dialog(self, parent, title, fields, callback=None, **kwargs):
        """Create ENTERPRISE-GRADE input dialog - Consistent input UI"""
        entries = {}

        def create_content(content_frame, dialog):
            # Create input fields
            for field_name, field_config in fields.items():
                field_container = self.create_enterprise_input(
                    content_frame,
                    label=field_config.get('label', field_name.title()),
                    placeholder=field_config.get('placeholder', ''),
                    input_type=field_config.get('type', 'text')
                )
                field_container.pack(fill=tk.X, pady=(0, 16))
                entries[field_name] = field_container.entry

            # Button frame
            button_frame = tk.Frame(content_frame, bg=self.colors['surface'])
            button_frame.pack(fill=tk.X, pady=(20, 0))

            # Cancel button
            self.create_enterprise_button(
                button_frame, "CANCEL",
                command=lambda: dialog.destroy(),
                style='secondary', size='medium'
            ).pack(side=tk.LEFT, padx=(0, 10))

            # Submit button
            def submit_action():
                if callback:
                    values = {name: entry.get() for name, entry in entries.items()}
                    callback(values)
                dialog.destroy()

            self.create_enterprise_button(
                button_frame, "SUBMIT",
                command=submit_action,
                style='primary', size='medium'
            ).pack(side=tk.RIGHT)

        return self.create_enterprise_dialog(parent, title, create_content, 500, 400, **kwargs)

    def add_micro_interaction(self, widget, interaction_type='hover_lift'):
        """Add ENTERPRISE micro-interactions for better UX"""
        if interaction_type == 'hover_lift':
            def on_enter(e):
                try:
                    widget.configure(relief='raised', borderwidth=1)
                except:
                    pass

            def on_leave(e):
                try:
                    widget.configure(relief='flat', borderwidth=0)
                except:
                    pass

            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)

        elif interaction_type == 'click_feedback':
            def on_press(e):
                try:
                    widget.configure(relief='sunken')
                except:
                    pass

            def on_release(e):
                try:
                    widget.configure(relief='raised')
                    widget.after(100, lambda: widget.configure(relief='flat'))
                except:
                    pass

            widget.bind("<Button-1>", on_press)
            widget.bind("<ButtonRelease-1>", on_release)

        return widget


class ProfessionalScrollableFrame(tk.Frame):
    """Professional scrollable frame with modern themed scrollbar"""

    def __init__(self, parent, theme_colors=None, **kwargs):
        super().__init__(parent, **kwargs)

        # Store theme colors
        self.theme_colors = theme_colors or {}
        self._destroyed = False

        # Create canvas and scrollbar with professional styling
        self.canvas = tk.Canvas(
            self,
            bg=self.theme_colors.get('bg', '#ffffff'),
            highlightthickness=0,
            borderwidth=0,
            relief='flat'
        )

        self.scrollbar = tk.Scrollbar(
            self,
            orient="vertical",
            command=self.canvas.yview,
            width=12  # Thinner, more modern scrollbar
        )

        self.scrollable_frame = tk.Frame(
            self.canvas,
            bg=self.theme_colors.get('bg', '#ffffff')
        )

        # Configure professional scrollbar appearance
        if self.theme_colors:
            self.scrollbar.configure(
                bg=self.theme_colors.get('gray_100', '#f3f4f6'),
                troughcolor=self.theme_colors.get('gray_50', '#f9fafb'),
                activebackground=self.theme_colors.get('gray_300', '#d1d5db'),
                relief='flat',
                borderwidth=0,
                highlightthickness=0
            )

        # Create window in canvas
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self._on_frame_configure(e)
        )

        self.canvas_frame = self.canvas.create_window(
            (0, 0),
            window=self.scrollable_frame,
            anchor="nw"
        )

        # Configure canvas scrolling
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Pack canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Bind smooth mouse wheel scrolling
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Button-4>", self._on_mousewheel)  # Linux scroll up
        self.canvas.bind("<Button-5>", self._on_mousewheel)  # Linux scroll down

        # Bind canvas resize to update scrollable frame width
        self.canvas.bind('<Configure>', self._on_canvas_configure)

        # Bind destroy event to cleanup
        self.bind("<Destroy>", self._on_destroy)

    def _on_frame_configure(self, event):
        """Update scroll region when frame is configured"""
        if not self._destroyed:
            try:
                self.canvas.configure(scrollregion=self.canvas.bbox("all"))
            except:
                pass

    def _on_canvas_configure(self, event):
        """Update the scrollable frame width when canvas is resized"""
        if not self._destroyed:
            try:
                self.canvas.itemconfig(self.canvas_frame, width=event.width)
            except:
                pass

    def _on_mousewheel(self, event):
        """Handle smooth mouse wheel scrolling"""
        if not self._destroyed:
            try:
                # Smooth scrolling with smaller increments
                if event.num == 5 or event.delta < 0:
                    # Scroll down
                    self.canvas.yview_scroll(3, "units")
                elif event.num == 4 or event.delta > 0:
                    # Scroll up
                    self.canvas.yview_scroll(-3, "units")
            except:
                pass

    def _on_destroy(self, event):
        """Cleanup when widget is destroyed"""
        if event.widget == self:
            self._destroyed = True

    def get_frame(self):
        """Get the scrollable frame to add widgets to"""
        return self.scrollable_frame
