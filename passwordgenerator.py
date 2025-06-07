import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import hashlib
import random
from PIL import Image, ImageTk, ImageDraw


class LFSR:
    """Linear Feedback Shift Register pentru generarea secvențelor pseudo-aleatoare"""

    def __init__(self, seed=None, taps=None):
        if seed is None:
            seed = random.randint(1, 0xFFFF)
        if taps is None:
            # Taps pentru LFSR de 16 biți (polinomial primitiv)
            taps = [16, 14, 13, 11]

        self.seed = seed
        self.taps = taps
        self.register = seed

    def next_bit(self):
        """Generează următorul bit din secvența LFSR"""
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.register >> (tap - 1)) & 1

        self.register = ((self.register << 1) | feedback) & 0xFFFF
        return feedback

    def next_int(self, max_val):
        """Generează un număr întreg în intervalul [0, max_val)"""
        if max_val <= 0:
            return 0

        bits_needed = max_val.bit_length()
        while True:
            value = 0
            for _ in range(bits_needed):
                value = (value << 1) | self.next_bit()
            if value < max_val:
                return value


class SplashScreen:
    """Ecran de încărcare cu logo și progress bar"""

    def __init__(self):
        self.splash = tk.Toplevel()
        self.splash.title("Secure Password Generator")
        self.splash.geometry("400x300")
        self.splash.configure(bg='#1e1e2e')
        self.splash.resizable(False, False)

        # Centrează fereastra
        self.splash.transient()
        self.splash.grab_set()

        # Ascunde decorațiunile ferestrei
        self.splash.overrideredirect(True)

        # Centrează pe ecran
        self.center_window()

        self.create_logo()
        self.create_elements()
        self.animate_progress()

    def center_window(self):
        """Centrează fereastra pe ecran"""
        self.splash.update_idletasks()
        x = (self.splash.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.splash.winfo_screenheight() // 2) - (300 // 2)
        self.splash.geometry(f"400x300+{x}+{y}")

    def create_logo(self):
        """Creează logo-ul aplicației"""
        try:
            # Încearcă să creeze un logo cu PIL
            logo_size = 80
            img = Image.new('RGBA', (logo_size, logo_size), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)

            # Desenează un scut (logo pentru securitate)
            shield_color = '#00d4aa'
            lock_color = '#ffffff'

            # Scut
            points = [
                (logo_size // 2, 10),
                (logo_size - 15, 25),
                (logo_size - 15, logo_size - 25),
                (logo_size // 2, logo_size - 5),
                (15, logo_size - 25),
                (15, 25)
            ]
            draw.polygon(points, fill=shield_color)

            # Lacăt în mijloc
            lock_x, lock_y = logo_size // 2, logo_size // 2
            lock_size = 15

            # Corp lacăt
            draw.rectangle([
                lock_x - lock_size // 2, lock_y - 5,
                lock_x + lock_size // 2, lock_y + lock_size // 2
            ], fill=lock_color)

            # Arc lacăt
            draw.arc([
                lock_x - lock_size // 3, lock_y - lock_size,
                lock_x + lock_size // 3, lock_y
            ], 0, 180, fill=lock_color, width=3)

            self.logo_image = ImageTk.PhotoImage(img)

            # Afișează logo-ul
            logo_label = tk.Label(self.splash, image=self.logo_image, bg='#1e1e2e')
            logo_label.pack(pady=(40, 20))

        except Exception:
            # Fallback - folosește text dacă PIL nu funcționează
            logo_label = tk.Label(
                self.splash,
                text="🔐",
                font=("Arial", 48),
                fg='#00d4aa',
                bg='#1e1e2e'
            )
            logo_label.pack(pady=(40, 20))

    def create_elements(self):
        """Creează elementele UI ale splash screen-ului"""
        # Titlu
        title_label = tk.Label(
            self.splash,
            text="Secure Password Generator",
            font=("Arial", 18, "bold"),
            fg='#00d4aa',
            bg='#1e1e2e'
        )
        title_label.pack(pady=10)

        # Subtitlu
        subtitle_label = tk.Label(
            self.splash,
            text="LFSR Algorithm • AES Encryption",
            font=("Arial", 10),
            fg='#a6adc8',
            bg='#1e1e2e'
        )
        subtitle_label.pack(pady=5)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.splash,
            variable=self.progress_var,
            maximum=100,
            length=300,
            style="Custom.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(pady=(30, 10))

        # Status text
        self.status_label = tk.Label(
            self.splash,
            text="Inițializare...",
            font=("Arial", 9),
            fg='#a6adc8',
            bg='#1e1e2e'
        )
        self.status_label.pack()

        # Configurează stilul progress bar-ului
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(
            "Custom.Horizontal.TProgressbar",
            background='#00d4aa',
            troughcolor='#313244',
            borderwidth=0,
            lightcolor='#00d4aa',
            darkcolor='#00d4aa'
        )

    def animate_progress(self):
        """Animează progress bar-ul"""
        self.steps = [
            (20, "Încărcare LFSR..."),
            (40, "Inițializare criptare..."),
            (60, "Configurare interfață..."),
            (80, "Finalizare..."),
            (100, "Gata!")
        ]
        self.current_step = 0
        self.update_progress_step()

    def update_progress_step(self):
        """Actualizează un pas din progress bar"""
        if self.current_step < len(self.steps):
            progress, status = self.steps[self.current_step]
            self.progress_var.set(progress)
            self.status_label.config(text=status)
            self.current_step += 1

            # Programează următorul update după 300ms
            self.splash.after(300, self.update_progress_step)
        else:
            # Finalizează și închide splash screen-ul
            self.splash.after(500, self.splash.destroy)


class PasswordGenerator:
    def __init__(self):
        # Creează fereastra root mai întâi
        self.root = tk.Tk()
        self.root.withdraw()  # Ascunde fereastra principală temporar

        # Afișează splash screen
        splash = SplashScreen()
        self.root.wait_window(splash.splash)  # Așteaptă să se închidă splash-ul

        # Configurează fereastra principală
        self.root.deiconify()  # Afișează fereastra principală
        self.root.title("Secure Password Generator - LFSR Algorithm")
        self.root.geometry("800x700")
        self.root.configure(bg='#1e1e2e')

        # Inițializează LFSR
        self.lfsr = LFSR()

        # Setări pentru salvarea fișierelor
        self.save_directory = "generated_passwords"
        if not os.path.exists(self.save_directory):
            os.makedirs(self.save_directory)

        self.setup_ui()
        self.center_window()

    def center_window(self):
        """Centrează fereastra principală"""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (800 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"800x700+{x}+{y}")

    def setup_ui(self):
        """Configurează interfața utilizator"""
        # Stilizare
        style = ttk.Style()
        style.theme_use('clam')

        # Configurează culorile pentru tema dark
        style.configure('TNotebook', background='#1e1e2e', borderwidth=0)
        style.configure('TNotebook.Tab', background='#313244', foreground='#cdd6f4', padding=[20, 10])
        style.map('TNotebook.Tab', background=[('selected', '#00d4aa')], foreground=[('selected', '#1e1e2e')])

        # Header
        header_frame = tk.Frame(self.root, bg='#1e1e2e', height=80)
        header_frame.pack(fill='x', padx=20, pady=(20, 10))
        header_frame.pack_propagate(False)

        title = tk.Label(
            header_frame,
            text="🔐 Secure Password Generator",
            font=("Arial", 20, "bold"),
            fg='#00d4aa',
            bg='#1e1e2e'
        )
        title.pack(side='left', pady=20)

        subtitle = tk.Label(
            header_frame,
            text="LFSR Algorithm • AES-256 Encryption",
            font=("Arial", 10),
            fg='#a6adc8',
            bg='#1e1e2e'
        )
        subtitle.pack(side='right', pady=25)

        # Notebook pentru tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=10)

        # Tab Generator
        self.generator_frame = tk.Frame(self.notebook, bg='#1e1e2e')
        self.notebook.add(self.generator_frame, text="🔧 Generator Parole")

        # Tab Istoric
        self.history_frame = tk.Frame(self.notebook, bg='#1e1e2e')
        self.notebook.add(self.history_frame, text="📋 Istoric Parole")

        self.setup_generator_tab()
        self.setup_history_tab()

    def setup_generator_tab(self):
        """Configurează tab-ul generator"""
        # Frame principal cu scroll
        canvas = tk.Canvas(self.generator_frame, bg='#1e1e2e', highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.generator_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#1e1e2e')

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Setări caractere alfabetice
        alpha_frame = self.create_setting_frame(scrollable_frame, "🔤 Caractere Alfabetice")
        self.alpha_min_var = tk.StringVar(value="2")
        self.alpha_max_var = tk.StringVar(value="8")
        self.create_min_max_inputs(alpha_frame, "Minim:", "Maxim:", self.alpha_min_var, self.alpha_max_var)

        # Setări caractere numerice
        numeric_frame = self.create_setting_frame(scrollable_frame, "🔢 Caractere Numerice")
        self.numeric_min_var = tk.StringVar(value="1")
        self.numeric_max_var = tk.StringVar(value="4")
        self.create_min_max_inputs(numeric_frame, "Minim:", "Maxim:", self.numeric_min_var, self.numeric_max_var)

        # Setări caractere speciale
        special_frame = self.create_setting_frame(scrollable_frame, "⚡ Caractere Speciale")
        self.special_min_var = tk.StringVar(value="1")
        self.special_max_var = tk.StringVar(value="3")
        self.create_min_max_inputs(special_frame, "Minim:", "Maxim:", self.special_min_var, self.special_max_var)

        # Lungime totală
        length_frame = self.create_setting_frame(scrollable_frame, "📏 Lungime Totală")
        self.total_length_var = tk.StringVar(value="12")
        tk.Label(length_frame, text="Caractere totale:", bg='#1e1e2e', fg='#cdd6f4', font=("Arial", 10)).grid(row=0,
                                                                                                              column=0,
                                                                                                              sticky='w',
                                                                                                              padx=5,
                                                                                                              pady=5)
        tk.Entry(length_frame, textvariable=self.total_length_var, bg='#313244', fg='#cdd6f4',
                 insertbackground='#cdd6f4', width=10).grid(row=0, column=1, padx=5, pady=5)

        # Separatori
        separator_frame = self.create_setting_frame(scrollable_frame, "➖ Separatori")
        self.separator_enabled_var = tk.BooleanVar(value=False)
        self.separator_interval_var = tk.StringVar(value="4")

        tk.Checkbutton(
            separator_frame,
            text="Activează separatori",
            variable=self.separator_enabled_var,
            bg='#1e1e2e',
            fg='#cdd6f4',
            selectcolor='#313244',
            activebackground='#1e1e2e',
            activeforeground='#00d4aa'
        ).grid(row=0, column=0, columnspan=2, sticky='w', padx=5, pady=5)

        tk.Label(separator_frame, text="Interval (caractere):", bg='#1e1e2e', fg='#cdd6f4', font=("Arial", 10)).grid(
            row=1, column=0, sticky='w', padx=5, pady=5)
        tk.Entry(separator_frame, textvariable=self.separator_interval_var, bg='#313244', fg='#cdd6f4',
                 insertbackground='#cdd6f4', width=10).grid(row=1, column=1, padx=5, pady=5)

        # Numărul de parole
        count_frame = self.create_setting_frame(scrollable_frame, "🔢 Număr Parole")
        self.password_count_var = tk.StringVar(value="5")
        tk.Label(count_frame, text="Parole per sesiune:", bg='#1e1e2e', fg='#cdd6f4', font=("Arial", 10)).grid(row=0,
                                                                                                               column=0,
                                                                                                               sticky='w',
                                                                                                               padx=5,
                                                                                                               pady=5)
        tk.Entry(count_frame, textvariable=self.password_count_var, bg='#313244', fg='#cdd6f4',
                 insertbackground='#cdd6f4', width=10).grid(row=0, column=1, padx=5, pady=5)

        # Buton generare
        generate_btn = tk.Button(
            scrollable_frame,
            text="🎲 Generează Parole",
            command=self.generate_passwords,
            bg='#00d4aa',
            fg='#1e1e2e',
            font=("Arial", 12, "bold"),
            relief='flat',
            pady=10,
            cursor='hand2'
        )
        generate_btn.pack(pady=20, padx=20, fill='x')

        # Zona de afișare rezultate
        results_frame = tk.LabelFrame(
            scrollable_frame,
            text="🔑 Parole Generate",
            bg='#1e1e2e',
            fg='#00d4aa',
            font=("Arial", 12, "bold")
        )
        results_frame.pack(fill='both', expand=True, padx=20, pady=10)

        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            height=8,
            bg='#313244',
            fg='#cdd6f4',
            insertbackground='#cdd6f4',
            font=("Consolas", 11),
            wrap=tk.WORD
        )
        self.results_text.pack(fill='both', expand=True, padx=10, pady=10)

    def setup_history_tab(self):
        """Configurează tab-ul istoric"""
        # Header pentru istoric
        header_frame = tk.Frame(self.history_frame, bg='#1e1e2e')
        header_frame.pack(fill='x', padx=20, pady=10)

        tk.Label(
            header_frame,
            text="📋 Istoric Parole Generate",
            font=("Arial", 16, "bold"),
            fg='#00d4aa',
            bg='#1e1e2e'
        ).pack(side='left')

        refresh_btn = tk.Button(
            header_frame,
            text="🔄 Actualizează",
            command=self.load_history,
            bg='#313244',
            fg='#cdd6f4',
            font=("Arial", 10),
            relief='flat',
            cursor='hand2'
        )
        refresh_btn.pack(side='right')

        # Lista pentru istoric
        self.history_text = scrolledtext.ScrolledText(
            self.history_frame,
            bg='#313244',
            fg='#cdd6f4',
            insertbackground='#cdd6f4',
            font=("Consolas", 10),
            wrap=tk.WORD
        )
        self.history_text.pack(fill='both', expand=True, padx=20, pady=10)

        # Încarcă istoricul la pornire
        self.load_history()

    def create_setting_frame(self, parent, title):
        """Creează un frame pentru setări cu titlu"""
        frame = tk.LabelFrame(
            parent,
            text=title,
            bg='#1e1e2e',
            fg='#00d4aa',
            font=("Arial", 11, "bold"),
            pady=10
        )
        frame.pack(fill='x', padx=20, pady=10)
        return frame

    def create_min_max_inputs(self, parent, min_label, max_label, min_var, max_var):
        """Creează input-uri pentru minim și maxim"""
        tk.Label(parent, text=min_label, bg='#1e1e2e', fg='#cdd6f4', font=("Arial", 10)).grid(row=0, column=0,
                                                                                              sticky='w', padx=5,
                                                                                              pady=5)
        tk.Entry(parent, textvariable=min_var, bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4', width=10).grid(
            row=0, column=1, padx=5, pady=5)

        tk.Label(parent, text=max_label, bg='#1e1e2e', fg='#cdd6f4', font=("Arial", 10)).grid(row=0, column=2,
                                                                                              sticky='w', padx=5,
                                                                                              pady=5)
        tk.Entry(parent, textvariable=max_var, bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4', width=10).grid(
            row=0, column=3, padx=5, pady=5)

    def validate_inputs(self):
        """Validează input-urile utilizatorului"""
        try:
            alpha_min = int(self.alpha_min_var.get())
            alpha_max = int(self.alpha_max_var.get())
            numeric_min = int(self.numeric_min_var.get())
            numeric_max = int(self.numeric_max_var.get())
            special_min = int(self.special_min_var.get())
            special_max = int(self.special_max_var.get())
            total_length = int(self.total_length_var.get())
            password_count = int(self.password_count_var.get())

            # Validări
            if any(val < 0 for val in [alpha_min, alpha_max, numeric_min, numeric_max, special_min, special_max]):
                raise ValueError("Valorile nu pot fi negative")

            if alpha_min > alpha_max or numeric_min > numeric_max or special_min > special_max:
                raise ValueError("Valorile minime nu pot fi mai mari decât maximele")

            if total_length < (alpha_min + numeric_min + special_min):
                raise ValueError("Lungimea totală este prea mică pentru cerințele minime")

            if password_count <= 0 or password_count > 100:
                raise ValueError("Numărul de parole trebuie să fie între 1 și 100")

            return {
                'alpha_min': alpha_min, 'alpha_max': alpha_max,
                'numeric_min': numeric_min, 'numeric_max': numeric_max,
                'special_min': special_min, 'special_max': special_max,
                'total_length': total_length, 'password_count': password_count,
                'separator_enabled': self.separator_enabled_var.get(),
                'separator_interval': int(self.separator_interval_var.get()) if self.separator_enabled_var.get() else 0
            }

        except ValueError as e:
            messagebox.showerror("Eroare Validare", f"Date de intrare invalide: {str(e)}")
            return None

    def generate_password(self, config):
        """Generează o singură parolă folosind LFSR"""
        # Seturile de caractere
        alpha_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        numeric_chars = "0123456789"
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        # Calculează numărul de caractere pentru fiecare tip
        alpha_count = self.lfsr.next_int(config['alpha_max'] - config['alpha_min'] + 1) + config['alpha_min']
        numeric_count = self.lfsr.next_int(config['numeric_max'] - config['numeric_min'] + 1) + config['numeric_min']
        special_count = self.lfsr.next_int(config['special_max'] - config['special_min'] + 1) + config['special_min']

        # Ajustează pentru lungimea totală
        current_length = alpha_count + numeric_count + special_count
        if current_length < config['total_length']:
            # Adaugă caractere aleatoriu pentru a ajunge la lungimea dorită
            remaining = config['total_length'] - current_length
            while remaining > 0:
                char_type = self.lfsr.next_int(3)
                if char_type == 0:
                    alpha_count += 1
                elif char_type == 1:
                    numeric_count += 1
                else:
                    special_count += 1
                remaining -= 1

        # Generează caracterele
        password_chars = []

        # Adaugă caractere alfabetice
        for _ in range(alpha_count):
            char_idx = self.lfsr.next_int(len(alpha_chars))
            password_chars.append(alpha_chars[char_idx])

        # Adaugă caractere numerice
        for _ in range(numeric_count):
            char_idx = self.lfsr.next_int(len(numeric_chars))
            password_chars.append(numeric_chars[char_idx])

        # Adaugă caractere speciale
        for _ in range(special_count):
            char_idx = self.lfsr.next_int(len(special_chars))
            password_chars.append(special_chars[char_idx])

        # Amestecă caracterele folosind LFSR
        for i in range(len(password_chars) - 1, 0, -1):
            j = self.lfsr.next_int(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

        password = ''.join(password_chars)

        # Adaugă separatori dacă sunt activați
        if config['separator_enabled'] and config['separator_interval'] > 0:
            separated_password = ""
            for i, char in enumerate(password):
                if i > 0 and i % config['separator_interval'] == 0:
                    separated_password += "-"
                separated_password += char
            password = separated_password

        return password

    def generate_passwords(self):
        """Generează parolele și le afișează"""
        config = self.validate_inputs()
        if not config:
            return

        try:
            # Generează parolele
            passwords = []
            for _ in range(config['password_count']):
                password = self.generate_password(config)
                passwords.append(password)

            # Afișează rezultatele
            self.results_text.delete(1.0, tk.END)
            result_text = f"🎲 Generate {len(passwords)} parole cu LFSR:\n"
            result_text += "=" * 50 + "\n\n"

            for i, password in enumerate(passwords, 1):
                result_text += f"{i:2d}. {password}\n"

            result_text += "\n" + "=" * 50 + "\n"
            result_text += f"📊 Statistici:\n"
            result_text += f"   • Lungime medie: {sum(len(p.replace('-', '')) for p in passwords) / len(passwords):.1f} caractere\n"
            result_text += f"   • Algoritm: LFSR (seed: {self.lfsr.seed})\n"
            result_text += f"   • Timestamp: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"

            self.results_text.insert(tk.END, result_text)

            # Salvează parolele criptat
            self.save_passwords_encrypted(passwords, config)

            # Reinițializează LFSR cu un seed nou pentru următoarea generare
            self.lfsr = LFSR()

            messagebox.showinfo("Succes", f"Au fost generate {len(passwords)} parole și salvate criptat!")

        except Exception as e:
            messagebox.showerror("Eroare", f"Eroare la generarea parolilor: {str(e)}")

    def save_passwords_encrypted(self, passwords, config):
        """Salvează parolele criptat în fișier"""
        try:
            # Creează timestamp pentru nume fișier
            timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
            filename = f"passwords_{timestamp}.enc"
            filepath = os.path.join(self.save_directory, filename)

            # Creează cheia de criptare din numele fișierului
            key_material = filename.encode('utf-8')
            key = base64.urlsafe_b64encode(hashlib.sha256(key_material).digest())
            cipher = Fernet(key)

            # Pregătește datele pentru salvare
            data = {
                'timestamp': datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                'passwords': passwords,
                'config': config,
                'lfsr_seed': self.lfsr.seed,
                'count': len(passwords)
            }

            # Criptează și salvează
            json_data = json.dumps(data, indent=2)
            encrypted_data = cipher.encrypt(json_data.encode('utf-8'))

            with open(filepath, 'wb') as f:
                f.write(encrypted_data)

            print(f"Parole salvate criptat în: {filepath}")

        except Exception as e:
            messagebox.showerror("Eroare Salvare", f"Nu s-au putut salva parolele: {str(e)}")

    def load_history(self):
        """Încarcă și afișează istoricul parolelor"""
        try:
            self.history_text.delete(1.0, tk.END)

            if not os.path.exists(self.save_directory):
                self.history_text.insert(tk.END, "📭 Nu există istoric de parole generate.\n")
                return

            files = [f for f in os.listdir(self.save_directory) if f.endswith('.enc')]
            if not files:
                self.history_text.insert(tk.END, "📭 Nu există fișiere de istoric.\n")
                return

            # Sortează fișierele după dată
            files.sort(reverse=True)

            history_text = "📋 ISTORIC PAROLE GENERATE\n"
            history_text += "=" * 60 + "\n\n"

            for filename in files[:10]:  # Afișează ultimele 10 sesiuni
                try:
                    filepath = os.path.join(self.save_directory, filename)

                    # Decriptează fișierul
                    key_material = filename.encode('utf-8')
                    key = base64.urlsafe_b64encode(hashlib.sha256(key_material).digest())
                    cipher = Fernet(key)

                    with open(filepath, 'rb') as f:
                        encrypted_data = f.read()

                    decrypted_data = cipher.decrypt(encrypted_data)
                    data = json.loads(decrypted_data.decode('utf-8'))

                    # Afișează informațiile sesiunii
                    history_text += f"🕒 {data['timestamp']}\n"
                    history_text += f"📊 {data['count']} parole generate (seed LFSR: {data['lfsr_seed']})\n"
                    history_text += f"⚙️  Configurație: "
                    history_text += f"Alfabet({data['config']['alpha_min']}-{data['config']['alpha_max']}), "
                    history_text += f"Numeric({data['config']['numeric_min']}-{data['config']['numeric_max']}), "
                    history_text += f"Special({data['config']['special_min']}-{data['config']['special_max']}), "
                    history_text += f"Lungime({data['config']['total_length']})\n"

                    # Afișează primele 3 parole ca exemplu
                    history_text += "🔑 Exemple parole:\n"
                    for i, password in enumerate(data['passwords'][:3], 1):
                        history_text += f"   {i}. {password}\n"

                    if len(data['passwords']) > 3:
                        history_text += f"   ... și încă {len(data['passwords']) - 3} parole\n"

                    history_text += "\n" + "-" * 60 + "\n\n"

                except Exception as e:
                    history_text += f"❌ Eroare la citirea {filename}: {str(e)}\n\n"

            self.history_text.insert(tk.END, history_text)

        except Exception as e:
            self.history_text.insert(tk.END, f"❌ Eroare la încărcarea istoricului: {str(e)}\n")

    def run(self):
        """Pornește aplicația"""
        self.root.mainloop()


if __name__ == "__main__":
    # Verifică dependențele
    try:
        from cryptography.fernet import Fernet
    except ImportError as e:
        print(f"Eroare: Lipsește dependența cryptography - {e}")
        print("Instalează cu: pip install cryptography")
        exit(1)

    try:
        from PIL import Image, ImageTk, ImageDraw

        print("PIL detectat - logo grafic va fi folosit")
    except ImportError:
        print("PIL nu este instalat - se va folosi logo text")
        print("Pentru logo grafic, instalează cu: pip install pillow")

    # Pornește aplicația
    app = PasswordGenerator()
    app.run()
