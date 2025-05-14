import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk

# Function to calculate CVSS score based on selected metrics
def calculate_cvss(event=None):
    # Weights for each metric
    av_weights = {"Network (N)": 1.0, "Adjacent Network (A)": 0.646, "Local (L)": 0.395, "Physical (P)": 0.2}
    ac_weights = {"Low (L)": 0.71, "High (H)": 0.35}
    au_weights = {"None (N)": 0.704, "Single (S)": 0.56, "Multiple (M)": 0.45}
    ci_weights = {"None (N)": 0.0, "Partial (P)": 0.275, "Complete (C)": 0.66}
    
    # Get the values from the combo boxes
    av = av_weights.get(av_combo.get(), 0)
    ac = ac_weights.get(ac_combo.get(), 0)
    au = au_weights.get(au_combo.get(), 0)
    c = ci_weights.get(c_combo.get(), 0)
    i = ci_weights.get(i_combo.get(), 0)
    a = ci_weights.get(a_combo.get(), 0)
    
    # Calculate Impact
    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    
    # Calculate Exploitability
    exploitability = 20 * av * ac * au
    
    # Calculate Base Score
    if impact > 0:
        f_impact = 1.176
    else:
        f_impact = 0
    base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    
    # Cap the base score to a maximum of 10.0
    base_score = min(base_score, 10.0)
    
    result_label.config(text=f"CVSS Score: {base_score:.1f}")

# Function to hide tooltip
def hide_tooltip(event):
    if hasattr(event.widget, "tooltip"):
        event.widget.tooltip.destroy()

# Initialize the main window
root = tk.Tk()
root.title("Offline CVSS Calculator")

# Main frame to hold all widgets
main_frame = ttk.Frame(root, padding="10 10 10 10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Section 1: Access Vector (AV)
av_label = ttk.Label(main_frame, text="Access Vector (AV):")
av_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
av_combo = ttk.Combobox(main_frame, values=["Network (N)", "Adjacent Network (A)", "Local (L)", "Physical (P)"])
av_combo.grid(row=0, column=1, padx=10, pady=10)
av_combo.bind("<<ComboboxSelected>>", calculate_cvss)
av_combo.bind("<Enter>", lambda event: show_tooltip(event, "Defines how the vulnerability is exploited."))
av_combo.bind("<Leave>", hide_tooltip)

# Section 2: Access Complexity (AC)
ac_label = ttk.Label(main_frame, text="Access Complexity (AC):")
ac_label.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
ac_combo = ttk.Combobox(main_frame, values=["Low (L)", "High (H)"])
ac_combo.grid(row=1, column=1, padx=10, pady=10)
ac_combo.bind("<<ComboboxSelected>>", calculate_cvss)
ac_combo.bind("<Enter>", lambda event: show_tooltip(event, "Describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability."))
ac_combo.bind("<Leave>", hide_tooltip)

# Section 3: Authentication (Au)
au_label = ttk.Label(main_frame, text="Authentication (Au):")
au_label.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
au_combo = ttk.Combobox(main_frame, values=["Multiple (M)", "Single (S)", "None (N)"])
au_combo.grid(row=2, column=1, padx=10, pady=10)
au_combo.bind("<<ComboboxSelected>>", calculate_cvss)
au_combo.bind("<Enter>", lambda event: show_tooltip(event, "The number of times an attacker must authenticate to exploit a vulnerability."))
au_combo.bind("<Leave>", hide_tooltip)

# Section 4: Confidentiality Impact (C)
c_label = ttk.Label(main_frame, text="Confidentiality Impact (C):")
c_label.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
c_combo = ttk.Combobox(main_frame, values=["None (N)", "Partial (P)", "Complete (C)"])
c_combo.grid(row=3, column=1, padx=10, pady=10)
c_combo.bind("<<ComboboxSelected>>", calculate_cvss)
c_combo.bind("<Enter>", lambda event: show_tooltip(event, "Measures the impact on confidentiality of a successful exploit of the vulnerability."))
c_combo.bind("<Leave>", hide_tooltip)

# Section 5: Integrity Impact (I)
i_label = ttk.Label(main_frame, text="Integrity Impact (I):")
i_label.grid(row=4, column=0, padx=10, pady=10, sticky=tk.W)
i_combo = ttk.Combobox(main_frame, values=["None (N)", "Partial (P)", "Complete (C)"])
i_combo.grid(row=4, column=1, padx=10, pady=10)
i_combo.bind("<<ComboboxSelected>>", calculate_cvss)
i_combo.bind("<Enter>", lambda event: show_tooltip(event, "Measures the impact on integrity of a successful exploit of the vulnerability."))
i_combo.bind("<Leave>", hide_tooltip)

# Section 6: Availability Impact (A)
a_label = ttk.Label(main_frame, text="Availability Impact (A):")
a_label.grid(row=5, column=0, padx=10, pady=10, sticky=tk.W)
a_combo = ttk.Combobox(main_frame, values=["None (N)", "Partial (P)", "Complete (C)"])
a_combo.grid(row=5, column=1, padx=10, pady=10)
a_combo.bind("<<ComboboxSelected>>", calculate_cvss)
a_combo.bind("<Enter>", lambda event: show_tooltip(event, "Measures the impact on availability of a successful exploit of the vulnerability."))
a_combo.bind("<Leave>", hide_tooltip)

# Label to display the result
result_label = ttk.Label(main_frame, text="CVSS Score: -", font=("Arial", 12, "bold"))
result_label.grid(row=6, column=0, columnspan=2, pady=10)

# Start the GUI loop
root.mainloop()
