from openai import OpenAI

client = OpenAI(api_key='sk-proj-')
import tkinter as tk
from tkinter import ttk

# OpenAI API Key

# Function to interact with ChatGPT API using the new ChatCompletion method
def interact_with_chatgpt(prompt):
    try:
        # Use the new Chat API for GPT-based models
        response = client.chat.completions.create(model="gpt-4",  # You can also use gpt-3.5-turbo
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ])
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error: {e}"

# Function to generate prompt with CVSS variables based on the mode selected
def generate_prompt_with_cvss_variables(cvss_score, av, ac, au, c, i, a, mode):
    if mode == 'Explanation':
        prompt = (f"The CVSS score is {cvss_score}. The selected variables are: "
                  f"Attack Vector (AV): {av}, Attack Complexity (AC): {ac}, "
                  f"Authentication (Au): {au}, Confidentiality Impact (C): {c}, "
                  f"Integrity Impact (I): {i}, Availability Impact (A): {a}. "
                  "Can you provide an explanation based on this information?")
    elif mode == 'Recommendation':
        prompt = (f"The CVSS score is {cvss_score}. The selected variables are: "
                  f"Attack Vector (AV): {av}, Attack Complexity (AC): {ac}, "
                  f"Authentication (Au): {au}, Confidentiality Impact (C): {c}, "
                  f"Integrity Impact (I): {i}, Availability Impact (A): {a}. "
                  "What are some recommended actions for remediation?")
    elif mode == 'Attack Simulation':
        prompt = (f"The CVSS score is {cvss_score}. The selected variables are: "
                  f"Attack Vector (AV): {av}, Attack Complexity (AC): {ac}, "
                  f"Authentication (Au): {au}, Confidentiality Impact (C): {c}, "
                  f"Integrity Impact (I): {i}, Availability Impact (A): {a}. "
                  "Simulate a potential attack scenario based on this information.")
    else:
        prompt = "Invalid mode selected."

    return prompt

# Function to calculate CVSS score and automatically pass variables to ChatGPT
def calculate_cvss(event=None):
    # CVSS v3.1 weights
    av_weights = {"Network (N)": 0.85, "Adjacent Network (A)": 0.62, "Local (L)": 0.55, "Physical (P)": 0.2}
    ac_weights = {"Low (L)": 0.77, "High (H)": 0.44}
    pr_weights = {"None (N)": 0.85, "Low (L)": 0.62, "High (H)": 0.27}  # Scope not implemented, defaulting to unchanged
    ui_weights = {"None (N)": 0.85, "Required (R)": 0.62}
    cia_weights = {"None (N)": 0.0, "Low (L)": 0.22, "High (H)": 0.56}

    # Get user selections
    av = av_combo.get()
    ac = ac_combo.get()
    au = au_combo.get()  # Interpreted as PR
    c = c_combo.get()
    i = i_combo.get()
    a = a_combo.get()

    # Ensure all values are selected
    if not all([av, ac, au, c, i, a]):
        result_label.config(text="CVSS Score: Invalid input")
        return

    # Impact score
    impact_sub = 1 - ((1 - cia_weights[c]) * (1 - cia_weights[i]) * (1 - cia_weights[a]))
    impact = 6.42 * impact_sub

    # Exploitability
    exploitability = 8.22 * av_weights[av] * ac_weights[ac] * pr_weights[au] * ui_weights["None (N)"]

    # Final base score calculation
    if impact <= 0:
        base_score = 0.0
    else:
        base_score = min((impact + exploitability), 10)

    result_label.config(text=f"CVSS Score: {base_score:.1f}")

    # ChatGPT interaction
    mode = mode_combo.get()
    prompt = generate_prompt_with_cvss_variables(base_score, av, ac, au, c, i, a, mode)
    response = interact_with_chatgpt(prompt)

    response_textbox.config(state=tk.NORMAL)
    response_textbox.delete(1.0, tk.END)
    response_textbox.insert(tk.END, f"ChatGPT {mode}:\n{response}")
    response_textbox.config(state=tk.DISABLED)
# Initialize the main window
root = tk.Tk()
root.title("Offline CVSS Calculator with ChatGPT Integration")

# Main frame to hold all widgets
main_frame = ttk.Frame(root, padding="10 10 10 10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Vulnerability Name Entry
vulnerability_name_label = ttk.Label(main_frame, text="Vulnerability Name:")
vulnerability_name_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
vulnerability_name_entry = ttk.Entry(main_frame)
vulnerability_name_entry.grid(row=0, column=1, padx=10, pady=10)

# Section 1: Access Vector (AV)
av_label = ttk.Label(main_frame, text="Access Vector (AV):")
av_label.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
av_combo = ttk.Combobox(main_frame, values=["Network (N)", "Adjacent Network (A)", "Local (L)", "Physical (P)"])
av_combo.grid(row=1, column=1, padx=10, pady=10)

# Section 2: Access Complexity (AC)
ac_label = ttk.Label(main_frame, text="Access Complexity (AC):")
ac_label.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
ac_combo = ttk.Combobox(main_frame, values=["Low (L)", "High (H)"])
ac_combo.grid(row=2, column=1, padx=10, pady=10)

# Section 3: Authentication (Au)
au_label = ttk.Label(main_frame, text="Authentication (Au):")
au_label.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
au_combo = ttk.Combobox(main_frame, values=["Multiple (M)", "Single (S)", "None (N)"])
au_combo.grid(row=3, column=1, padx=10, pady=10)

# Section 4: Confidentiality Impact (C)
c_label = ttk.Label(main_frame, text="Confidentiality Impact (C):")
c_label.grid(row=4, column=0, padx=10, pady=10, sticky=tk.W)
c_combo = ttk.Combobox(main_frame, values=["None (N)", "Low (L)", "High (H)"])
c_combo.grid(row=4, column=1, padx=10, pady=10)

# Section 5: Integrity Impact (I)
i_label = ttk.Label(main_frame, text="Integrity Impact (I):")
i_label.grid(row=5, column=0, padx=10, pady=10, sticky=tk.W)
i_combo = ttk.Combobox(main_frame, values=["None (N)", "Low (L)", "High (H)"])
i_combo.grid(row=5, column=1, padx=10, pady=10)

# **Mode selection dropdown** Allows for users to select ChatGPT options (such as "Explanation", "Recommendation", or "Attack Simulation"). 
# Choose the type of analysis wanted from ChatGPT when interacting with the CVSS calculator.

# Section 6: Availability Impact (A)
a_label = ttk.Label(main_frame, text="Availability Impact (A):")
a_label.grid(row=6, column=0, padx=10, pady=10, sticky=tk.W)
a_combo = ttk.Combobox(main_frame, values=["None (N)", "Low (L)", "High (H)"])
a_combo.grid(row=6, column=1, padx=10, pady=10)

# Mode Selection for ChatGPT Interaction
mode_label = ttk.Label(main_frame, text="ChatGPT Mode:")
mode_label.grid(row=7, column=0, padx=10, pady=10, sticky=tk.W)
mode_combo = ttk.Combobox(main_frame, values=["Explanation", "Recommendation", "Attack Simulation"])
mode_combo.grid(row=7, column=1, padx=10, pady=10)

# Label to display the CVSS Score
result_label = ttk.Label(main_frame, text="CVSS Score: -", font=("Arial", 12, "bold"))
result_label.grid(row=8, column=0, columnspan=2, pady=10)

# Textbox to display ChatGPT response
response_textbox = tk.Text(main_frame, wrap="word", width=60, height=10)
response_textbox.grid(row=9, column=0, columnspan=2, padx=10, pady=10)
response_textbox.config(state=tk.DISABLED)  # Initially disable editing

# Button to calculate the CVSS score and generate ChatGPT response
calculate_button = ttk.Button(main_frame, text="Calculate CVSS", command=calculate_cvss)
calculate_button.grid(row=10, column=0, columnspan=2, padx=10, pady=10)

# Start the GUI loop
root.mainloop()
