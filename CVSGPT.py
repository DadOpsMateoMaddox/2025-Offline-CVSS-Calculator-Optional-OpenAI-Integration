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

# Function to send CVSS variables to ChatGPT
def generate_prompt_with_cvss_variables(cvss_score, av, ac, au, c, i, a):
    prompt = (f"The CVSS score is {cvss_score}. The selected variables are: "
              f"Attack Vector (AV): {av}, Attack Complexity (AC): {ac}, "
              f"Authentication (Au): {au}, Confidentiality Impact (C): {c}, "
              f"Integrity Impact (I): {i}, Availability Impact (A): {a}. "
              "Can you provide an analysis or recommendations based on this information?")
    return prompt

# Function to calculate CVSS score and automatically pass variables to ChatGPT
def calculate_cvss(event=None):
    # Weights for each metric
    av_weights = {"Network (N)": 1.0, "Adjacent Network (A)": 0.646, "Local (L)": 0.395, "Physical (P)": 0.2}
    ac_weights = {"Low (L)": 0.71, "High (H)": 0.35}
    au_weights = {"None (N)": 0.704, "Single (S)": 0.56, "Multiple (M)": 0.45}
    ci_weights = {"None (N)": 0.0, "Partial (P)": 0.275, High (H)": 0.66}

    # Get the values from the combo boxes
    av = av_combo.get()
    ac = ac_combo.get();
    au = au_combo.get()
    c = c_combo.get()
    i = i_combo.get()
    a = a_combo.get()

    # Calculate Impact
    impact = 10.41 * (1 - (1 - ci_weights.get(c, 0)) * (1 - ci_weights.get(i, 0)) * (1 - ci_weights.get(a, 0)))

    # Calculate Exploitability
    exploitability = 20 * av_weights.get(av, 0) * ac_weights.get(ac, 0) * au_weights.get(au, 0)

    # Calculate Base Score
    if impact > 0:
        f_impact = 1.176
    else:
        f_impact = 0
    base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact

    # Cap the base score to a maximum of 10.0
    base_score = min(base_score, 10.0)

    # Show the CVSS Score in the result label
    result_label.config(text=f"CVSS Score: {base_score:.1f}")

    # Generate a prompt with CVSS variables and send it to ChatGPT
    prompt = generate_prompt_with_cvss_variables(base_score, av, ac, au, c, i, a)
    response = interact_with_chatgpt(prompt)

    # Display the ChatGPT response
    response_textbox.config(state=tk.NORMAL)  # Enable textbox
    response_textbox.delete(1.0, tk.END)
    response_textbox.insert(tk.END, f"ChatGPT Analysis: {response}")
    response_textbox.config(state=tk.DISABLED)  # Disable textbox for editing

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

# Section 6: Availability Impact (A)
a_label = ttk.Label(main_frame, text="Availability Impact (A):")
a_label.grid(row=6, column=0, padx=10, pady=10, sticky=tk.W)
a_combo = ttk.Combobox(main_frame, values=["None (N)", "Low (L)", "High (H)"])
a_combo.grid(row=6, column=1, padx=10, pady=10)

# Label to display the CVSS Score
result_label = ttk.Label(main_frame, text="CVSS Score: -", font=("Arial", 12, "bold"))
result_label.grid(row=7, column=0, columnspan=2, pady=10)

# Textbox to display ChatGPT response
response_textbox = tk.Text(main_frame, wrap="word", width=60, height=10)
response_textbox.grid(row=8, column=0, columnspan=2, padx=10, pady=10)
response_textbox.config(state=tk.DISABLED)  # Initially disable editing

# Button to calculate the CVSS score and generate ChatGPT response
calculate_button = ttk.Button(main_frame, text="Calculate CVSS", command=calculate_cvss)
calculate_button

#Here's the rest of the code to complete the button setup:

calculate_button.grid(row=9, column=0, columnspan=2, padx=10, pady=10)

# Start the GUI loop
root.mainloop()
