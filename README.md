# CyberGuard — Password Strength & Vulnerability Analyzer

> **Cybersecurity Internship Project**  
> A lightweight, client-side web application built with **HTML5, CSS3, and Vanilla JavaScript** that analyzes password strength, calculates information entropy, detects common breach patterns, and generates cryptographically secure random passwords.

---

## 📌 Project Overview

Passwords remain the primary line of defense against unauthorized digital access. Weak, reused, and predictable passwords account for over **80% of confirmed data breaches**.

This project provides an interactive cybersecurity tool that educates users and evaluates passwords in real-time. It analyzes password complexity, calculates Shannon entropy, tests against common dictionary leaks and keyboard sequences, and estimates brute-force crack times.

### 🛡️ Privacy Guarantee
**100% Client-Side Execution:** All calculations, regular expression matching, and entropy metrics are computed entirely within the user's browser using Vanilla JavaScript. **No data is ever stored, logged, or transmitted over any network.**

---

## 🚀 Key Features

| Feature | Description |
| :--- | :--- |
| **Real-Time Analysis** | Evaluates passwords instantly on each keystroke without submitting forms or reloading. |
| **Show / Hide Password** | Seamless toggle with SVG icons to verify entered credentials safely. |
| **Security Checklist** | Live checklist checking length, uppercase, lowercase, numbers, symbols, and pattern absence. |
| **Strength Meter & Score** | Visual dynamic progress bar (0–100%) color-coded across 5 levels (*Very Weak*, *Weak*, *Fair*, *Strong*, *Very Strong*). |
| **Crack Time Estimator** | Calculates the approximate time required to crack the password assuming a 10-billion-hash/second GPU rig. |
| **Pattern & Breach Detection** | Identifies dictionary-leaked words (`password`, `admin`, `welcome`), repeated characters (`aaa`), and keyboard walks (`qwerty`, `1234`). |
| **Dynamic Suggestions** | Actionable tips that dynamically update to guide the user toward stronger passwords. |
| **Secure CSPRNG Generator** | Generates strong passwords using the browser's native `window.crypto.getRandomValues()` API (avoiding insecure `Math.random()`). |
| **One-Click Clipboard & Transfer** | Easily copy generated passwords or send them directly into the analyzer for verification. |
| **Fully Responsive** | Optimized for mobile screens, tablets, laptops, and wide desktop displays. |

---

## 📂 Project Structure

```text
password-strength-analyzer/
├── index.html        # Semantic HTML5 markup, layout, and UI components
├── style.css         # Modern cybersecurity dark theme, styles, and animations
├── script.js         # Core logic: analysis, entropy math, pattern checks, & generator
└── README.md         # Documentation, concepts, testing guide, and viva prep
```

### File Breakdown (Beginner-Friendly Explanation)

1. **`index.html`**:
   - Defines the webpage layout using semantic HTML tags (`<header>`, `<main>`, `<section>`, `<footer>`).
   - Houses the password input box, show/hide toggle buttons, strength meter container, checklist items, and the random password generator interface.
   - Embeds clean SVG icons directly, meaning **no external libraries or internet connections** are needed to display icons.

2. **`style.css`**:
   - Implements a modern **Cybersecurity Dark Theme** (deep slate `#080d1a`, glowing cyber-cyan `#00f2fe`, and emerald green `#10b981`).
   - Uses **CSS Variables** (`:root`) for easy color customization.
   - Uses **CSS Flexbox & CSS Grid** to make the dashboard fully responsive on phones and computers.
   - Features smooth CSS transitions for the progress bar, button hover glows, and status badges.

3. **`script.js`**:
   - Contains clean, commented JavaScript divided into logical modules:
     - **Event Listeners**: Watches for user typing and button clicks.
     - **Pattern Detector**: Scans for sequences (`123`, `abc`), keyboard walks (`qwerty`), and leaked dictionary words.
     - **Entropy Calculator**: Applies the formula $E = L \times \log_2(R)$ to measure information entropy in bits.
     - **Scoring Engine**: Calculates a score from 0 to 100 based on length, character diversity, and pattern penalties.
     - **CSPRNG Password Generator**: Uses `window.crypto.getRandomValues()` and the Fisher-Yates shuffle algorithm to generate cryptographically unbiased passwords.

4. **`README.md`**:
   - Comprehensive documentation for submission, explaining technical concepts, testing steps, and project architecture.

---

## 🧠 Cybersecurity Concepts Used

### 1. Information Entropy (Shannon Entropy)
Entropy measures the unpredictability of a password. It is measured in **bits**:
$$\text{Entropy} = L \times \log_2(R)$$
- **$L$** = Length of the password.
- **$R$** = Pool size of possible characters (e.g., lowercase [26] + uppercase [26] + digits [10] + symbols [33] = 95).
- A password with $> 60$ bits of entropy is considered resilient against standard brute-force attacks; $> 80$ bits is considered highly secure.

### 2. CSPRNG vs `Math.random()`
Most beginner JavaScript tutorials use `Math.random()`, which is **pseudorandom** and predictable (uses algorithms like xorshift128+). Attackers can predict future outputs from observed outputs.
This project strictly uses `window.crypto.getRandomValues()`, which interfaces with the operating system's hardware entropy pool (mouse movements, CPU timings), making generated passwords cryptographically secure.

### 3. Common Vulnerability Patterns
Brute-force attackers do not guess uniformly; they prioritize:
- **Dictionary Attacks**: Testing leaked databases (e.g., RockYou).
- **Mask Attacks / Keystroke Walks**: Sequences like `qwerty` or `asdfgh` that follow physical keyboard geometry.
- **Sequential & Birthday Patterns**: Sequential numbers (`1234`) or years (`1998`, `2024`).

---

## 💻 How to Run and Test the Website

You don't need any special backend, database, or package managers (like Node.js or npm).

### Method 1: Direct File Open (Simplest)
1. Open the project folder in Windows File Explorer:
   `c:\Users\Krupa\OneDrive\Desktop\password-strength-analyzer`
2. **Double-click `index.html`** (or right-click $\rightarrow$ **Open with** $\rightarrow$ **Google Chrome**, **Microsoft Edge**, or **Firefox**).
3. The website will load instantly in your default web browser!

### Method 2: Using VS Code Live Server (Recommended for Development)
1. Open the project folder in **Visual Studio Code**.
2. If you have the **Live Server** extension installed:
   - Right-click anywhere in `index.html` and select **"Open with Live Server"**.
3. It will open `http://127.0.0.1:5500/index.html` with live-reload support.

### Method 3: Using Python's Built-In HTTP Server
If you have Python installed, open PowerShell in the project folder and run:
```powershell
python -m http.server 8000
```
Then visit `http://localhost:8000` in your browser.

---

## 🧪 Test Cases (Try These in the Analyzer!)

| Test Case | Password to Try | Expected Strength | Observations & Feedback |
| :--- | :--- | :--- | :--- |
| **Common Leaked Password** | `password123` | **Very Weak** | Triggers the red vulnerability warning banner: detected in breach dictionaries. |
| **Keyboard Walk** | `qwerty123` | **Very Weak** | Detects sequential keyboard rows and numbers; penalizes score. |
| **Repeated Characters** | `aaaa1111` | **Very Weak** | Identifies repetitive characters that drastically reduce entropy. |
| **Only Letters (No Variety)** | `mysecretword` | **Weak** | Suggests adding uppercase letters, numbers, and symbols. |
| **Standard Mixed Password** | `P@ssw0rd2024` | **Fair** | Contains diversity, but penalized for common word roots and year pattern. |
| **Strong Passphrase** | `battery-horse-staple-99` | **Strong** | Long character length provides high resistance to brute force. |
| **Cryptographic Random** | *(Use the built-in generator)* | **Very Strong (95-100)** | Full green meter, 80+ bits entropy, crack time measured in centuries. |

---

## 🎯 Questions an Internship Evaluator / Examiner Might Ask

<details>
<summary><strong>Q1: Why is client-side password checking safer for user privacy?</strong></summary>
<em>Answer:</em> Transmitting passwords to a remote server for analysis introduces serious security risks (man-in-the-middle attacks, server logging, and network eavesdropping). Running all checks locally in JavaScript guarantees the user's password never leaves their device.
</details>

<details>
<summary><strong>Q2: Why is length more important than complexity for password entropy?</strong></summary>
<em>Answer:</em> In the entropy formula $E = L \times \log_2(R)$, length ($L$) acts as a linear multiplier outside the logarithm, whereas character pool size ($R$) is compressed by $\log_2$. Adding 4 characters often provides greater exponential search complexity than merely swapping a letter for a symbol.
</details>

<details>
<summary><strong>Q3: Why did you use <code>window.crypto.getRandomValues</code> instead of <code>Math.random()</code>?</strong></summary>
<em>Answer:</em> <code>Math.random()</code> is a pseudo-random number generator (PRNG) intended for statistics or games, not cryptography. Its seed and internal states can be determined. <code>window.crypto.getRandomValues()</code> is a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) backed by OS-level entropy.
</details>

---

## 📜 License & Acknowledgments
- Developed as an educational Cybersecurity Internship Project.
- Free to modify and enhance for academic presentations and learning portfolios.
