/**
 * CyberGuard Password Strength & Vulnerability Analyzer
 * Vanilla JavaScript (ES6+) - 100% Client-Side
 * 
 * This script handles:
 * 1. Real-time password criteria evaluation
 * 2. Information entropy calculation (Shannon Entropy)
 * 3. Detection of breached passwords & predictable patterns (keyboard walks, sequences)
 * 4. Crack time estimation based on brute-force speeds
 * 5. Dynamic improvement suggestions
 * 6. Cryptographically secure random password generation (Web Crypto API)
 */

document.addEventListener("DOMContentLoaded", () => {
  // =========================================================================
  // 1. DOM Elements Selection
  // =========================================================================
  const passwordInput = document.getElementById("passwordInput");
  const togglePasswordBtn = document.getElementById("togglePasswordBtn");
  const clearInputBtn = document.getElementById("clearInputBtn");
  const eyeIcon = document.getElementById("eyeIcon");
  const eyeOffIcon = document.getElementById("eyeOffIcon");

  // Meter & Badges
  const strengthBar = document.getElementById("strengthBar");
  const strengthLabel = document.getElementById("strengthLabel");
  const strengthScore = document.getElementById("strengthScore");
  const entropyBadge = document.getElementById("entropyBadge");
  const crackTimeValue = document.getElementById("crackTimeValue");

  // Warning & Checklist
  const warningBox = document.getElementById("warningBox");
  const warningText = document.getElementById("warningText");
  const suggestionsList = document.getElementById("suggestionsList");

  // Checklist items
  const reqLength = document.getElementById("reqLength");
  const reqLower = document.getElementById("reqLower");
  const reqUpper = document.getElementById("reqUpper");
  const reqNumber = document.getElementById("reqNumber");
  const reqSpecial = document.getElementById("reqSpecial");
  const reqPattern = document.getElementById("reqPattern");
  const lengthCounter = document.getElementById("lengthCounter");

  // Generator Elements
  const lengthSlider = document.getElementById("lengthSlider");
  const lengthValueDisplay = document.getElementById("lengthValueDisplay");
  const genUpper = document.getElementById("genUpper");
  const genLower = document.getElementById("genLower");
  const genNumbers = document.getElementById("genNumbers");
  const genSymbols = document.getElementById("genSymbols");
  const generateBtn = document.getElementById("generateBtn");
  const generatedPasswordOutput = document.getElementById("generatedPasswordOutput");
  const copyPasswordBtn = document.getElementById("copyPasswordBtn");
  const copyFeedback = document.getElementById("copyFeedback");
  const useGeneratedBtn = document.getElementById("useGeneratedBtn");

  // =========================================================================
  // 2. Security Dictionaries & Known Patterns
  // =========================================================================
  
  // Top commonly breached & weak passwords (case-insensitive check)
  const COMMON_WEAK_PASSWORDS = [
    "password", "password123", "123456", "12345678", "123456789", "qwerty", 
    "12345", "1234", "111111", "1234567", "dragon", "123123", "baseball", 
    "football", "shadow", "master", "monkey", "superman", "killer", "trustno1", 
    "admin", "administrator", "welcome", "welcome1", "login", "iloveyou", 
    "princess", "starwars", "passphrase", "default", "changeme", "guest", 
    "charlie", "donald", "batman", "letmein", "sunshine", "access", "hello",
    "secret", "testing", "computer", "internet", "matrix", "test1234", "system"
  ];

  // Common keyboard sequence rows to detect simple walks
  const KEYBOARD_SEQUENCES = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890"
  ];

  // =========================================================================
  // 3. Password Analysis Functions
  // =========================================================================

  /**
   * Checks for predictable sequences like '1234', 'abcd', or 'qwerty'.
   * @param {string} pwd - The password string
   * @returns {boolean} - True if a sequential pattern is detected
   */
  function hasSequentialPatterns(pwd) {
    const lower = pwd.toLowerCase();

    // Check keyboard rows (3 or more adjacent keys)
    for (const row of KEYBOARD_SEQUENCES) {
      for (let i = 0; i <= row.length - 3; i++) {
        const forward = row.substring(i, i + 3);
        const reverse = forward.split("").reverse().join("");
        if (lower.includes(forward) || lower.includes(reverse)) {
          return true;
        }
      }
    }

    // Check alphabetical sequence (e.g. 'abc', 'xyz', 'cba')
    for (let i = 0; i < pwd.length - 2; i++) {
      const code1 = lower.charCodeAt(i);
      const code2 = lower.charCodeAt(i + 1);
      const code3 = lower.charCodeAt(i + 2);

      if ((code2 === code1 + 1 && code3 === code2 + 1) || 
          (code2 === code1 - 1 && code3 === code2 - 1)) {
        return true;
      }
    }

    // Check 4-digit common birth/century years (e.g., 1980-2029)
    if (/(?:19[5-9]\d|20[0-2]\d)/.test(pwd)) {
      return true;
    }

    return false;
  }

  /**
   * Checks for 3 or more repeated identical characters in a row (e.g. 'aaa', '1111').
   * @param {string} pwd - The password string
   * @returns {boolean}
   */
  function hasRepeatedChars(pwd) {
    return /(.)\1{2,}/.test(pwd);
  }

  /**
   * Calculates Shannon / Combinatorial Entropy in bits.
   * Entropy = length * log2(poolSize)
   * @param {string} pwd - The password string
   * @returns {number} - Entropy in bits
   */
  function calculateEntropy(pwd) {
    if (!pwd) return 0;

    let poolSize = 0;
    if (/[a-z]/.test(pwd)) poolSize += 26;
    if (/[A-Z]/.test(pwd)) poolSize += 26;
    if (/[0-9]/.test(pwd)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) poolSize += 33; // standard keyboard symbols

    if (poolSize === 0) return 0;
    const entropy = pwd.length * Math.log2(poolSize);
    return Math.round(entropy);
  }

  /**
   * Estimates brute-force crack time assuming a modern attack cluster
   * capable of checking ~10 billion (10^10) guesses per second.
   * @param {number} entropy - Password entropy in bits
   * @returns {string} - Human-readable time estimate
   */
  function estimateCrackTime(entropy) {
    if (entropy <= 0) return "Instant";
    
    // Total possible combinations = 2^entropy
    // Time in seconds = (2^entropy) / (10^10 hashes per second)
    const log2GuessesPerSec = Math.log2(1e10); // ~33.2 bits
    const netBits = entropy - log2GuessesPerSec;

    if (netBits <= 0) return "Instant (< 1 millisecond)";
    
    // Calculate seconds from remaining bits
    const seconds = Math.pow(2, netBits);

    if (seconds < 60) {
      return `${Math.max(1, Math.round(seconds))} seconds`;
    }
    const minutes = seconds / 60;
    if (minutes < 60) {
      return `${Math.round(minutes)} minutes`;
    }
    const hours = minutes / 60;
    if (hours < 24) {
      return `${Math.round(hours)} hours`;
    }
    const days = hours / 24;
    if (days < 365) {
      return `${Math.round(days)} days`;
    }
    const years = days / 365.25;
    if (years < 1000) {
      return `${Math.round(years)} years`;
    }
    if (years < 1000000) {
      return `${(years / 1000).toFixed(1)} thousand years`;
    }
    if (years < 1000000000) {
      return `${(years / 1000000).toFixed(1)} million years`;
    }
    return "Centuries (Centillions of years)";
  }

  /**
   * Main analyzer: computes strength score, checks criteria, generates warnings and tips.
   * @param {string} pwd - The input password
   */
  function analyzePassword(pwd) {
    // 1. Reset state if empty
    if (!pwd || pwd.length === 0) {
      resetAnalyzer();
      return;
    }

    const length = pwd.length;
    lengthCounter.textContent = `${length} char${length === 1 ? '' : 's'}`;

    // Criteria checks
    const hasLength = length >= 8;
    const hasLower = /[a-z]/.test(pwd);
    const hasUpper = /[A-Z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSpecial = /[^a-zA-Z0-9]/.test(pwd);

    // Pattern checks
    const isSequential = hasSequentialPatterns(pwd);
    const isRepeated = hasRepeatedChars(pwd);
    const isCommonWeak = COMMON_WEAK_PASSWORDS.includes(pwd.toLowerCase());
    const hasPatternIssue = isSequential || isRepeated || isCommonWeak;

    // Update Criteria Checklist UI
    updateChecklistItem(reqLength, hasLength);
    updateChecklistItem(reqLower, hasLower);
    updateChecklistItem(reqUpper, hasUpper);
    updateChecklistItem(reqNumber, hasNumber);
    updateChecklistItem(reqSpecial, hasSpecial);
    updateChecklistItem(reqPattern, !hasPatternIssue);

    // Calculate Entropy
    const entropy = calculateEntropy(pwd);
    entropyBadge.textContent = `${entropy} bits entropy`;

    // 2. Score Calculation (0 to 100 scale)
    let score = 0;

    // Length scoring
    if (length > 0 && length < 8) {
      score += length * 3; // up to 21
    } else if (length >= 8 && length < 12) {
      score += 25 + (length - 8) * 4; // 25 to 37
    } else if (length >= 12 && length < 16) {
      score += 40 + (length - 12) * 4; // 40 to 52
    } else if (length >= 16) {
      score += 60 + Math.min((length - 16) * 2, 15); // 60 to 75
    }

    // Character variety scoring
    if (hasLower) score += 5;
    if (hasUpper) score += 5;
    if (hasNumber) score += 5;
    if (hasSpecial) score += 10;

    // Entropy bonus
    if (entropy > 50) score += 5;
    if (entropy > 75) score += 5;

    // Deductions for bad patterns
    if (isSequential) score -= 15;
    if (isRepeated) score -= 15;

    // Severe penalty if password is only letters or only digits
    if (/^[a-zA-Z]+$/.test(pwd) || /^\d+$/.test(pwd)) {
      score -= 15;
    }

    // Critical override: if password is a known common breach, cap score
    if (isCommonWeak) {
      score = Math.min(score, 10);
    }

    // Clamp score strictly between 5 and 100
    score = Math.max(5, Math.min(100, score));

    // 3. Determine Strength Label, Color & Crack Time
    let label = "Very Weak";
    let statusClass = "status-very-weak";
    let barColor = "var(--status-very-weak)";

    if (score < 25) {
      label = "Very Weak";
      statusClass = "status-very-weak";
      barColor = "var(--status-very-weak)";
    } else if (score < 50) {
      label = "Weak";
      statusClass = "status-weak";
      barColor = "var(--status-weak)";
    } else if (score < 70) {
      label = "Fair";
      statusClass = "status-fair";
      barColor = "var(--status-fair)";
    } else if (score < 88) {
      label = "Strong";
      statusClass = "status-strong";
      barColor = "var(--status-strong)";
    } else {
      label = "Very Strong";
      statusClass = "status-very-strong";
      barColor = "var(--status-very-strong)";
    }

    // Update Progress Bar & Score Display
    strengthScore.textContent = `${score} / 100`;
    strengthLabel.textContent = label;
    strengthLabel.className = `strength-status ${statusClass}`;

    strengthBar.style.width = `${score}%`;
    strengthBar.style.backgroundColor = barColor;

    // Glow effect for very strong passwords
    if (score >= 88) {
      strengthBar.style.boxShadow = "0 0 12px rgba(0, 242, 254, 0.7)";
    } else {
      strengthBar.style.boxShadow = "none";
    }

    // Estimate crack time
    crackTimeValue.textContent = estimateCrackTime(entropy);

    // 4. Vulnerability Warning Box Management
    if (isCommonWeak) {
      warningBox.classList.remove("hidden");
      warningText.textContent = `"${pwd}" was detected in known data breach dictionaries! Automated attacker tools guess this password in milliseconds.`;
    } else if (isSequential) {
      warningBox.classList.remove("hidden");
      warningText.textContent = "Sequential patterns (like '123', 'abc', or 'qwerty') or year formats make passwords easily guessable by dictionary cracking tools.";
    } else if (isRepeated) {
      warningBox.classList.remove("hidden");
      warningText.textContent = "Repeating characters (e.g. 'aaa' or '111') drastically lower password entropy and make it vulnerable.";
    } else {
      warningBox.classList.add("hidden");
    }

    // 5. Dynamic Suggestions Engine
    generateSuggestions({
      pwd,
      length,
      hasLength,
      hasLower,
      hasUpper,
      hasNumber,
      hasSpecial,
      isCommonWeak,
      isSequential,
      isRepeated,
      score
    });
  }

  /**
   * Helper to update checklist item styles
   */
  function updateChecklistItem(element, isValid) {
    const iconSpan = element.querySelector(".criteria-icon");
    if (isValid) {
      element.classList.add("valid");
      element.classList.remove("invalid");
      iconSpan.textContent = "✓";
    } else {
      element.classList.remove("valid");
      element.classList.add("invalid");
      iconSpan.textContent = "✕";
    }
  }

  /**
   * Helper to reset checklist to neutral state
   */
  function resetChecklistItem(element) {
    element.classList.remove("valid", "invalid");
    const iconSpan = element.querySelector(".criteria-icon");
    iconSpan.textContent = "•";
  }

  /**
   * Resets analyzer to empty starting view
   */
  function resetAnalyzer() {
    lengthCounter.textContent = "0 chars";
    entropyBadge.textContent = "0 bits entropy";
    strengthScore.textContent = "0 / 100";
    strengthLabel.textContent = "Enter a password";
    strengthLabel.className = "strength-status status-empty";
    strengthBar.style.width = "0%";
    strengthBar.style.backgroundColor = "var(--text-dim)";
    strengthBar.style.boxShadow = "none";
    crackTimeValue.textContent = "Instant";
    warningBox.classList.add("hidden");

    [reqLength, reqLower, reqUpper, reqNumber, reqSpecial, reqPattern].forEach(resetChecklistItem);

    suggestionsList.innerHTML = `
      <li class="suggestion-item">Start typing a password above to view real-time recommendations.</li>
    `;
  }

  /**
   * Generates dynamic actionable suggestions based on missing criteria.
   */
  function generateSuggestions(data) {
    const suggestions = [];

    if (data.isCommonWeak) {
      suggestions.push("Immediately replace this with an unguessable phrase. Never use words found in leaked password databases.");
    }

    if (data.length < 8) {
      suggestions.push("Increase length to at least 8 characters. Minimum 12-16 characters is ideal.");
    } else if (data.length < 12) {
      suggestions.push("Consider expanding to 12 or more characters. Length is the #1 defense against brute-force attacks.");
    }

    if (!data.hasUpper) {
      suggestions.push("Add uppercase letters (A-Z) to widen the character search space.");
    }

    if (!data.hasLower) {
      suggestions.push("Add lowercase letters (a-z).");
    }

    if (!data.hasNumber) {
      suggestions.push("Include numeric digits (0-9).");
    }

    if (!data.hasSpecial) {
      suggestions.push("Add special characters or symbols (such as !, @, #, $, %, ^, &).");
    }

    if (data.isSequential) {
      suggestions.push("Break up sequential keystrokes (like '123' or 'abc') with unexpected characters.");
    }

    if (data.isRepeated) {
      suggestions.push("Remove repeating characters (e.g., replace 'aaa' with varied characters).");
    }

    // When everything looks good!
    if (suggestions.length === 0 && data.score >= 80) {
      suggestions.push("🎉 Excellent work! Your password has high cryptographic entropy and no obvious patterns.");
      suggestions.push("Tip: Make sure you do not reuse this same password across other websites.");
    }

    // Render suggestions in DOM
    suggestionsList.innerHTML = suggestions
      .map(tip => `<li class="suggestion-item">${tip}</li>`)
      .join("");
  }

  // =========================================================================
  // 4. Secure Random Password Generator (Web Crypto API)
  // =========================================================================

  const CHARSETS = {
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    lower: "abcdefghijklmnopqrstuvwxyz",
    numbers: "0123456789",
    symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?"
  };

  /**
   * Generates a random number in range [0, max) using CSPRNG.
   * Prevents modulo bias.
   */
  function getSecureRandomInt(max) {
    const randomBuffer = new Uint32Array(1);
    const maxUint = 0xffffffff;
    const limit = maxUint - (maxUint % max);

    let rand;
    do {
      window.crypto.getRandomValues(randomBuffer);
      rand = randomBuffer[0];
    } while (rand >= limit);

    return rand % max;
  }

  /**
   * Generates a cryptographically strong random password.
   */
  function generateSecurePassword() {
    const length = parseInt(lengthSlider.value, 10);
    const includeUpper = genUpper.checked;
    const includeLower = genLower.checked;
    const includeNumbers = genNumbers.checked;
    const includeSymbols = genSymbols.checked;

    let availableChars = "";
    const mandatoryChars = [];

    if (includeUpper) {
      availableChars += CHARSETS.upper;
      mandatoryChars.push(CHARSETS.upper[getSecureRandomInt(CHARSETS.upper.length)]);
    }
    if (includeLower) {
      availableChars += CHARSETS.lower;
      mandatoryChars.push(CHARSETS.lower[getSecureRandomInt(CHARSETS.lower.length)]);
    }
    if (includeNumbers) {
      availableChars += CHARSETS.numbers;
      mandatoryChars.push(CHARSETS.numbers[getSecureRandomInt(CHARSETS.numbers.length)]);
    }
    if (includeSymbols) {
      availableChars += CHARSETS.symbols;
      mandatoryChars.push(CHARSETS.symbols[getSecureRandomInt(CHARSETS.symbols.length)]);
    }

    // Fallback if user unchecks all boxes: default to lower + numbers
    if (availableChars.length === 0) {
      genLower.checked = true;
      genNumbers.checked = true;
      availableChars = CHARSETS.lower + CHARSETS.numbers;
      mandatoryChars.push(CHARSETS.lower[getSecureRandomInt(CHARSETS.lower.length)]);
      mandatoryChars.push(CHARSETS.numbers[getSecureRandomInt(CHARSETS.numbers.length)]);
    }

    // Fill the remaining password length
    const resultChars = [...mandatoryChars];
    for (let i = mandatoryChars.length; i < length; i++) {
      const randIndex = getSecureRandomInt(availableChars.length);
      resultChars.push(availableChars[randIndex]);
    }

    // Fisher-Yates shuffle using cryptographically secure random integers
    for (let i = resultChars.length - 1; i > 0; i--) {
      const j = getSecureRandomInt(i + 1);
      const temp = resultChars[i];
      resultChars[i] = resultChars[j];
      resultChars[j] = temp;
    }

    const generatedPassword = resultChars.join("");
    generatedPasswordOutput.value = generatedPassword;
    return generatedPassword;
  }

  // =========================================================================
  // 5. Event Listeners & UI Handlers
  // =========================================================================

  // Real-time input listener for analyzer
  passwordInput.addEventListener("input", (e) => {
    analyzePassword(e.target.value);
  });

  // Clear input button
  clearInputBtn.addEventListener("click", () => {
    passwordInput.value = "";
    analyzePassword("");
    passwordInput.focus();
  });

  // Show / Hide password toggle
  togglePasswordBtn.addEventListener("click", () => {
    const isPassword = passwordInput.getAttribute("type") === "password";
    if (isPassword) {
      passwordInput.setAttribute("type", "text");
      eyeIcon.classList.add("hidden");
      eyeOffIcon.classList.remove("hidden");
      togglePasswordBtn.setAttribute("title", "Hide password");
    } else {
      passwordInput.setAttribute("type", "password");
      eyeIcon.classList.remove("hidden");
      eyeOffIcon.classList.add("hidden");
      togglePasswordBtn.setAttribute("title", "Show password");
    }
  });

  // Slider change updates length display
  lengthSlider.addEventListener("input", (e) => {
    lengthValueDisplay.textContent = e.target.value;
  });

  // Generate button click
  generateBtn.addEventListener("click", () => {
    generateSecurePassword();
  });

  // Copy password to clipboard
  copyPasswordBtn.addEventListener("click", async () => {
    const passwordToCopy = generatedPasswordOutput.value;
    if (!passwordToCopy || passwordToCopy === "Click Generate Below") {
      generateSecurePassword();
    }

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(generatedPasswordOutput.value);
      } else {
        // Fallback for non-https or older environments
        generatedPasswordOutput.select();
        document.execCommand("copy");
      }

      // Show copied confirmation tooltip
      copyFeedback.classList.remove("hidden");
      setTimeout(() => {
        copyFeedback.classList.add("hidden");
      }, 2500);
    } catch (err) {
      console.error("Clipboard copy failed: ", err);
    }
  });

  // "Analyze This Password" button transfers generated password into analyzer
  useGeneratedBtn.addEventListener("click", () => {
    if (generatedPasswordOutput.value === "Click Generate Below") {
      generateSecurePassword();
    }
    passwordInput.value = generatedPasswordOutput.value;
    analyzePassword(passwordInput.value);
    
    // Smooth scroll up to analyzer on mobile devices
    passwordInput.scrollIntoView({ behavior: "smooth", block: "center" });
    passwordInput.focus();
  });

  // Generate an initial random password on page load so the generator isn't empty
  generateSecurePassword();
});
