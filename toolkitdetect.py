from collections import Counter
import math
import base64
import re 
import sys 

# --- INPUT ---

def read_input_file(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        return f.read().strip()
    
# --- DETECTORS ---

def looks_like_base64(text):
    text = text.replace('\n', '').strip()

    if len(text) < 8 or len(text) % 4 != 0:
        return False
    
    return bool(re.fullmatch(r'[A-Za-z0-9+/=]+', text))

def looks_like_hex(text):
    text = text.replace(' ', '').replace('\n', '').strip()

    return (
        len(text) >= 4 and
        len(text) %2 == 0 and
        all(c in '0123456789abcdefABCDEF' for c in text)
    )

def looks_like_caesar(text):
    letters = sum(c.isalpha() for c in text)
    return letters > 0 and letters / max(len(text), 1) > 0.7

# --- ROUTER ---

def detect_tools(text):
    tools = []

    stripped = text.replace("\n", "").strip()

    if re.fullmatch(r'(?:[0-9a-fA-F]{2})+', stripped):
        tools.append("hex")

    if looks_like_base64(text):
        tools.append("base64")

    if looks_like_caesar(text):
        tools.append("caesar")

    return tools

# --- DRIVER ---

def scan_file(filepath):
    text = read_input_file(filepath)
    tools = detect_tools(text)

    print(f"[+] Scanning: {filepath}")

    if tools:
        print("[+] Possible tools detected: ")

        for tool in tools:
            print(f"    - {tool}")
    else:
        print("[-] No obvious encoding detected")

    return text, tools 

def base64_decode(text):
    try:
        data = text.encode() if isinstance(text, str) else text 
        decoded_bytes = base64.b64decode(data, validate=True)

        if b'\x00' in decoded_bytes:
            return decoded_bytes 

        return decoded_bytes.decode(errors="ignore")
        
    except Exception:
        return None 
    
def hex_decode(text):
    cleaned = re.sub(r'[^0-9a-fA-F]', '', text)

    if len(cleaned) % 2 != 0:
        return None

    try:
        return bytes.fromhex(cleaned).decode(errors="ignore")
    except ValueError:
        return None 

ENGLISH_FREQ = {
    'e': 12.0, 't': 9.1, 'a': 8.1, 'o': 7.5, 'i': 7.0, 'n': 6.7,
    's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
    'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
    'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'x': 0.15,
    'j': 0.15, 'q': 0.10, 'z': 0.07
}

def english_score(text):
    text = text.lower()
    letters = [c for c in text if c.isalpha()]

    if not letters:
        return float('-inf')
    
    counts = Counter(letters)
    score = 0.0 

    for char, freq in ENGLISH_FREQ.items():
        observed = counts.get(char, 0) * 100 / len(letters)
        score -= abs(freq - observed)

    return score

def caesar_shift(text, shift):
    result = ""

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_bruteforce(text, top_n=3):
    candidates = []

    for shift in range(26):
        decoded = caesar_shift(text, shift)
        score = english_score(decoded)
        candidates.append((score, shift, decoded))

    candidates.sort(reverse=True)
    return candidates[:top_n]

def xor_single_byte(data, key):
    return bytes(b ^ key for b in data)

def xor_bruteforce(text, top_n=3):
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raw = text.encode(errors='ignore')

    candidates = []

    for key in range(256):
        decoded = xor_single_byte(raw, key)
        try:
            decoded_text = decoded.decode(errors='ignore')
        except Exception:
            continue

        score = english_score(decoded_text)
        candidates.append((score, key, decoded_text))

    candidates.sort(reverse=True)
    return candidates[:top_n]

def should_try_xor(text, threshold=15):
    baseline = english_score(text)
    results = xor_bruteforce(text, top_n=1)
    best_score = results[0][0]

    return best_score - baseline > threshold

def save_step(step_num, tool, content):
    ext = "bin" if isinstance(content, bytes) else "text"
    filename = f"step_{step_num}_{tool}.{ext}"

    mode = "wb" if isinstance(content, bytes) else "w"
    
    with open(filename, mode) as f:
        f.write(content)
        
    print(f"[+] Saved output to {filename}")

FLAG_PREFIXES = [
    "picoCTF",
    "CTF",
    "FLAG",
    "flag"
]

def flag_finder(text):
    prefixes = "|".join(FLAG_PREFIXES)
    pattern = rf'(?:{prefixes})\{{[^}}]+\}}'

    flags = re.findall(pattern, text)

    if flags:
        for flag in flags:
            print(f"[+] Found flag: {flag}")
    else:
        print("No flags found.")

    return flags

DECODERS = {
    "base64": base64_decode,
    "hex": hex_decode,
}

SPECIAL = ["caesar", "xor"]

def run_pipeline(text, max_depth=5):
    current = text 

    for step in range(1, max_depth + 1):
        print(f"\n[*] Pipeline step {step}")

        detected = detect_tools(current)
        progressed = False 

        for tool in detected:
            if tool in DECODERS:
                output = DECODERS[tool](current)

                if isinstance(output, bytes):
                    save_step(step, tool, output)
                    print("[+] Binary output detected - stopping pipeline")
                    return output

                if output and output != current:
                    save_step(step, tool, output)
                    current = output
                    progressed = True 
                    break

            elif tool == "caesar":
                results = caesar_bruteforce(current)

                if results:

                    best = results[0][2]
                    save_step(step, "caesar_best", best)
                    current = best 
                    progressed = True 
                    break 

        MAX_XOR_SIZE = 1024 

        if not progressed:
            if len(current) <= MAX_XOR_SIZE:
                print("[+] Trying XOR brute force as fallback")
                results = xor_bruteforce(current)
                for score, key, text_out in results:
                    save_step(step, f"xor_key_{key}", text_out)

                current = results[0][2]
                progressed = True
            
            else:
                print("[-] Skipping XOR brute force - input too large")
                break

        if isinstance(current, str):
            flags = flag_finder(current)
            if flags:
                print("[+] Flag detected - stopping pipeline")
                break
        
        if not progressed:
            print("[-] Pipeline stalled - stopping")
            break

    return current 

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <input_file>")
        return 
    
    filepath = sys.argv[1]

    text, tools = scan_file(filepath)

    final_text = run_pipeline(text)

    print("\n[*] Final scan for flags: ")
    flag_finder(final_text)

if __name__ == "__main__":

    main()
