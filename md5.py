import hashlib

target_hash = "md5值"
password_found = False  # Eine Variable, um zu verfolgen, ob wir es gefunden haben

# Stelle sicher, dass der Pfad zu rockyou.txt korrekt ist
wordlist_path = "/usr/share/wordlists/rockyou.txt"

try:
    with open(wordlist_path, "r", encoding='utf-8', errors='ignore') as file:
        print(f"Starting search in {wordlist_path} for hash {target_hash}...")
        for line_number, line in enumerate(file, 1):
            word = line.strip()
            
            # Deine Logik: Wort + Newline
            candidate_string = word + "\n"
            hash_password = hashlib.md5(candidate_string.encode('utf-8')).hexdigest()
            
            if hash_password == target_hash:
                print(f"\n!!! Password FOUND !!!")
                print(f"The word from rockyou.txt is: {word}")
                print(f"(This means the content of ROOTPASS was: {word}\\n)")
                password_found = True
                break # Schleife verlassen, da Passwort gefunden wurde
            
            # Fortschrittsanzeige (optional, aber hilfreich bei langen Listen)
            if line_number % 1000000 == 0: # Alle 1 Mio. Wörter
                print(f"Processed {line_number:,} words... Still searching.")

except FileNotFoundError:
    print(f"Error: Wordlist not found at {wordlist_path}")
    exit()

if not password_found:
    print(f"\nPassword for hash {target_hash} not found in {wordlist_path} with the 'word + newline' logic.")
