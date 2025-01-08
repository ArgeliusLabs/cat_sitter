import argparse
import datetime
import subprocess
import os
import time

# Dictionary of wordlists with their file paths
# These are common password lists used for dictionary attacks
WORDLISTS = {
    'target_custom': 'c:\\tools\\wordlists\\target_custom.txt',     # Organization-specific wordlist
    'rockyou': 'c:\\tools\\wordlists\\rockyou.txt',                # Famous leaked password list
    'have_i_been_pwned': 'c:\\tools\\wordlists\\hashes_dot_org_list.txt'  # Compilation of leaked passwords
}

# Dictionary of hashcat rules
# Rules modify words from wordlists (e.g., adding numbers, changing case)
# 'd3adhob0': '.\\rules\\d3adhob0.rule' # Another comprehensive rule set
RULES = {
    'best64': '.\\rules\\best64.rule',    # Popular transformations
    'd3ad0ne': '.\\rules\\d3ad0ne.rule'  # Comprehensive rule set
}

# Mask patterns for brute force attacks
# ?u = uppercase, ?l = lowercase, ?a = all characters
EIGHT_CHAR_MASKS = [
    '?u?l?l?l?l?l?a?a',  # Capital letter, 5 lowercase, 2 any chars
    '?u?l?l?l?l?a?a?a',  # Capital letter, 4 lowercase, 3 any chars
    '?a?a?a?a?a?a?a?a'   # 8 characters of any type
]

def run_hashcat(hash_format, hash_file, wordlist, rule=None, attack_mode='0'):
    """
    Execute hashcat with given parameters and handle errors.
    
    Args:
        hash_format (str): Hashcat mode number (e.g., 1000 for NTLM)
        hash_file (str): Path to file containing hashes to crack
        wordlist (str): Path to wordlist file
        rule (str, optional): Path to rules file
        attack_mode (str): Hashcat attack mode:
            '0' = Straight/Wordlist
            '1' = Combination
            '3' = Brute-force
    """
    if not os.path.exists(hash_file):
        print(f'[!] Hash file {hash_file} does not exist')
        return None
        
    if os.path.getsize(hash_file) == 0:
        print(f'[!] Hash file {hash_file} is empty')
        return None
    
    # Basic hashcat command with optimization (-O) and workload (-w3)
    cmd = ['hashcat.exe', '-O', '-w3', f'-a{attack_mode}', f'-m{hash_format}', hash_file]
    
    if wordlist:
        if attack_mode == '1' and ' ' in wordlist:
            # For combination attacks, split multiple wordlists into separate arguments
            cmd.extend(wordlist.split())
        else:
            cmd.append(wordlist)
    if rule:
        cmd.extend(['-r', rule])
    
    try:
        print(f'[*] Running: {" ".join(cmd)}')
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.abspath(__file__))  # Run from script directory
        )
        
        # Print hashcat's output for monitoring
        if result.stdout:
            print("[*] Output:")
            print(result.stdout)
        if result.stderr:
            print("[!] Error output:")
            print(result.stderr)
            
        result.check_returncode()
        print('[*] Completed successfully')
        return result
    except subprocess.CalledProcessError as e:
        print(f'[!] Hashcat exited with code {e.returncode}')
        if e.stdout:
            print("[*] Last output before error:")
            print(e.stdout)
        if e.stderr:
            print("[!] Error details:")
            print(e.stderr)
        return None

def try_wordlist_attack(hash_format, hash_file, wordlist, rule=None):
    """
    Run a wordlist attack with optional rules.
    
    Args:
        hash_format (str): Hashcat mode number
        hash_file (str): Path to hash file
        wordlist (str): Path to wordlist
        rule (str, optional): Path to rules file
    """
    description = f'Wordlist: {wordlist.split("\\")[-1]}'
    if rule:
        description += f' with {rule.split("\\")[-1]} rules'
    print(f'[*] Trying {description}')
    return run_hashcat(hash_format, hash_file, wordlist, rule)

def main():
    """
    Main function that orchestrates the password cracking attempts.
    
    Command line arguments:
        hash_file: Path to file containing hashes to crack
        hash_format: Hashcat mode number (e.g., 1000=NTLM, 5600=NTLMv2, 13100=Kerberos)
        --skip-wordlists: Skip dictionary-based attacks
        --skip-bruteforce: Skip brute force attacks
    
    Example usage:
        python cat_sitter.py ntlm_hashes.txt 1000
        python cat_sitter.py ntlm_hashes.txt 5600 --skip-bruteforce
    """
    parser = argparse.ArgumentParser(description='Advanced Password Cracking Script')
    parser.add_argument('hash_file', help='The file containing the hashes to crack')
    parser.add_argument('hash_format', help='Hash Format. NTLM:1000 NTLMv2:5600 Kerberos:13100')
    parser.add_argument('--skip-wordlists', action='store_true', help='Skip wordlist attacks')
    parser.add_argument('--skip-bruteforce', action='store_true', help='Skip brute force attacks')
    
    args = parser.parse_args()

    start_time = time.time()
    print(f'[*] Starting password cracking at {datetime.datetime.now()}')
    print(f'[*] Hash file: {args.hash_file}, Format: {args.hash_format}')

    if not args.skip_wordlists:
        # Try each wordlist
        for wordlist_name, wordlist_path in WORDLISTS.items():
            try_wordlist_attack(args.hash_format, args.hash_file, wordlist_path)
            
            # Apply rules to certain wordlists for more combinations
            if wordlist_name in ['rockyou', 'have_i_been_pwned']:
                for rule_name, rule_path in RULES.items():
                    try_wordlist_attack(args.hash_format, args.hash_file, wordlist_path, rule_path)

        # Try combination attacks (using words from rockyou against itself)
        print('[*] Running combination attacks...')
        run_hashcat(args.hash_format, args.hash_file, 
                   f'{WORDLISTS["rockyou"]} {WORDLISTS["rockyou"]}', 
                   attack_mode='1')

    if not args.skip_bruteforce:
        # Try brute force attacks with different patterns
        print('[*] Running brute force attacks...')
        for mask in EIGHT_CHAR_MASKS:
            run_hashcat(args.hash_format, args.hash_file, mask, attack_mode='3')

    # Show final results
    print('\n[*] Cracking completed. Found hashes:')
    cmd = ['hashcat.exe', '--show', f'-m{args.hash_format}', args.hash_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        else:
            print("No hashes were cracked")
    except subprocess.CalledProcessError as e:
        print(f'[!] Error showing results: {e}')

    elapsed_time = time.time() - start_time
    print(f'\n[*] Total execution time: {datetime.timedelta(seconds=int(elapsed_time))}')

if __name__ == '__main__':
    main() 
