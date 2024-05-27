import tkinter as tk
from tkinter import ttk, messagebox
import string
import random
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

# Caesar Cipher hagar
def caesar_cipher(text, key, encrypt=True):
    try:
        shift = int(key) if encrypt else -int(key) 
    except ValueError:
        return "Invalid key: Key must be an integer"
    result = ""
    for char in text:    
        if char.isalpha():      #checks if alpha no matter lower or uppercase
            shift_base = 65 if char.isupper() else 97 #lao uppercase we change ascii value to 65 wich is A if lower, 97 is a
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base) #change to ascii value, nekhali el rarnge bta3 el ascii starts from zero 
        else:
            result += char
    return result

# Monoalphabetic Cipher hagar
def generate_keyword_cipher(keyword):
    keyword = keyword.upper()
    unique_letters = [] #empty list
    for letter in keyword:
        if letter not in unique_letters and letter.isalpha():
            unique_letters.append(letter) #only if it meets the criteria 
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    remaining_letters = [letter for letter in alphabet if letter not in unique_letters]
    keyword_cipher = unique_letters + remaining_letters
    return ''.join(keyword_cipher)

def monoalphabetic_cipher(text, key, encrypt=True):
    key_cipher = generate_keyword_cipher(key)
    text = text.upper()
    reversed_key_cipher = {v: k for k, v in zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", key_cipher)} if not encrypt else None 
    result_text = ""  # Initialize result_text here
    for char in text:
        if char.isalpha():
            index = ord(char) - ord('A')
            result_text += key_cipher[index] if encrypt else reversed_key_cipher[char]
        else:
            result_text += char
    return result_text


# Playfair Cipher saif
def key_gen(key):
    alpha = string.ascii_lowercase.replace("j", "i") #creates a string of alphabets while replacing j with i
    key_matrix = ['' for _ in range(5)] #creates a 5x5 matrix of empty strings
    seen = set() #keeps track of characters added to the matrix
    i = j = 0
    for char in key + alpha:#iterate through the key followed by the modified alphabet
        if char not in seen and char.isalpha(): #byshof el char fel matrix(seen) w alphabetic
            seen.add(char) #add character to the seen set
            key_matrix[i] += char # append character to the current row[i] of the matrix
            j += 1
            if j == 5: #if the current row is filled
                i += 1 #move to the next row
                j = 0 #reset the column index
    return [list(row) for row in key_matrix] #return the matrix as a list of lists

def find_position(letter, key_matrix):
    for row_idx, row in enumerate(key_matrix): #interate over key_matrix with index and current row
        if letter in row:
            return row_idx, row.index(letter)
    return None

def playfair_encrypt(plaintext, key_matrix):
    plaintext = plaintext.replace("j", "i")
    digraphs = [] #store pairs of characters
    i = 0
    while i < len(plaintext): #loop though plaintext
        a = plaintext[i] #assign current characters to a
        b = plaintext[i + 1] if i + 1 < len(plaintext) else 'x' #Assigns the next character to b, or 'x' if it doesn't exist.
        if a == b:
            b = 'x'
        digraphs.append(a + b)
        i += 2 if a != b else 1 #incriment the index by 2 lao zay b3d/ gheer kda by 1
    ciphertext = ""
    for digraph in digraphs:
        row1, col1 = find_position(digraph[0], key_matrix) #awel char
        row2, col2 = find_position(digraph[1], key_matrix) #tany char
        if row1 == row2:
            ciphertext += key_matrix[row1][(col1 + 1) % 5] + key_matrix[row2][(col2 + 1) % 5] #adds to the right of both
        elif col1 == col2:
            ciphertext += key_matrix[(row1 + 1) % 5][col1] + key_matrix[(row2 + 1) % 5][col2] #addsbelow both
        else:
            ciphertext += key_matrix[row1][col2] + key_matrix[row2][col1] #swap lao rect
    return ciphertext

def playfair_decrypt(ciphertext, key_matrix):
    digraphs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]# splits ciphertext into pairs of characters
    plaintext = ""
    for digraph in digraphs:
        row1, col1 = find_position(digraph[0], key_matrix)
        row2, col2 = find_position(digraph[1], key_matrix)
        if row1 == row2:
            plaintext += key_matrix[row1][(col1 - 1) % 5] + key_matrix[row2][(col2 - 1) % 5] #left
        elif col1 == col2:
            plaintext += key_matrix[(row1 - 1) % 5][col1] + key_matrix[(row2 - 1) % 5][col2] #above
        else:
            plaintext += key_matrix[row1][col2] + key_matrix[row2][col1]
    return plaintext

def playfair_cipher(text, key, encrypt=True):
    key_matrix = key_gen(key) 
    return playfair_encrypt(text, key_matrix) if encrypt else playfair_decrypt(text, key_matrix)

# Rail Fence Cipher rania
def rail_fence_encrypt(plaintext, key):
    key = int(key)  # The number of rails
    rail = [''] * key #itializes a list rail wl key hoa el number of empty strings, representing each rail.
    num = 0 #to keep track of the current rail
    direction = 1  # Start moving 'down' the rails

    plaintext = plaintext.replace(" ", "")

    for char in plaintext:
        rail[num] += char #hn7ot el char fel current rail
        num += direction #net7arak lel rail el ba3deeh

        if num == 0 or num == key - 1: #hnshoof e7na foo2 wla ta7t
            direction *= -1  # Change direction

    return ''.join(rail)

def rail_fence_decrypt(ciphertext, key):
    key = int(key)  # Number of rails
    length = len(ciphertext) #calc el length
    rails = [[] for _ in range(key)] #hn3ml list fadya le kol rail
    pattern = [None] * length #list nkeep track  of rail pattern lkol char fel cipher
    down = True
    row = 0
    for i in range(length):
        pattern[i] = row #record the current rail
        if row == key - 1: #btshoof lao e7na fel akher rail ta7t
            down = False #changes to up
        elif row == 0: # lao up
            down = True #changes to down
        row += 1 if down else -1 #Moves to the next rail based on the direction.

    index = 0
    for r in range(key): #each rail
        for i in range(length): #each index fel ciphertext
            if pattern[i] == r: #btshoof el character el fel position i lao belongs fel position r fel rail
                rails[r].append(ciphertext[index])
                index += 1

    result = []
    row = 0 #reset
    down = True
    for i in range(length):
        result.append(rails[row].pop(0)) #from rail to result
        if row == key - 1:
            down = False
        elif row == 0:
            down = True
        row += 1 if down else -1

    return ''.join(result)

# Row Transposition Cipher rania
def row_transposition_cipher(text, key, encrypt=True):
    key_len = len(key)
    sorted_key = sorted((char, idx) for idx, char in enumerate(key))  # Create a tuple of key and its index

    if encrypt:
        message = text.replace(" ", "")
        num_of_columns = len(key)
        num_of_rows = len(message) // num_of_columns
        if len(message) % num_of_columns != 0:
            num_of_rows += 1

        padding_length = num_of_rows * num_of_columns - len(message)
        message += 'X' * padding_length

        grid = [['' for _ in range(num_of_columns)] for _ in range(num_of_rows)]

        index = 0
        for row in range(num_of_rows):
            for col in range(num_of_columns):
                grid[row][col] = message[index]
                index += 1

        cipher_text = ""
        for num in key:
            col = int(num) - 1
            for row in range(num_of_rows):
                cipher_text += grid[row][col]

        return cipher_text
    else:
        cipher_text = text
        num_of_columns = len(key)
        num_of_rows = len(cipher_text) // num_of_columns

        grid = [['' for _ in range(num_of_columns)] for _ in range(num_of_rows)]

        index = 0
        for num in key:
            col = int(num) - 1
            for row in range(num_of_rows):
                grid[row][col] = cipher_text[index]
                index += 1

        plain_text = ""
        for row in range(num_of_rows):
            for col in range(num_of_columns):
                plain_text += grid[row][col]

        plain_text = plain_text.rstrip('X')

        return plain_text


# Polyalphabetic Cipher saif
def polyalphabetic_cipher(text, key, encrypt=True):
    try:
        shifts = [int(k) for k in key]
    except ValueError:
        return "Invalid key: Each character of the key must be an integer"

    # Initialize variables
    key_length = len(shifts)
    key_index = 0
    result = []

    for char in text:
        if char.isalpha():
            shift = shifts[key_index % key_length]
            if not encrypt:
                shift = -shift

            base = 97 if char.islower() else 65
            new_char = chr((ord(char) - base + shift) % 26 + base) #base converts back to original ascii range
            result.append(new_char)

            key_index += 1  # Increment key index only if the character is alphabetic
        else:
            result.append(char)

    return ''.join(result)



# Vigenère Cipher hagar
def vigenere_cipher(text, key, encrypt=True):
    # If decrypting, adjust the key for decryption by reversing the shifts
    if not encrypt:
        adjusted_key = ''
        for k in key:
            shift = (26 - (ord(k.lower()) - ord('a'))) % 26
            adjusted_key += chr(shift + ord('a'))
        key = adjusted_key

    cipher = ""
    index = 0

    for char in text:
        if char in string.ascii_letters:
            base = ord('a') if char.islower() else ord('A')
            offset = ord(key[index].lower()) - ord('a')
            cipher += chr((ord(char) - base + offset) % 26 + base) #hn3ml el shift wn7ot el result fel cipher
            index = (index + 1) % len(key) #update the index and wrap if needed
        else:
            cipher += char

    return cipher


# DES and AES Ciphers saif, rania
def des_cipher(text, key, encrypt=True):

    if len(key) != 16:
        raise ValueError("DES key must be 16 hexadecimal characters long.")
    
    key_bytes = bytes.fromhex(key) #Convert the key from a hexadecimal string to a byte array.

    cipher = DES.new(key_bytes, DES.MODE_ECB) #create an object bel key w use ecb for enc w dec
    
    if encrypt:
        padded_text = pad(bytes.fromhex(text), DES.block_size) #multiple of des block size
        encrypted_text = cipher.encrypt(padded_text) #encrypt
        return encrypted_text.hex().upper() #returns the text in hexa and uppercase
    else:
        # Decrypt and return the plaintext
        encrypted_text = bytes.fromhex(text)
        decrypted_text = unpad(cipher.decrypt(encrypted_text), DES.block_size)
        return decrypted_text.hex().upper()

def aes_cipher(text, key, encrypt=True):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    if encrypt:
        return cipher.encrypt(pad(text.encode(), AES.block_size)).hex()
    else:
        return unpad(cipher.decrypt(bytes.fromhex(text)), AES.block_size).decode()

# GUI application setup and logic
def process_text(encrypt=True):
    text = input_text.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    algorithm = algorithm_combobox.get()
    
    if not text or not key or not algorithm:
        messagebox.showerror("Error", "All fields must be filled out")
        return
    
    if algorithm in ['Caesar', 'Polyalphabetic', 'Rail Fence', 'Row Transposition'] and not key.isdigit():
        messagebox.showerror("Error", "Key must be a number for this algorithm")
        return

    if algorithm in ['DES', 'AES'] and len(key) not in [8, 16, 24, 32]:
        messagebox.showerror("Error", "Key length for DES must be 16 hexadecimal characters. For AES it must be 16, 24, or 32 characters.")
        return
    
    # Preprocess text to remove spaces if not using AES
    if algorithm != 'AES':
        text = text.replace(" ", "")

    try:
        cipher_methods = {
            'Caesar': caesar_cipher,
            'Monoalphabetic': monoalphabetic_cipher,
            'Playfair': playfair_cipher,
            'Polyalphabetic': polyalphabetic_cipher,
            'Vigenère': vigenere_cipher,
            'Row Transposition': row_transposition_cipher,
            'Rail Fence': lambda text, key, encrypt=encrypt: rail_fence_encrypt(text, key) if encrypt else rail_fence_decrypt(text, key),
            'DES': des_cipher,
            'AES': aes_cipher
        }
        result = cipher_methods[algorithm](text, key, encrypt)
        
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI components
root = tk.Tk()
root.geometry("800x600")
root.title("Encryption and Decryption Tool")

algorithm_label = tk.Label(root, text="Select Algorithm")
algorithm_label.pack(pady=5)
algorithm_combobox = ttk.Combobox(root, values=[
    "Caesar", "Monoalphabetic", "Playfair", "Polyalphabetic", "Vigenère",
    "Rail Fence", "Row Transposition", "DES", "AES"
])
algorithm_combobox.pack(pady=5)

input_label = tk.Label(root, text="Input Text")
input_label.pack(pady=5)
input_text = tk.Text(root, height=5, width=80)
input_text.pack(pady=5)

key_label = tk.Label(root, text="Key")
key_label.pack(pady=5)
key_entry = tk.Entry(root)
key_entry.pack(pady=5)

encrypt_button = tk.Button(root, text="Encrypt", command=lambda: process_text(encrypt=True))
encrypt_button.pack(pady=5)

decrypt_button = tk.Button(root, text="Decrypt", command=lambda: process_text(encrypt=False))
decrypt_button.pack(pady=5)

output_label = tk.Label(root, text="Output Text")
output_label.pack(pady=5)
output_text = tk.Text(root, height=5, width=80)
output_text.pack(pady=5)

root.mainloop()
