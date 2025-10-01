import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
# import os 
# import os.path
from PIL import Image
import random
# import cv2

import hashlib
import pyaes


def hash_password(password, salt):
    password_hash = hashlib.sha512((password + salt).encode('utf-8')).hexdigest()
    return password_hash

def verify_password(stored_password, provided_password, salt):
    password_hash = hashlib.sha512((provided_password + salt).encode('utf-8')).hexdigest()
    print("Hashed Password:", password_hash)
    print("Password Matched",password_hash == stored_password)
    return password_hash

# AES & HASHING
def AES(user_password,provided_salt):
    # Hash the password
    hashed_password = hash_password(user_password, provided_salt)
    print("Hashed Password:", hashed_password)

    key = "THE_secret_KEY_is_SECRET_becaus!"
    plaintext =hashed_password

# key must be bytes, so we convert it
    key = key.encode('utf-8')

    aes = pyaes.AESModeOfOperationCTR(key)    
    ciphertext = aes.encrypt(plaintext)

# show the encrypted data
    print (ciphertext)

#decryption
    aes = pyaes.AESModeOfOperationCTR(key)

# decrypted data is always binary, need to decode to plaintext
    decrypted = aes.decrypt(ciphertext).decode('utf-8')


    print (decrypted == plaintext)

# Verify a password
    print("Decrypted_hash",decrypted)
    provided_password = input("Enter the password:")
    user_name=input("Enter the user name:")
#verfiy_hash=hash_password(provided_password,user_name)

    password_matched = verify_password(decrypted, provided_password, user_name)
#print("Password Matched:", password_matched)
#print("Hash Matched:",verfiy_hash)
    print("Hash Matched:",decrypted==password_matched)
# Encrypytion libs
def text_to_binary(input_file, output_file):
    with open(input_file, 'r') as file:
        text = file.read()

    binary = ''.join(format(ord(char), '08b') for char in text)

    with open(output_file, 'w') as file:
        file.write(binary)
        
def binary_to_ascii(input_file_path, output_file_path):
    try:
        with open(input_file_path, 'r') as input_file:
            binary_content = input_file.read().strip() 

            chunks = [binary_content[i:i+8] for i in range(0, len(binary_content), 8)]

            ascii_values = [int(chunk, 2) for chunk in chunks]


            with open(output_file_path, 'w') as output_file:
                for value in ascii_values:
                    output_file.write(f"{value}\n")


            print(f"ASCII values saved to {output_file_path}")
    except FileNotFoundError:
        print(f"Error: File '{input_file_path}' not found.")


#ascii to rgb
        

from PIL import Image
import random
# colors = [95,255,255]
# colors = bytes(colors)
# img = Image.frombytes('RGB', (1920, 1080), colors)
# img.show()
# img.save('D:\Pixel\.png')
def ascii_to_rgb(rgb_file,image_name):
    colors=[]


# file = open("D:\Pixel\Assets\output_ascii.txt")
# for i in file.read():
#     colors.append(i)
# close file
#file.close()

    with open(rgb_file, "r") as f:
        score = f.read() # Read all file in case values are not on a single line
        colors = [ int(x) for x in score.split() ] # Convert strings to ints
    
    num=len(colors)
    print(len(colors))
    for i in range(num,2138440*3,1):
        i=random.randint(0,255)
        colors.append(i)
    print(len(colors)/3)                              #2138440 1980x360  Dpi
    colors = bytes(colors)                          #2211840 2048x1080
    img = Image.frombytes('RGB', (1980,1080), colors)
    img.show()
    img.save(image_name)
    f.close()


# Decryption libs
def de_png_to_rgb(image_path, output_file):
    
    with open(output_file, 'w') as file:
        image = Image.open(image_path)
        width, height = image.size

        for y in range(height):
            for x in range(width):
                r, g, b = image.getpixel((x, y))
                # Print each value on a separate line with left alignment
                print(f"{r:<5}", file=file)
                print(f"{g:<5}", file=file)
                print(f"{b:<5}", file=file)

def format_binary(value):
    
    binary_str = bin(value)[2:]  # Remove "0b" prefix
    return binary_str.zfill(8)  # Pad with leading zeros
def rgb_binary_de(input_file, output_file):
    

    with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
        data_list = []
    
        # Read the first n lines
        for i in range(12):
            line = f_in.readline().strip()
            data_list.extend(line.split())

        # Group data into sets of 3
        for i in range(0, len(data_list), 3):
            try:
                
                r, g, b = map(int, data_list[i:i+3])
                binary_r = format_binary(r)
                binary_g = format_binary(g)
                binary_b = format_binary(b)
            
                output_line = f"{binary_r:<8}\n{binary_g:<8}\n{binary_b:<8}\n"
                f_out.write(output_line)
            except ValueError as e:
                print(f"Error on line {i+1}: Invalid data ({e}). Skipping entry.")

def join_lines_with_space(input_file, output_file):
    with open(input_file, 'r') as file:
        lines = file.readlines()

   
    joined_text = ' '.join([line.strip() for line in lines])

    with open(output_file, 'w') as file:
        file.write(joined_text)

def de_bin_to_text(input_file, output_file):
    with open(input_file, 'r',encoding="utf-8") as file:
        binary_str = file.read().replace(' ', '')  

  
    text = ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])

    with open(output_file, 'w',encoding="utf-8") as file:
        file.write(text)

def remove_last_letter(input_file, output_file):
    with open(input_file, 'r',encoding="utf-8") as file:
        content = file.read()

    updated_content = content[:-1]

    with open(output_file, 'w',encoding="utf-8") as file:
        file.write(updated_content)

   
# Encryption
def Encrypt(filepath):
    
    text_to_binary(filepath,'temp/bin_en.txt')
    binary_to_ascii("temp/bin_en.txt","temp/output_ascii_en.txt")
    img_name="Demo.png"
    ascii_to_rgb("temp/output_ascii_en.txt",img_name)


# Decryption
def Decrypt(filepath):
   
    de_png_to_rgb(filepath,"temp/output_acsii_de.txt")
    rgb_binary_de("temp/output_acsii_de.txt","temp/bin_de.txt")
    join_lines_with_space('temp/bin_de.txt','temp/sbin_de.txt')
    de_bin_to_text('temp/sbin_de.txt','temp/lbin_de.txt')
    output_txt_file='temp/output.txt'
    remove_last_letter('temp/lbin_de.txt',output_txt_file,)

# UI part
def UploadActionEn(event=None):
        filename1 = filedialog.askopenfilename()
        print('Selected:', filename1)
        Encrypt(filename1) 

def UploadActionDe(event=None):
        filename2 = filedialog.askopenfilename()
        print('Selected:', filename2) 
        Decrypt(filename2)

def Window1_en(event=None):
     
     root = tk.Tk()
     Window1(root).pack()
    #Window2(root).pack()
    #  Window3(Window1).pack()
     root.mainloop()
def Window2_de(event=None):
     
     root = tk.Tk()
     Window2(root).pack()
    #Window2(root).pack()
    #  Window3(Window1).pack()
     root.mainloop()
  
class Window1(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        self.button = tk.Button(self, text="Select the text", command=UploadActionEn)
        self.button.pack()
        # self.inputtxt = tk.Text(self, height = 5, width = 10) 
        # self.inputtxt.pack() 
        self.button = tk.Button(self, text="Back",command=self.open_next_window)
        self.button.pack()
    def open_next_window(self):
        self.master.destroy()


class Window2(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        self.button = tk.Button(self, text="Select the image", command=UploadActionDe)
        self.button.pack()
        self.button = tk.Button(self, text="Back",command=self.open_next_window)
        self.button.pack()
    def open_next_window(self):
        self.master.destroy()

   







def login ():
    global username,password
    username = entry_username.get()
    password = entry_password.get()

   # Dummy Login
    if username == "admin" and password == "admin":
       
        login_window.withdraw()

        
        new_window = tk.Toplevel()
        new_window.title("Welcome")
        label = tk.Label(new_window, text="Welcome, " + username + "!")
        label.pack(padx=20, pady=20)
        
        button_en = tk.Button(new_window, text="Encrypt", command=Window1_en)
        button_en.pack(padx=20, pady=10)
        button_de = tk.Button(new_window, text="Decrypt", command=Window2_de)
        button_de.pack(padx=20, pady=10)

        # Show the new window
        new_window.deiconify()
       
    else:
        messagebox.showerror("Error", "Invalid username or password")


login_window = tk.Tk()
login_window.title("Login Page")

label_username = tk.Label(login_window, text="Username:")
label_username.pack(padx=20, pady=10)
entry_username = tk.Entry(login_window)
entry_username.pack(padx=20, pady=5)


label_password = tk.Label(login_window, text="Password:")
label_password.pack(padx=20, pady=10)
entry_password = tk.Entry(login_window, show="*")
entry_password.pack(padx=20, pady=5)

button_login = tk.Button(login_window, text="Login", command=login)
button_login.pack(padx=20, pady=10)

login_window.mainloop()
