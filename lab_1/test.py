import hashlib
from screeninfo import get_monitors
from itertools import cycle

def xor_cypher(input_data, key):
    return bytes([x ^ y for (x, y) in zip(input_data, cycle(key))])

def check_password(input_password, hashed_password):
    hashed_input = hashlib.sha256(input_password.encode()).hexdigest()
    return hashed_input == hashed_password

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as f:
        data = f.read()

    encrypted_data = xor_cypher(data, key)

    with open(file_name + '.enc', 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as f:
        data = f.read()

    decrypted_data = xor_cypher(data, key)

    with open(file_name[:-4], 'wb') as f:
        f.write(decrypted_data)


password_lab3 = None

def on_button_click(input_var, window):
    global password_lab3
    password_lab3 = input_var.get()

    if check_password(password_lab3, hashed_password):
        key = password_lab3.encode()
        decrypt_file('lab1.db.enc', key)
        os.remove('lab1.db.enc')
        msg.showinfo("Success", "File successfully decrypted!")
        window.destroy() 
    else:
        msg.showerror("Error", "Invalid password!")


ls = os.listdir()

if "lab1.db" in ls:
    np = input("Enter new password: ").encode()
    file = open("config.json", "w")
    file.write(json.dumps({"sha256":hashlib.sha256(np).hexdigest()}))
    file.close()
    encrypt_file("lab1.db",np)
    os.remove('lab1.db')

file = open("config.json")
hashed_password = json.loads(file.read())["sha256"]
file.close()

window = Tk()
window.title("File Decrypter")

input_var = StringVar()

Label(window, text="Password").grid(row=0, column=0)
Entry(window, textvariable=input_var, show='*').grid(row=0, column=1)
Button(window, text='Decrypt', command=lambda: on_button_click(input_var, window)).grid(row=1, column=0, columnspan=2)

window.mainloop()
  encrypt_file('lab1.db', password_lab3.encode())
    os.remove('lab1.db')