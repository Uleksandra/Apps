import tkinter
from tkinter import *
from tkinter import messagebox as msg
import customtkinter as ctk
import db
import os
import re
import win32api
import win32.lib.win32con as win32con
import platform
from tkinter import filedialog,messagebox
import winreg
import hashlib
import json
from itertools import cycle

def xor_cypher(input_data, key):
    return bytes([x ^ y for (x, y) in zip(input_data, cycle(key))])

def check_password(input_password, hashed_password):
    hashed_input = hashlib.md5(input_password.encode()).hexdigest()
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
        decrypt_file('data_user.json.enc', key)
        os.remove('data_user.json.enc')
        msg.showinfo("Success", "File successfully decrypted!")
        window.destroy() 
    else:
        msg.showerror("Error", "Invalid password!")



class Window_Log(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Window_Log")
        self.geometry('400x400')
        self.configure(fg_color='gray')
        self.resizable(False, False)
        self.count = 0
        frame = ctk.CTkFrame(master=self)
        frame.place(relx=0.5, rely=0.5, anchor='center')

        ctk.CTkLabel(master=frame, font=("Georgia", 18), text="Enter user name").grid(row=0, column=0, columnspan=2, pady=10)
        self.log_entry = ctk.CTkEntry(master=frame, width=250, height=30, font=("Georgia", 18))
        self.log_entry.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        ctk.CTkLabel(master=frame, font=("Georgia", 18), text="Enter password").grid(row=2, column=0, columnspan=2, pady=10)
        self.pwd_entry = ctk.CTkEntry(master=frame, width=250, height=30, font=("Georgia", 18), show='*')
        self.pwd_entry.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

        self.log_b = ctk.CTkButton(master=frame, font=("Georgia", 18), text="Sign in",text_color="gray", fg_color="palegreen", command=self.sing_in)
        self.log_b.grid(row=4, column=0, columnspan=2, pady=18)

        self.exit_b = ctk.CTkButton(master=frame, font=("Georgia", 18), text="Exit", text_color="gray", fg_color="palegreen", command=self.exit_command)
        self.exit_b.grid(row=5, column=0, columnspan=2, pady=10)

        self.info = ctk.CTkButton(master=frame, font=("Georgia", 18), text="Information", text_color="gray", fg_color="palegreen", command=self.info_command)
        self.info.grid(row=6, column=0, columnspan=2, pady=10)

    # Кнопка виходу
    def exit_command(self):
        self.destroy()
        return 0
    
    # Кнопка довідка
    def info_command(self):
        tkinter.messagebox.showinfo(title="Information", message=f"""
                                    Creator: 
        Muzychka-Skrypka Oleksandra FB-04, 
                                    Variant: 10
        The presence of ordinary and capital letters, as well as signs of 
        arithmetic operations.""")     

    # Кнопка авторизації
    def sing_in(self):
        login =  self.log_entry.get()
        passwd  = self.pwd_entry.get()
        
        if login != "":
            try:
                User = DataBase.data_user[login]
            except KeyError:
                tkinter.messagebox.showerror(title= "Error", icon="error", message=f"'{login}' don't registrated")
            else:
                if User != None and User['pwd'] != passwd:
                    if self.count == 2:
                        tkinter.messagebox.showwarning(title="Warning", icon="warning", message=f"Stupid hacker 💩")
                        self.exit_command()
                    else:
                        tkinter.messagebox.showwarning(title="Warning", icon="warning", message=f"Password is not correct")
                    self.count = self.count + 1
                elif User['ban'] == True:
                    tkinter.messagebox.showwarning(title="Warning", icon="warning", message=f"'{login}' was banned. What did you do?....")
                else:
                    self.exit_command()
                    CtrlPan = ControlPanel(login)
                    CtrlPan.mainloop()

        else:
            tkinter.messagebox.showerror(title="Error warning", icon="error", message=f"""
Enter login please, then click 'Sign in'""")  
class ControlPanel(ctk.CTk):
    def __init__(self, login):
        super().__init__()
        self.user = login
        self.title("Control")
        self.geometry('800x400')
        self.configure(fg_color='black')
        self.resizable(False, False)

        self.apply_butt = ctk.CTkButton(master=self, font = ("Georgia", 18), text = "Change password", text_color = "gray", fg_color = "palegreen", command = self.changeP)
        self.apply_butt.grid(row=0, column=0, padx=10, pady=10)

        self.logout_butt = ctk.CTkButton(master=self, font=("Georgia", 18), text="LOGOUT", text_color="gray", fg_color="lightcoral", command = self.log_out)
        self.logout_butt.grid(row=1, column=0, padx=10, pady=10)

        self.inf_butt = ctk.CTkButton(master=self, font=("Georgia", 18), text="Information", text_color="gray", fg_color="palegreen", command = self.info_command)
        self.inf_butt.grid(row=2, column=0, padx=10, pady=10)

        if self.user == "ADMIN":
            self.geometry('800x400')

            self.add_usr_butt = ctk.CTkButton(master = self, text = "Sing up new user", font = ("Georgia", 18), text_color = "gray", fg_color = "palegreen", command = self.add_usr)
            self.add_usr_butt.grid(row=0, column=1, padx=10, pady=10)

            self.new_user = ctk.CTkEntry(master = self)
            self.new_user.grid(row=0, column=2, padx=10, pady=10)

            self.add_contr = ctk.CTkButton(master = self, text = "Add password control", font = ("Georgia", 18), text_color = "gray", fg_color = "palegreen", command = self.add_pwd_control)
            self.add_contr.grid(row=1, column=1, padx=10, pady=10)

            self.re_contr = ctk.CTkButton(master=self, text="Remove password control", font=("Georgia", 18), text_color="gray", fg_color="palegreen", command = self.re_pwd_control)
            self.re_contr.grid(row=1, column=2, padx=10, pady=10)

            self.disable_butt = ctk.CTkButton(master=self, text="Ban user", font=("Georgia", 18), text_color="gray", fg_color="palegreen", command = self.Ban_User)
            self.disable_butt.grid(row=2, column=1, padx=10, pady=10)

            self.able_butt = ctk.CTkButton(master=self, text="Unban user", font=("Georgia", 18), text_color="gray", fg_color="palegreen", command = self.Unban_User)
            self.able_butt.grid(row=2, column=2, padx=10, pady=10)

            self.usersList = tkinter.Listbox(master=self, background="lightgray", selectmode="multiple")
            self.usersList.grid(row=3, column=0, columnspan=3, padx=60, pady=10, sticky="ew")
            self.Users_List()
    def changeP(self):
        CtrlPass = Change_PASS(self.user)
        CtrlPass.mainloop()

    def log_out(self):
        self.destroy()
        logWin = Window_Log()
        logWin.mainloop()

    # Кнопка довідка
    def info_command(self):
        tkinter.messagebox.showinfo(title="Information", message=f"""
                                    Creator: 
        Muzychka-Skrypka Oleksandra FB-04, 
                                    Variant: 10
        The presence of ordinary and capital letters, as well as signs of 
        arithmetic operations.""")     

    def add_usr(self):
        self.new_usr = self.new_user.get()
        if self.new_usr:
            if self.new_usr not in DataBase.data_user:
                DataBase.AddUser(self.new_usr)
            else: tkinter.messagebox.showinfo(title="Error", message="user already exists ")
        else: tkinter.messagebox.showinfo(title="Error", message="invalid username")
        self.Users_List()

    def Users_List(self):
        self.usersList.delete(0,END)
        for index,username in enumerate(DataBase.data_user):
            user = DataBase.data_user[username]
            self.usersList.insert(index,f"{username}    nocontrol "if DataBase.data_user[username]["restrictions"] == False else f"{username }    control")
            color = "violet" if DataBase.data_user[username]["ban"] == True else None
            self.usersList.itemconfig(index,bg=color)


    def add_pwd_control(self):
        for user in self.usersList.curselection():
            target = self.usersList.get(user).split()[0]
            DataBase.Add_Control(target)
        self.Users_List()


    def re_pwd_control(self):
        for user in self.usersList.curselection():
            target = self.usersList.get(user).split()[0]
            DataBase.Re_Control(target)
        self.Users_List()

    def Unban_User(self):
        for user in self.usersList.curselection():
            target = self.usersList.get(user).split()[0]
            DataBase.UnbanUser(target)
        self.Users_List()


    def Ban_User(self):
        for user in self.usersList.curselection():
            target = self.usersList.get(user).split()[0]
            DataBase.BanUser(target)
        self.Users_List()

class Change_PASS(ctk.CTk):
    def __init__(self, login):
        super().__init__()
        self.user = login
        self.title("Contol password")
        self.geometry('500x400')
        self.configure(fg_color='black')
        self.resizable(False, False)  
        
        ctk.CTkLabel(master=self, font=("Georgia", 18), text="Old Password").pack()
        self.old_pwd = ctk.CTkEntry(master=self, width=250)
        self.old_pwd.pack(ipadx=2, ipady=2)

        ctk.CTkLabel(master=self, font=("Georgia", 18), text="New Password").pack()
        self.new_pwd = ctk.CTkEntry(master=self, width=250)
        self.new_pwd.pack(ipadx=2, ipady=2)

        ctk.CTkLabel(master=self, font=("Georgia", 18), text="Confirm Password").pack()
        self.confirm_pwd = ctk.CTkEntry(master=self, width=250)
        self.confirm_pwd.pack(ipadx=2, ipady=2)

        self.apply_button = ctk.CTkButton(master=self, font=("Georgia", 18), text="Change", text_color="gray", fg_color="palegreen", command=self.password_dat)
        self.apply_button.pack(ipadx=2, ipady=2)
    def password_dat(self):
        self.oldpasswd =  self.old_pwd.get()
        self.newpasswd  = self.new_pwd.get()
        self.confirmpasswd = self.confirm_pwd.get()
        if self.newpasswd != self.confirmpasswd:
            tkinter.messagebox.showerror(title="Error", message=f"New Password and Confirm Password is diferent")
        else:
            
            if DataBase.data_user[self.user]["restrictions"] ==  True:
                rigthtih = self.passwordValidation(self.newpasswd)
                if rigthtih == True and self.oldpasswd != self.newpasswd and self.oldpasswd == DataBase.data_user[self.user]["pwd"]:
                    tkinter.messagebox.showinfo(title="Complete", message="Changed password successfully")
                    DataBase.changePassword(self.user, self.newpasswd)
                else:
                    tkinter.messagebox.showinfo(title="Error", message="new password is incorrect\n or simmilar with old password")
            else:
                if self.oldpasswd != self.newpasswd and self.oldpasswd == DataBase.data_user[self.user]["pwd"]:
                    tkinter.messagebox.showinfo(title="Complete", message="Changed password successfully")
                    self.destroy()
                    DataBase.changePassword(self.user, self.newpasswd)
                else: tkinter.messagebox.showerror(title="Error", icon="error", message="new password is incorrect\n or simmilar with old password")
            
    
    def passwordValidation(self, Password):
        mathCharacters = set('+-=/%')
        if re.search('[A-Z]',Password) is None:
            tkinter.messagebox.showerror(title="Error", icon="error", message="Your Password must have at least 1 uppercase letter.")
            return False
        elif re.search('[a-z]',Password) is None:
            tkinter.messagebox.showerror(title="Error", icon="error", message="Your Password must have at least 1 lowercase letter.")
            return False
        elif not mathCharacters.intersection(Password):
            tkinter.messagebox.showerror(title="Error", icon="error", message="Your Password must have at least 1 mathCharacters")
            return False
        else:
            return True
        
class HashCheck():
        def __init__(self):
            tkinter.messagebox.showinfo(title="Info", message="Wait a second/ We check your hash")
        def GetInfoUser(self):
            info_hash = {
                'username': win32api.GetUserName(),
                'computername': win32api.GetComputerName(),
                'windowsdir': win32api.GetWindowsDirectory(),
                'systemdir': win32api.GetSystemDirectory(),
                'mouse': win32api.GetSystemMetrics(win32con.SM_CMOUSEBUTTONS),
                # 'screen': win32api.GetSystemMetrics(win32con.SM_CXSCREEN),
                'disks': win32api.GetLogicalDriveStrings().split('\0'),
                # 'memory': win32api.GlobalMemoryStatusEx()[0]
            }
            return info_hash
        def getRegKey(self, sign):
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,"SOFTWARE\\MuzychkaSkrypka")
            value = winreg.QueryValueEx(key,sign)[0]
            return value
        def Hash_Check(self):
            info = self.GetInfoUser()
            print(info)
            json_info = json.dumps(info).encode('utf-8')
            hash_object = hashlib.md5(json_info)
            hash_now = hash_object.hexdigest()
            # hash_now = hashlib.md5(json.dumps(info).encode()).hexdigest()
            cool_hash = self.getRegKey("HashValue")
            print(hash_now)
            print(cool_hash)
            if hash_now == cool_hash:
                # print("kdsfukygfukygjJASKDJKSJKASDJKJDSJSDAK")
                return True
            else:
                return False 
hash_TF = HashCheck()

if hash_TF.Hash_Check():
    
    if not "data_user.json" in os.listdir() and not "data_user.json.enc" in os.listdir():
        DataBase = db.Data()
        DataBase.file_init()
        np = input("Enter new password: ").encode()
        file = open("config.json", "w")
        file.write(json.dumps({"md5":hashlib.md5(np).hexdigest()}))
        file.close()
        encrypt_file("data_user.json",np)
        os.remove('data_user.json')


    file = open("config.json")
    hashed_password = json.loads(file.read())["md5"]
    file.close()

    window = ctk.CTk()
    window.geometry('150x200')
    window.resizable(False, False)
    window.title("File Decrypter")

    input_var = StringVar()

    ctk.CTkLabel(window, text="Password", font = ("Georgia", 18), text_color="gray", fg_color="palegreen").grid(row=0, column=1, padx=10, pady=10)
    ctk.CTkEntry(window, textvariable=input_var, show='*').grid(row=1, column=1, padx=10, pady=10)
    ctk.CTkButton(window, text='Decrypt', font = ("Georgia", 18), text_color="gray", fg_color="palegreen", command=lambda: on_button_click(input_var, window)).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    window.protocol("WM_DELETE_WINDOW", exit)
    window.mainloop()
    DataBase = db.Data()
    DataBase.file_init()


    logWin = Window_Log()
    logWin.mainloop()
    encrypt_file('data_user.json', password_lab3.encode())
    os.remove('data_user.json')

else:
  tkinter.messagebox.showinfo(title="Error", message="Your hash is incorrect")

