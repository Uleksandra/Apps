import json
import os

class Data:
    def __init__(self):
        self.state = True
        # file_path = f"{os.path.dirname(os.path.abspath(__file__))}/data_user.json"
        if os.path.exists('data_user.json') == False:
            # self.state = False
         
            self.state = False
            self.data_user = {
                'ADMIN': {
                    'pwd': '',
                    'su': True,
                    'ban': False,
                    'restrictions': False
                }
            }


    def file_init(self):
        if self.state == True:
            with open(f"data_user.json", "r") as file:
                self.data_user = json.load(file)
            print("File exist")    
        else:    
            with open(f"data_user.json", "w") as createBase:
                json.dump(self.data_user, createBase)
            self.state = True
            print("Creating new file")

    def changePassword(self, username, newpassword):
        self.data_user[username]["pwd"] = newpassword
        with open(f"data_user.json", "w+") as w_base:
            json.dump(self.data_user, w_base)

    def AddUser(self, username):
        self.data_user[username] = {
                'pwd': '',
                'su': False,
                'ban': False,
                'restrictions': False
            }
        with open(f"data_user.json", "w+") as w_base:
            json.dump(self.data_user, w_base)
    
    def Add_Control(self, username):
        self.data_user[username]["restrictions"] = True
        with open(f"data_user.json", "w+") as w_base:
            json.dump(self.data_user, w_base)    

    def Re_Control(self, username):
        self.data_user[username]["restrictions"] = False
        with open(f"data_user.json", "w+") as w_base:
            json.dump(self.data_user, w_base)

    def BanUser(self,username):
        self.data_user[username]["ban"] = True
        with open(f"data_user.json", "w+") as w_base:
            json.dump(self.data_user, w_base)


    def UnbanUser(self, username):
        self.data_user[username]["ban"] = False
        with open(f"data_user.json", "w+") as w_base:
            json.dump(self.data_user, w_base)
