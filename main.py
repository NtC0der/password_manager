
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk
from tkinter import PhotoImage

from PIL import Image, ImageTk  # Import Image and ImageTk from PIL library
import os

class PasswordManager:

    def __init__(self) :
        self.key = None
        self.password_file = None
        self.password_dict  = {}

    def key_generate(self, path): # path is to store the key
        self.key = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(self.key)

        return self.key # returning the key so that it is displayed

    def load_key(self, path):
        with open(path, 'rb') as f:
            self.key = f.read()

    def create_password_file(self, path, initial_values=None):
        self.password_file = path

        if initial_values is not None:
            for key, value in initial_values.items(): 
                self.add_password(key, value)
                
    def load_pasword_file(self, path):
        self.password_file = path

        with open(path, "r") as f:
            for line in f:
                site, user, encrypted_password = line.strip().split("|")
                decrypted_password = Fernet(self.key).decrypt(encrypted_password.encode()).decode()
                self.password_dict[site] = [user, decrypted_password]

    def add_password(self, site, user, password):
        self.password_dict[site] = [user, password]

        sorted_dict = {k: self.password_dict[k] for k in sorted(self.password_dict)} # sotrting the passwords alphabetically based on site name
        self.password_dict = sorted_dict

        if self.password_file is not None:
            with open(self.password_file, 'w') as f:  # Open file in write mode to overwrite existing content
                for site_name in self.password_dict.keys():                    
                    user, password = self.password_dict[site_name]
                    encrypted_password = Fernet(self.key).encrypt(password.encode()).decode()
                    f.write(f"{site_name}|{user}|{encrypted_password}\n")

    def remove_password(self, site):

        self.password_dict.pop(site)

        with open(self.password_file, 'w') as f:  # Open file in write mode to overwrite existing content
                for site_name in self.password_dict.keys():                    
                    user, password = self.password_dict[site_name]
                    encrypted_password = Fernet(self.key).encrypt(password.encode()).decode()
                    f.write(f"{site_name}|{user}|{encrypted_password}\n")
    
    def get_password(self, site):
        if site in self.password_dict:
            return self.password_dict[site][1]  # Returning the password
        else:
            return None

class ScrollableFrame(tk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self, bg="#121212", width=400)
        self.scrollbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="black")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Makes the scrollable frame take the size of the canvas
        self.canvas.bind("<Configure>", self.on_canvas_configure)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.pack(side="top", fill="both", expand=True)

    def on_canvas_configure(self, event): #making the scroll frame full sized

        canvas_width = event.width
        self.canvas.itemconfig(self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw"), width=(canvas_width - 5))

def check_file_exists(file_name):
    script_dir = os.path.dirname(__file__)  # Get the directory of the script
    file_path = os.path.join(script_dir, file_name)

    if os.path.exists(file_path):
        return [True, file_path]
    else:
        return [None, file_path]

def create_info_enter_window(pm):

    def error_info():
        title_label.configure(text="Please fill out all your info...")

        confirm_button.configure(bg="#A80000")
        root.after(500, lambda: confirm_button.configure(bg="#12520b"))

    def return_home():
        root.destroy()
        create_homepage_window(pm)

    def store_info():

        site = site_enter.get()
        user = user_enter.get()
        password = password_enter.get().strip()

        if site.strip() and user.strip() and password: # checking if the user has entered the info
        
            pm.add_password(site, user, password)
            return_home()
        else:
            error_info()
 
    root = tk.Tk()

    root.geometry("400x400")
    root.title("NT password manager")
    root.config(bg="black")

    root.resizable(False, False) #makes it not resizable

    # Set background image
    image_path = os.path.join(os.path.join(os.path.dirname(__file__), "assets"), "background.jpg")    
    img = Image.open(image_path)
    img = img.resize((400, 400), Image.LANCZOS)  # Resize image to fit window

    background_image = ImageTk.PhotoImage(img)
    background_label = tk.Label(root, image=background_image)
    background_label.img = background_image
    background_label.place(relx=0.5, rely=0.5, anchor='center', relwidth=1, relheight=1)  

    title_label = tk.Label(root, text="Please enter your info below...", font=('Arial', 18), bg="black", fg="white")
    title_label.pack(pady=10)
    
    main_frame = tk.Frame(root, bg="black")
    main_frame.pack(expand=True)

    #---------------Site info-----------------#
    site_frame = tk.Frame(main_frame, bg="black")
    site_frame.pack(pady=10)

    site_label = tk.Label(site_frame, text="Site name:", font=('Arial', 18), bg="black", fg="white")
    site_label.pack()

    site_enter = tk.Entry(site_frame, font=('Arial', 18), bg="black", fg="white", justify='center')
    site_enter.pack()

    #---------------User info-----------------#
    user_frame = tk.Frame(main_frame, bg="black")
    user_frame.pack(pady=10)

    user_label = tk.Label(user_frame, text="User name:", font=('Arial', 18), bg="black", fg="white")
    user_label.pack()

    user_enter = tk.Entry(user_frame, font=('Arial', 18), bg="black", fg="white", justify='center')
    user_enter.pack()

    #---------------Password info-----------------#
    password_frame = tk.Frame(main_frame, bg="black")
    password_frame.pack(pady=10)

    password_label = tk.Label(password_frame, text="Password:", font=('Arial', 18), bg="black", fg="white")
    password_label.pack()

    password_enter = tk.Entry(password_frame, font=('Arial', 18), bg="black", fg="white", justify='center')
    password_enter.pack()

    #------------------Buttons-------------------#
    buttons_frame = tk.Frame(main_frame, bg="black")
    buttons_frame.pack()

    cancel_button = tk.Button(buttons_frame, text="Cancel", font=('Arial', 18), bg="#52100b", fg="white", command=return_home)
    cancel_button.pack(side=tk.LEFT)

    confirm_button = tk.Button(buttons_frame, text="Confirm", font=('Arial', 18), bg="#12520b", fg="white", command=store_info)
    confirm_button.pack(side=tk.LEFT, padx=5)

    root.mainloop()

def create_delete_window(pm, site_name): # Runs when the delete button is pressed
    
    def exit_window():
        root.destroy()
        create_homepage_window(pm)

    def delete_info(site_name): # Runs when the Yes button is pressed
        pm.remove_password(site_name)
        exit_window()

    root = tk.Tk()

    root.geometry("400x400")
    root.title("NT password manager")
    root.config(bg="black")

    # Sets background image
    image_path = os.path.join(os.path.join(os.path.dirname(__file__), "assets"), "background.jpg")                      
    img = Image.open(image_path)
    img = img.resize((400, 400), Image.LANCZOS)  # Resizes image to fit window
    background_image = ImageTk.PhotoImage(img)
    background_label = tk.Label(root, image=background_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    confirm_label = tk.Label(root, text=f'Are you sure you want to delete the password for the site {site_name}?', font=('Arial', 18), bg="black", fg="white", wraplength=300)
    confirm_label.pack(pady=80)

    buttons_frame = tk.Frame(root, bg="black")
    buttons_frame.pack(pady=20)

    confirm_button = tk.Button(buttons_frame, text="Yes", font=('Arial', 18), bg="#1b5e07", fg="black", command=lambda: delete_info(site_name))
    confirm_button.pack(side=tk.LEFT, padx=10)

    decline_button = tk.Button(buttons_frame, text="No", font=('Arial', 18), bg="#8f140b", fg="black", command=exit_window)
    decline_button.pack(side=tk.LEFT, padx=10)

    root.resizable(False, False) #makes it not resizable

    root.mainloop()

def create_homepage_window(pm):

    def delete_info(site_name):
        root.destroy()
        create_delete_window(pm, site_name)

    def copy_password(password):
        root.clipboard_clear()
        root.clipboard_append(password) #copies password to clipboard

    def create_data_columns():     
        headers = ["Site Name", "Username", "Password"]

        grid_frame = tk.Frame(data_frame.scrollable_frame)
        grid_frame.pack(expand=True, fill="both", padx=20, pady=20)  # Center the grid_frame within the scrollable_frame

        # Create a label with the image as background
        background_label = tk.Label(grid_frame, image=background_image)
        background_label.place(relwidth=1, relheight=1)  # Fill the grid_frame

        background_label.image = background_image # preventing garbage collect

        # Create header labels
        for col, header in enumerate(headers):
            header_label = tk.Label(grid_frame, text=header, font=('Arial', 18, 'bold'), bg="black", fg="white")
            header_label.grid(row=0, column=col, padx=10, pady=5, sticky="ew")

        # Iterates through the password dictionary and create labels for each entry
        for row, (site_name, user_info) in enumerate(pm.password_dict.items(), start=1):
            username = user_info[0]
            password = user_info[1]

            site_name_label = tk.Label(grid_frame, text=site_name, font=('Arial', 18), bg="black", fg="white")
            site_name_label.grid(row=row, column=0, padx=10, pady=5, sticky="ew")

            username_label = tk.Label(grid_frame, text=username, font=('Arial', 18), bg="black", fg="white")
            username_label.grid(row=row, column=1, padx=10, pady=5, sticky="ew")

            password_label = tk.Label(grid_frame, text=password, font=('Arial', 18), bg="black", fg="white")
            password_label.grid(row=row, column=2, padx=10, pady=5, sticky="ew")

            #----------for delete png---------------
            image_path_del = os.path.join(os.path.join(os.path.dirname(__file__), "assets"), "delete.png") 
            image_del= Image.open(image_path_del)
            image_del = image_del.resize((30, 30), Image.LANCZOS)  # Adjusts size as needed
            image_del_with_alpha = ImageTk.PhotoImage(image_del) # Ensures the image has an alpha channel for transparency

            #----------for copy png-----------------
            image_path_copy = os.path.join(os.path.join(os.path.dirname(__file__), "assets"), "copy.png") 
            image_copy= Image.open(image_path_copy)
            image_copy = image_copy.resize((30, 30), Image.LANCZOS)  # Adjusts size as needed
            image_copy_with_alpha = ImageTk.PhotoImage(image_copy) # Ensures the image has an alpha channel for transparency

            copy_button = tk.Button(grid_frame, image=image_copy_with_alpha, bg="black", width=30, height=30, bd=0, highlightthickness=0, relief=tk.FLAT, command=lambda password=password: copy_password(password))
            copy_button.img = image_copy_with_alpha
            copy_button.grid(row=row, column=3, padx=5, pady=5)

            delete_button = tk.Button(grid_frame, image=image_del_with_alpha, bg="black", width=30, height=30, bd=0, highlightthickness=0, relief=tk.FLAT, command=lambda site_name=site_name: delete_info(site_name)) #lamba allows us to place params
            delete_button.img = image_del_with_alpha
            delete_button.grid(row=row, column=4, padx=5, pady=5)

        # Ensure columns expand evenly
        for col in range(len(headers)):
            grid_frame.grid_columnconfigure(col, weight=1)

    def add_info(): #creates info add window

        root.destroy()
        create_info_enter_window(pm)

    pass_fileName = "passwords"
    pass_path = check_file_exists(pass_fileName)

    if pass_path[0] is not None: #checking if the password file exists, if not then we create it
        pm.load_pasword_file(pass_path[1])
    else:
        pm.create_password_file(pass_path[1])

    root = tk.Tk()

    root.geometry("800x500")
    root.title("NT password manager")
    root.config(bg="black")

    # Sets background image
    image_path = os.path.join(os.path.join(os.path.dirname(__file__), "assets"), "background.jpg")                      
    img = Image.open(image_path)
    img = img.resize((800, 500), Image.LANCZOS)  # Resize image to fit window
    background_image = ImageTk.PhotoImage(img)
    background_label = tk.Label(root, image=background_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    title_frame = tk.Frame(root, bg="black")
    title_frame.pack(pady=10)

    title_label = tk.Label(title_frame, text="Passwords", font=('Arial', 30), bg="black", fg="white")
    title_label.pack(side=tk.LEFT)

    image_path_check = os.path.join(os.path.join(os.path.dirname(__file__), "assets"), "check.png") 

    image_check = Image.open(image_path_check)
    image_check = image_check.resize((30, 30), Image.LANCZOS)  # Adjusts size as needed

    image_with_alpha = ImageTk.PhotoImage(image_check) # Ensures the image has an alpha channel for transparency

    addInfo_button = tk.Button(title_frame, image=image_with_alpha, bg="black", bd=0, highlightthickness=0, relief=tk.FLAT, command=add_info)
    addInfo_button.pack(side=tk.LEFT, padx=5)

    data_frame = ScrollableFrame(root)
    data_frame.pack(fill="both", expand=True)
    
    create_data_columns()

    root.resizable(False, False) #makes it not resizable

    root.mainloop()

def create_passwordEnter_window(pm, keys_path):

    def wrongKey():
        enter.configure(text="Incorrect")

        enter.configure(bg="#A80000")
        root.after(800, lambda: enter.configure(bg="#0b520b", text="Verify"))

    def verifyPressed(): 

        user_input = textbox.get()
        if user_input.encode('utf-8') == pm.key: #checking if the user has entered the correct passcode

            root.destroy() 
            create_homepage_window(pm)
        else:
            wrongKey()

    pm.load_key(keys_path) #loads the key

    root = tk.Tk()

    root.geometry("800x500")
    root.title("NT password manager")
    root.config(bg="black")

    # Sets background image
    image_path = os.path.join(os.path.join(os.path.dirname(__file__), "assets"), "background.jpg")                      
    img = Image.open(image_path)
    img = img.resize((800, 500), Image.LANCZOS)  # Resize image to fit window
    background_image = ImageTk.PhotoImage(img)
    background_label = tk.Label(root, image=background_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    root.resizable(False, False) #makes it not resizable

    # Creates a frame to center the widgets
    frame = tk.Frame(root, bg="black")
    frame.pack(expand=True)

    label = tk.Label(frame, text="Please enter your master key right below...", font=('Arial', 18), bg="black", fg="white")
    label.pack()

    textbox = tk.Entry(frame, width=60, font=('Arial', 16), justify='center')
    textbox.pack(pady=10)

    enter = tk.Button(frame, text="Verify", width=15, bg="#0b520b", font=('Arial', 16), command=verifyPressed)
    enter.pack()

    root.mainloop()

def create_passwordGenerate_window(pm):
    
    script_dir = os.path.dirname(__file__)  # Get the directory of the script
    keys_path = os.path.join(script_dir, "mykeys.key")

    pm.create_password_file(keys_path, initial_values=None)

    def generate_pressed():
        key = pm.key_generate(keys_path)

        if isinstance(key, bytes): 
            key = key.decode('utf-8')  # Decode bytes to string if necessary
        
        label.config(text=f'Your new master_key is: \n{key}')
        copy_button.config(state=tk.NORMAL)  # Enables the copy button after generating the key

    def copy_pressed():
        key_text = pm.key
        root.clipboard_clear()
        root.clipboard_append(key_text) #copies key
        login_button.pack() # log in button visible
        login_button.place(x=375, y=400)  # log in button visible at a fixed position

    def login_pressed(): #closes window and opens login window
        root.destroy() 
        create_passwordEnter_window(pm, keys_path)

    root = tk.Tk()

    root.geometry("800x500")
    root.title("NT password manager")
    root.config(bg="black")

    # Set background image
    image_path = os.path.join(os.path.join(os.path.dirname(__file__), "assets"), "background.jpg")                      
    img = Image.open(image_path)
    img = img.resize((800, 500), Image.LANCZOS)  # Resize image to fit window
    background_image = ImageTk.PhotoImage(img)
    background_label = tk.Label(root, image=background_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    root.resizable(False, False) #makes it not resizable
    
    frame = tk.Frame(root, bg="black")
    frame.pack(expand=True)

    label = tk.Label(frame, text="Please generate a master key", font=('Arial', 18), bg="black", fg="white")
    label.pack(pady=10)

    button_frame = tk.Frame(frame, bg="black")
    button_frame.pack(pady=10)

    generate_button = tk.Button(button_frame, text="generate", font=('Arial', 14), command=generate_pressed)
    generate_button.pack(side=tk.LEFT, padx=10)

    copy_button = tk.Button(button_frame, text="copy", font=('Arial', 14), command=copy_pressed, state=tk.DISABLED)
    copy_button.pack(side=tk.LEFT, padx=10)

    login_button = tk.Button(root, text="Log in", font=('Arial', 14), command=login_pressed)

    root.mainloop()

def main():

    pm = PasswordManager()
    keys_path = check_file_exists("mykeys.key")

    if keys_path[0] is not None and keys_path[1] is not None: #checking if the password key file exists
        create_passwordEnter_window(pm, keys_path[1])
    else:
        create_passwordGenerate_window(pm)

if __name__ == "__main__":
    main()