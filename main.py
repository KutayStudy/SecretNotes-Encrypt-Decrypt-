import tkinter
from PIL import ImageTk, Image
from tkinter import messagebox
import base64

window = tkinter.Tk()
window.minsize(height=800,width=500)
window.title("                                                              Secret Notes")

FONT = ("Arial",16,"normal")

img = ImageTk.PhotoImage(Image.open("top-secret.png"))

my_photo = tkinter.Label(image= img,)
my_photo.place(x=148,y=30)

my_writing = tkinter.Label(text="Enter your title",font=FONT)
my_writing.place(x=179,y=130)

my_entry = tkinter.Entry(width=31)
my_entry.place(x=155,y=160)

my_writing2 = tkinter.Label(text="Enter your secret",font=FONT)
my_writing2.place(x=166,y=185)

my_text = tkinter.Text(width=40)
my_text.place(x=88,y=220)

my_writing3 = tkinter.Label(text="Enter master key",font=FONT)
my_writing3.place(x=167.5,y=620)

my_entry2 = tkinter.Entry(width=31)
my_entry2.place(x=155,y=650)

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
def Encrypt_button():
    title = my_entry.get()
    message = my_text.get("1.0",tkinter.END)
    master_secret = my_entry2.get()

    if my_entry.get() == "":
        messagebox.showwarning("Warning", "Enter your title")
    elif len(message) == 0:
        messagebox.showwarning("Warning", "Enter your secret")
    elif my_entry2.get() == "":
        messagebox.showwarning("Warning", "Enter your key")
    else:

        message_encrypted = encode(master_secret, message)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")

        finally:
            my_entry.delete(0,tkinter.END)
            my_entry2.delete(0,tkinter.END)
            my_text.delete("1.0",tkinter.END)



def Decrypt_button():

    message_encrypted = my_text.get("1.0",tkinter.END)
    master_secret = my_entry2.get()

    if my_text.get("1.0", tkinter.END) == "":
        messagebox.showwarning("Warning", "Enter your secret")
    elif my_entry2.get() == "":
        messagebox.showwarning("Warning", "Enter your key")
    else:
        decrypted_message = decode(master_secret, message_encrypted)
        my_text.delete("1.0",tkinter.END)
        my_text.insert("1.0",decrypted_message)

my_button = tkinter.Button(text="Save & Encrypt",command=Encrypt_button)
my_button.place(x=204.5,y=680)

my_button2 = tkinter.Button(text="Decrypt",command=Decrypt_button)
my_button2.place(x=224,y=730)




tkinter.mainloop()