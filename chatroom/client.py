import tkinter as tk
from tkinter import messagebox
import socket
import threading
import ssl
#set up the gui
window = tk.Tk()
window.title("Client Window")
username = " "
#style the gui
top = tk.Frame(window)
name_label = tk.Label(top, text = "Enter your Name:", height=4).pack(side=tk.LEFT)
name_input = tk.Entry(top)
name_input.pack(side=tk.LEFT)
btnConnect = tk.Button(top, text="Connect", command=lambda : connect())
btnConnect.pack(side=tk.LEFT)

top.pack(side=tk.TOP)

display = tk.Frame(window)
lblLine = tk.Label(display, text="Chat Room").pack()
scrollBar = tk.Scrollbar(display)
scrollBar.pack(side=tk.RIGHT, fill=tk.Y)
display_text = tk.Text(display, height=30, width=55)
display_text.pack(side=tk.LEFT, fill=tk.Y, padx=(5, 0))
display_text.tag_config("tag_your_message", foreground="red")
scrollBar.config(command=display_text.yview)
display_text.config(yscrollcommand=scrollBar.set, background="green", highlightbackground="black", state="disabled")
display.pack(side=tk.TOP)



bottom = tk.Frame(window)
message_box = tk.Text(bottom, height=2, width=55)
message_box.pack(side=tk.LEFT, padx=(4, 15), pady=(5, 10))
message_box.config(highlightbackground="black", state="disabled")
message_box.bind("<Return>", (lambda event: get_message(message_box.get("1.0", tk.END))))
btnSend = tk.Button(bottom, text="Send", command=lambda: get_message(message_box.get("1.0", tk.END)))
btnSend.pack(side=tk.LEFT)
message_box.tag_config("tag_your_message", foreground="blue")
bottom.pack(side=tk.BOTTOM)

#ask for username, if user didn't input a user name, it will give an error
def connect():
    global username, client
    if len(name_input.get()) < 1:
        tk.messagebox.showerror(title="ERROR!!!", message="You MUST enter your first name <e.g. John>")
    else:
        username = name_input.get()
        connect_to_server(username)


# variable use for connection
client = None
HOST_ADDRESS = "127.0.0.1"
HOST_PORT = 5555
server_sni_hostname = 'example.com'
server_cert = 'server.crt'
client_cert = 'client.crt'
client_key = 'client.key'
#creates an ssl context object
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
#load_cert_chain() loads an X.509 certificate and its private key into the SSLContext object used for SSL handshake
context.load_cert_chain(certfile=client_cert, keyfile=client_key)
def connect_to_server(name):
    global client, HOST_PORT, HOST_ADDRESS
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client = context.wrap_socket(client, server_side=False, server_hostname=server_sni_hostname)
        client.connect((HOST_ADDRESS, HOST_PORT))
        client.send(name.encode()) # Send name to server after connecting

        name_input.config(state=tk.DISABLED)
        btnConnect.config(state=tk.DISABLED)
        message_box.config(state=tk.NORMAL)

        #threading allows for continuous message receipt
        threading._start_new_thread(receive_message_from_server, (client, "m"))
    except Exception as e:
        tk.messagebox.showerror(title="ERROR!!!", message="Cannot connect to host: " + HOST_ADDRESS + " on port: " + str(HOST_PORT) + " Server may be Unavailable. Try again later")

#function for getting server messages
def receive_message_from_server(sck, m):
    while True:
        from_server = sck.recv(4096).decode()
        if not from_server: break

        # display message from server on the chat window
        texts = display_text.get("1.0", tk.END).strip()
        display_text.config(state=tk.NORMAL)
        if len(texts) < 1:
            display_text.insert(tk.END, from_server)
        else:
            display_text.insert(tk.END, "\n"+ from_server)
        display_text.config(state=tk.DISABLED)
        display_text.see(tk.END)

    sck.close()
    window.destroy()

#display the message to the screen so that the user can see what they send and what other users send
def get_message(msg):

    msg = msg.replace('\n', '')
    if "!pm" in msg:
        pm = msg.split()
        i = 2
        client_msg = ''
        while i < (len(pm)):
            client_msg = client_msg + " " + pm[i]
            i = i + 1

        texts = display_text.get("1.0", tk.END).strip()
        display_text.config(state=tk.NORMAL)
        if len(texts) < 1:
            display_text.insert(tk.END, "You->" + pm[1] + ": " + client_msg, "tag_your_message")  # no line
        else:
            display_text.insert(tk.END, "\n" + "You->" + pm[1] + ": " + client_msg, "tag_your_message")

    else:
        texts = display_text.get("1.0", tk.END).strip()

        # enable the display area and insert the text and then disable.
        # why? Apparently, tkinter does not allow use insert into a disabled Text widget :(
        display_text.config(state=tk.NORMAL)
        if len(texts) < 1:
            display_text.insert(tk.END, "You->" + msg, "tag_your_message") # no line
        else:
            display_text.insert(tk.END, "\n" + "You->" + msg, "tag_your_message")

    display_text.config(state=tk.DISABLED)

    send_mssage_to_server(msg)

   

#send message to the server
def send_mssage_to_server(msg):
    client_msg = str(msg)
    display_text.see(tk.END)
    message_box.delete('1.0', tk.END)
    if client_msg.startswith('/'):
        if username=="admin":
            if client_msg.startswith('/kick'):
                client.send(f'KICK {client_msg[6:]}'.encode('ascii'))

        else:
            print('the command can only be execute by the admin')
    else:
        client.send(client_msg.encode())
    if msg == "exit":
        client.close()
        window.destroy()
    print("Sending message")
    print(client_msg)


#This function listens for events, such as button clicks or keypresses
window.mainloop()