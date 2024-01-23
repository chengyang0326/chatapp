import tkinter as tk
import socket
import threading
import ssl
from ssl import PROTOCOL_TLS_SERVER

#creates tkinter window object
window = tk.Tk()
window.title("Server")


# gui styling
connect_win = tk.Frame(window)
start_button = tk.Button(connect_win, text="Connect", command=lambda : start_server())
start_button.pack(side=tk.LEFT)
stop_button = tk.Button(connect_win, text="Stop", command=lambda : stop_server(), state=tk.DISABLED)
stop_button.pack(side=tk.LEFT)
connect_win.pack(side=tk.TOP, pady=(5, 0))


info_frame = tk.Frame(window)
lblHost = tk.Label(info_frame, text = "Host: X.X.X.X")
lblHost.pack(side=tk.LEFT)
lblPort = tk.Label(info_frame, text = "Port:XXXX")
lblPort.pack(side=tk.LEFT)
info_frame.pack(side=tk.TOP, pady=(5, 0))




#define variable use for connection
server = None
HOST_ADDR = "127.0.0.1"
HOST_PORT = 5555
client_name = " "
clients = []
clients_names = []


server_cert = 'server.crt'
server_key = 'server.key'
client_certs = 'client.crt'



#create ssl content object
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
#The method load_cert_chain() loads an X.509 certificate and its private key into the SSLContext object
#The loaded certificate will be used during the SSL Handshake with the peer.
context.load_cert_chain(certfile=server_cert, keyfile=server_key)
#The method load_verify_locations() of the SSLContext class loads a set of CA certificates used for verifying the certificate of the peer.
context.load_verify_locations(cafile=client_certs)


# Start server function
def start_server():
    global server, HOST_ADDR, HOST_PORT # code is fine without this
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(socket.AF_INET)
    print(socket.SOCK_STREAM)

    server.bind((HOST_ADDR, HOST_PORT))
    server.listen(5)  # server is listening for client connection

    threading._start_new_thread(accept_clients, (server, " "))

    lblHost["text"] = "Host: " + HOST_ADDR
    lblPort["text"] = "Port: " + str(HOST_PORT)


# Stop server function
def stop_server():  
    global server
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

#use for connect server and client
def accept_clients(the_server, y):
    while True:
        client, addr = the_server.accept()
        conn = context.wrap_socket(client, server_side=True)
        print("SSL established. Peer: {}".format(conn.getpeercert()))
        clients.append(conn)
        # use a thread so as not to clog the gui thread
        threading._start_new_thread(send_receive_client_message, (conn, addr))


# Function to receive message from current client AND
# Send that message to other clients
def send_receive_client_message(client_connection, client_ip_addr):
    global server, client_name, clients, clients_addr
    client_msg = " "

    # send welcome message to client

    client_name  = client_connection.recv(4096).decode()
    if client_name=="admin":
        client_connection.send('enter the password:'.encode(('ascii')))
        password=client_connection.recv(1024).decode('ascii')

        if password!="adminpass":
            client_connection.send("REFUSE".encode('ascii'))
            client_connection.close()
    welcome=(f'{client_name} connected')
    for c in clients:
        if c!=client_connection:
            c.send(welcome.encode())
            
    welcome_msg = "Welcome " + client_name + ". Use 'exit' to quit, or !pm username to private message.\n"
    if client_name=="admin" and password=="adminpass":
        welcome_msg="Welcome Admin. Use 'exit' to quit, or !pm username to private message. use !kick username to kick"
    client_connection.send(welcome_msg.encode())
    print(f'name of the client is {client_name}')




    clients_names.append(client_name)
    
    client_msg="These are the available clients that are connected:"
    client_connection.send(client_msg.encode())
    for c in clients_names:
        client_connection.send(c.encode())

    # update client names display


    while True:
        data = client_connection.recv(4096).decode()
        if not data: break
        if data == "exit": break
        if data.startswith('KICK'):
            print(data)

            client_to_kick=data[5:]
            print(client_to_kick)
            index=0
            print(clients_names)
            for i in range(len(clients_names)):
                if client_name==client_to_kick:
                    index= i

            print(index)
            client_got_kick=clients.pop(index)
            print(clients)
            clients_names.remove(client_to_kick)
            if client_got_kick not in clients:
                client_got_kick.send("You were kicked by the admin".encode('ascii'))
                client_got_kick.close()

        if "!pm" in data:
            pm = data.split()
            for c in range(len(clients_names)):
                if str(clients_names[c]) in str(pm[1]):
                    client_msg = ''
                    i = 2
                    while i < (len(pm)):
                        client_msg = client_msg + " " + pm[i]
                        i = i + 1
                    idx = clients.index(client_connection)
                    sending_client_name = clients_names[idx]
                    server_msg = str(sending_client_name + "-> " + "you: " + client_msg)
                    clients[c].send(server_msg.encode())




        else:
            client_msg = data
            idx = clients.index(client_connection)
            sending_client_name = clients_names[idx]

            for c in clients:
                if c != client_connection:
                    server_msg = str(sending_client_name + "->" + client_msg)
                    c.send(server_msg.encode())

    # removes client from connection list after exit
    idx = clients.index(client_connection)
    print(f'{clients_names[idx]} disconnected')
    exit_msg=(f'{clients_names[idx]} disconnected')
    for c in clients:
        if c != client_connection:
            c.send(exit_msg.encode())
    
    del clients_names[idx]
    del clients[idx]
    client_connection.close()

#This function listens for events, such as button clicks or keypresses
window.mainloop()