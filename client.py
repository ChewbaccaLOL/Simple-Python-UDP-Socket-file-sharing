from socket import *
from socket import error as error_1
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
from tkinter import messagebox
import os
import math
import threading
import time

bufferSize = 1024
peer_port = 8686
peer_host = gethostbyname(gethostname())
address = (peer_host, peer_port)
clients = []
clientItemList = []
itemList = []


# itemList = ['a1.txt', 'b2.jpg', 'c3.mpeg']


# def dscn():
#     try:
#         client_socket.sendto('Bye!'.encode('utf-8'), (host, port))
#         print('close - dscn')
#         client_socket.close()
#     except:
#         pass


def on_closing():
    disconnect_from_server()
    root.destroy()


def client_listener():
    global listenSocket
    global address
    global bufferSize
    global clients

    print(f'LISTEN SOCKET INFO:{address[0]}:{address[1]} ')

    while True:
        try:
            connectionSocket, addr = listenSocket.accept()
            data = connectionSocket.recv(bufferSize*4)

            fr = open(data.decode('utf-8'), 'rb')
            print('sending file...')
            l = fr.read(1024)
            while l:
                connectionSocket.send(l)
                l = fr.read(1024)
            fr.close()
            print('file sent!')
            connectionSocket.close()
        except error_1 as error:
            print(error)
            break


def disconnect_from_server():
    # print(clientSocket)
    try:
        tree.delete(*tree.get_children())
        clientItemList = []
        clientSocket = socket(AF_INET, SOCK_STREAM)
        clientSocket.connect((host, port))
        print('trying to disconnect')
        # clientSocket.connect((host, port))
        print('sending...')

        clientSocket.send(b'Bye!')
        time.sleep(0.025)
        clientSocket.send(peer_host.encode('utf-8'))
        time.sleep(0.025)
        clientSocket.send(str(peer_port).encode('utf-8'))

        print('sent!')
        global listenSocket
        # try:
        #     listenSocket.close()
        # except:
        #     pass
        try:
            clientSocket.close()
        except:
            pass

    except error_1 as error:
        print(str(error))
        try:
            clientSocket.close()
        except:
            pass
        # try:
        #     listenSocket.close()
        # except:
        #     pass
    except:
        print('error with connection before connection')


def connect_to_server():
    # print(clientSocket)
    global itemList
    global clientSocket
    global clientItemList
    global host
    global port
    message = b'Hi!'
    print("TCP Server IP address: ", host)
    print("TCP server port number: ", port)
    print('Message to be sent to server: ', message)
    clientSocket.connect((host, port))
    print('1')

    clientSocket.send(message)
    print('2')
    time.sleep(0.025)
    clientSocket.send(address[0].encode('utf-8'))
    clientSocket.recv(1024)
    clientSocket.send(str(address[1]).encode('utf-8'))
    print('sent client')
    clients = []
    clientItemList = []
    while True:
        recvMessage = clientSocket.recv(bufferSize)
        if recvMessage != 'Done!'.encode('utf-8'):
            print(recvMessage)
            clients.append([])
            clients[-1].append(recvMessage.decode())
            clientSocket.send(b' ')
            recvMessage = clientSocket.recv(bufferSize)
            clientSocket.send(b' ')
            print(recvMessage)
            clients[-1].append(recvMessage.decode())
        else:
            break
    print('sending items')
    for item1 in itemList:
        clientSocket.send(item1[0].encode('utf-8'))
        clientSocket.recv(1024)
        # time.sleep(0.025)
        clientSocket.send(str(item1[1]).encode('utf-8'))
        clientSocket.recv(1024)
        # time.sleep(0.025)
        clientSocket.send(item1[2].encode('utf-8'))
        clientSocket.recv(1024)

        # time.sleep(0.025)

    clientSocket.send('Done!'.encode('utf-8'))
    print('receiving items and clients')
    c = 1
    while True:
        recvMessage = clientSocket.recv(bufferSize)
        if recvMessage != b'Done!':
            if c == 1:
                addr01 = recvMessage.decode()
                clientSocket.send(b' ')

                recvMessage = clientSocket.recv(bufferSize)
                clientSocket.send(b' ')
                addr02 = recvMessage.decode()
                tpl1 = (addr01, addr02)
                clientItemList.append(tpl1)
                print(clientItemList)
                clientSocket.send(b' ')
                clientSocket.send(b' ')


                c = 0
            else:
                clientItemList.append([])
                while True:
                    if recvMessage != 'Items end'.encode('utf-8'):
                        filenamevar = recvMessage.decode()
                        print('sending after ', recvMessage)
                        clientSocket.send(b' ')
                        recvMessage = clientSocket.recv(bufferSize)
                        filesizevar = int(recvMessage.decode())
                        clientSocket.send(b' ')
                        recvMessage = clientSocket.recv(bufferSize)
                        filepathvar = recvMessage.decode()
                        item_tuple = (filenamevar, filesizevar, filepathvar)
                        clientItemList[-1].append(item_tuple)
                        clientSocket.send(b' ')
                        recvMessage = clientSocket.recv(bufferSize)


                    else:
                        break
                c = 1
        else:
            break
    # print(clientItemList)

    print('3')
    print(f"Message received from server: \n {clientItemList}\n")
    refresh_tree()
    # print(clientSocket)
    try:
        clientSocket.close()
    except:
        pass


def connection_func_btn():
    clientSocket = socket(AF_INET, SOCK_STREAM)
    listenSocket = socket(AF_INET, SOCK_STREAM)

    try:
        globals()['clientSocket'] = clientSocket
        connect_to_server()




    except error_1 as error:
        try:
            print('closing socket - error')
            # listenSocket.close()
            clientSocket.close()
        except:
            pass
    except KeyboardInterrupt:
        try:
            print('closing socket - kb hit')
            # listenSocket.close()
            clientSocket.close()
        except:
            pass
        print('Key pressed!')
    finally:
        print('connection alright!')
        print(clientSocket)


def con_btn_fnct():
    prcss_thread = threading.Thread(target=connection_func_btn)
    prcss_thread.start()


def check_fnct():
    global listenSocket
    print(listenSocket)
    global clientSocket
    print(clientSocket)


def refresh_tree():
    global tree
    global clientItemList
    tree.delete(*tree.get_children())
    for i in range(0, len(clientItemList), 2):
        print(i)
        id1 = tree.insert("", 'end', str(i), text='Client ' + str(int(i / 2)),
                          values=('', '', str(clientItemList[i][0]) + ':' + str(clientItemList[i][1])))
        # tree.item(str(i), open=tk.TRUE)
        for j in clientItemList[i + 1]:
            print(j)
            tree.insert(id1, "end", j[0] + str(i + 1), text='Item ' + str(int(i / 2) + 1),
                        values=(j[0], sizeof_fmt(j[1]), j[2]))
        print('inserted', i)


def add_item_local_tree():
    global tree_local
    global itemList
    tree_local.delete(*tree_local.get_children())
    for i in range(len(itemList)):
        print(i)
        tree_local.insert('', "end", itemList[i][0] + str(i), text='Item ' + str(i),
                          values=(itemList[i][0], sizeof_fmt(itemList[i][1]), itemList[i][2]))

        print('inserted', i)


def sizeof_fmt(num, suffix='B'):
    magnitude = int(math.floor(math.log(num, 1024)))
    val = num / math.pow(1024, magnitude)
    if magnitude > 7:
        return '{:.1f}{}{}'.format(val, 'Yi', suffix)
    return '{:3.1f}{}{}'.format(val, ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z'][magnitude], suffix)


def get_new_file():
    global root
    filepath = filedialog.askopenfilename()
    if filepath != '':
        sz = os.path.getsize(filepath)
        nm = os.path.basename(filepath)
        item_tuple = (nm, sz, filepath)
        if item_tuple not in itemList:
            itemList.append(item_tuple)
            disconnect_from_server()
            con_btn_fnct()
            add_item_local_tree()


def clear_refresh():
    itemList = []
    tree_local.delete(*tree_local.get_children())
    disconnect_from_server()
    con_btn_fnct()


def download_fnct():
    global tree
    curItem = tree.focus()
    parent_iid = tree.parent(curItem)
    if parent_iid:
        print(parent_iid)
        print(tree.item(parent_iid))
        print(tree.item(curItem))
        data = tree.item(curItem)
        filepath_dwnld = data['values'][2]
        filename_dwnld = data['values'][0]

        peer_address = tree.item(parent_iid)['values'][2].split(':')
        print(peer_address)
        print(filepath_dwnld)
        host_dnwnld = peer_address[0]
        port_dwnld = int(peer_address[1])

        dwnload_folder = filedialog.askdirectory()
        print(dwnload_folder)
        with socket(AF_INET, SOCK_STREAM) as downloadSocket:

            try:
                print('requesting...')
                downloadSocket.connect((host_dnwnld, port_dwnld))
                downloadSocket.send(filepath_dwnld.encode('utf-8'))
                fw = open(dwnload_folder + '/' + filename_dwnld, 'wb')
                l = downloadSocket.recv(1024)
                while l:
                    print('received few bites')
                    fw.write(l)
                    l = downloadSocket.recv(1024)
                fw.close()
                print('Received file!')
            except error_1 as error:
                print(error)
            except:
                pass
            finally:
                downloadSocket.close()



    else:
        messagebox.showinfo("Warning", 'Select item, not client!')


def main():
    # host = gethostbyname(gethostname())
    # port = 8888
    listenSocket = socket(AF_INET, SOCK_STREAM)
    listenSocket.bind(('', peer_port))
    listenSocket.listen(10)
    globals()['listenSocket'] = listenSocket

    listen_thread = threading.Thread(target=client_listener)
    listen_thread.daemon = True
    listen_thread.start()
    globals()['listen_thread'] = listen_thread

    root = tk.Tk()
    globals()['root'] = root
    root.title("P2P file sharing")
    root.geometry("1300x800-100-100")

    # IP selection
    IPlabel = tk.Label(text="Enter IP:", bg='#888')
    IPlabel.config(font=("Arial_helvetica 12"))
    IPlabel.place(x=50, y=50)

    IP_var = tk.StringVar()
    IP_var.set('192.168.1.106')

    IP_var_box = tk.Entry(textvariable=IP_var, font=("Arial_helvetica 12"), bg="#AAA")
    IP_var_box.place(x=120, y=50, width=108)

    # Port selection
    PortLabel = tk.Label(text="Port:", bg='#888')
    PortLabel.config(font=("Arial_helvetica 12"))
    PortLabel.place(x=240, y=50)

    Port_Var = tk.IntVar()
    Port_Var.set(8888)

    Port_Var_box = tk.Entry(textvariable=Port_Var, font=("Arial_helvetica 12"), bg="#AAA")
    Port_Var_box.place(x=280, y=50, width=40)

    # connection button
    globals()['host'] = IP_var.get()
    globals()['port'] = Port_Var.get()
    connect_btn = tk.Button(text="Connect to the server", background="#555", foreground="#ccc",
                            activebackground="#567",
                            padx="15", pady="6", font="15", command=lambda: con_btn_fnct())
    connect_btn.place(x=50, y=100, height=70, width=270, bordermode=tk.OUTSIDE)

    disconnect_btn = tk.Button(text="Disconnect", background="#555", foreground="#ccc",
                               activebackground="#567",
                               padx="15", pady="6", font="15", command=lambda: disconnect_from_server())
    disconnect_btn.place(x=50, y=190, height=30, width=270, bordermode=tk.OUTSIDE)

    get_file_btn = tk.Button(text="DOWNLOAD selected", background="#555", foreground="#ccd",
                             activebackground="#567",
                             padx="15", pady="6", font="15", command=lambda: download_fnct())
    get_file_btn.place(x=50, y=230, height=30, width=270, bordermode=tk.OUTSIDE)

    add_file_btn = tk.Button(text="Add file", background="#555", foreground="#ccc",
                             activebackground="#567",
                             padx="15", pady="6", font="15", command=lambda: get_new_file())
    add_file_btn.place(x=50, y=270, height=30, width=270, bordermode=tk.OUTSIDE)

    clear_list_btn = tk.Button(text="Clear file list and refresh", background="#555", foreground="#ccc",
                               activebackground="#567",
                               padx="15", pady="6", font="15", command=lambda: clear_refresh())
    clear_list_btn.place(x=50, y=310, height=30, width=270, bordermode=tk.OUTSIDE)

    check_btn = tk.Button(text="Check info", background="#555", foreground="#ccc",
                          activebackground="#567",
                          padx="15", pady="6", font="15", command=lambda: check_fnct())
    check_btn.place(x=50, y=450, height=30, width=270, bordermode=tk.OUTSIDE)

    tree = ttk.Treeview(root, selectmode='browse')
    globals()['tree'] = tree

    vsb = ttk.Scrollbar(root, orient='vertical', command=tree.yview)
    vsb.place(x=350 + 800 - 1, y=50 + 1, height=210 - 2)
    tree.configure(yscrollcommand=vsb.set)
    tree["columns"] = ("1", "2", "3")
    tree.column("1", width=200)
    tree.column("2", width=100)
    tree.column("3", width=300)
    tree.heading("1", text="File")
    tree.heading("2", text="Size")
    tree.heading("3", text="Path")
    tree.place(x=350, y=50, width=800, height=210)

    tree_local = ttk.Treeview(root, selectmode='browse')
    globals()['tree_local'] = tree_local

    vsb_local = ttk.Scrollbar(root, orient='vertical', command=tree_local.yview)
    vsb_local.place(x=350 + 800 - 1, y=270 + 1, height=210 - 2)
    tree_local.configure(yscrollcommand=vsb_local.set)
    tree_local["columns"] = ("1", "2", "3")
    tree_local.column("1", width=200)
    tree_local.column("2", width=100)
    tree_local.column("3", width=300)
    tree_local.heading("1", text="File")
    tree_local.heading("2", text="Size")
    tree_local.heading("3", text="Path")
    tree_local.place(x=350, y=270, width=800, height=210)

    root.resizable(width=False, height=False)

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.config(bg='#888')
    root.mainloop()


if __name__ == "__main__":
    main()

# host = gethostbyname(gethostname())
# port = 8888
#
# bufferSize = 1024
# message = b'Hi!'
#
# print("TCP Server IP address: ", host)
# print("TCP server port number: ", port)
# print('Message to be sent to server: ', message)
#
# clientSocket = socket(AF_INET, SOCK_STREAM)
# clientSocket.connect((host, port))
# clientSocket.send(message)
# recvMessage = clientSocket.recv(bufferSize)
# print("Message received from server: ", recvMessage)
