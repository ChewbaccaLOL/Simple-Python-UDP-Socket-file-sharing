from socket import *
import time

host = gethostbyname(gethostname())
listen_port = 8888

clients = []
bufferSize = 2048
itemList = [('111.168.1.106', '1111'), [('11.txt', 111, 'dummypath1'), ('11.jpg', 111111, 'dummypath11'), ('11.mpeg', 11111111, 'dummypath111')],
            ('222.168.1.106', '2222'), [('22.txt', 222, 'dummypath2'), ('22.jpg', 222222, 'dummypath22'), ('22.mpeg', 22222222, 'dummypath222')],
            ('333.168.1.106', '3333'), [('33.txt', 333, 'dummypath3'), ('33.jpg', 333333, 'dummypath33'), ('33.mpeg', 33333333, 'dummypath333')],
            ('444.168.1.106', '4444'), [('44.txt', 444, 'dummypath4'), ('44.jpg', 444444, 'dummypath44'), ('44.mpeg', 44444444, 'dummypath444')],
            ('555.168.1.106', '5555'), [('55.txt', 555, 'dummypath5'), ('55.jpg', 555555, 'dummypath55'), ('55.mpeg', 55555555, 'dummypath555')],
            ('666.168.1.106', '6666'), [('66.txt', 666, 'dummypath6'), ('66.jpg', 666666, 'dummypath66'), ('66.mpeg', 66666666, 'dummypath666')]]


def client_listener():
    while True:

        buffer = 2048
        data, address = listenSocket.recvfrom(buffer)
        if address not in clients and data == 'Hi!'.encode('utf-8'):
            print(f'New client: {address[0]}:{address[1]}')
            clients.append(address)
            print('Active clients: ', clients)
        elif data == 'Bye!'.encode('utf-8'):
            print(f'This client hsa quitted: {address[0]}:{address[1]}')
            clients.remove(address)
            print('Active clients: ', clients)


with socket(AF_INET, SOCK_STREAM) as listenSocket:
    try:
        listenSocket.bind(('', listen_port))
        print(f'Server hosted at {host}:{listen_port}\n')
        listenSocket.listen(10)
        print('The server is ready to receive')
        while True:

            connectionSocket, addr = listenSocket.accept()
            data = connectionSocket.recv(bufferSize)
            print(data)
            time.sleep(0.025)
            if data == 'Hi!'.encode('utf-8'):
                print('trying to receive data')
                # addr_rec = [connectionSocket.recv(bufferSize), connectionSocket.recv(bufferSize)]
                addr1 = connectionSocket.recv(bufferSize).decode()
                print('received 1st part', addr1)
                connectionSocket.send(b' ')
                addr2 = connectionSocket.recv(bufferSize).decode()
                addr_rec_tuple = (addr1, addr2)
                print(addr_rec_tuple)
                if addr_rec_tuple not in clients:
                    print(f'New client: {addr_rec_tuple[0]}:{addr_rec_tuple[1]}')
                    clients.append(addr_rec_tuple)
                    print('Active clients: ', clients)
                    for cl in clients:
                        print('sending', cl, '...')
                        connectionSocket.send(cl[0].encode('utf-8'))
                        connectionSocket.recv(1024)
                        time.sleep(0.025)
                        connectionSocket.send(str(cl[1]).encode('utf-8'))
                        connectionSocket.recv(1024)
                    time.sleep(0.025)
                    connectionSocket.send(b'Done!')
                    print('accepting item list on', addr_rec_tuple)
                    itemList.append(addr_rec_tuple)
                    itemList.append([])
                    while True:
                        recvMessage = connectionSocket.recv(bufferSize)
                        if recvMessage != b'Done!':
                            itnm = recvMessage.decode()
                            connectionSocket.send(b' ')
                            recvMessage = connectionSocket.recv(bufferSize)
                            itsz = int(recvMessage.decode())
                            connectionSocket.send(b' ')
                            recvMessage = connectionSocket.recv(bufferSize * 4)
                            connectionSocket.send(b' ')
                            itpth = recvMessage.decode()
                            item_tuple_var =(itnm, itsz, itpth)
                            itemList[-1].append(item_tuple_var)
                            print(itemList[-1])
                        else:
                            break
                    print('sending clients and their files to client', addr_rec_tuple)
                    c = 1
                    for el in itemList[:-2]:
                        if c == 1:
                            connectionSocket.send(el[0].encode('utf-8'))
                            connectionSocket.recv(1024)
                            # time.sleep(0.05)
                            connectionSocket.send(el[1].encode('utf-8'))
                            connectionSocket.recv(1024)
                            # time.sleep(0.05)
                            c = 0
                        else:
                            for item1 in el:
                                print(item1)
                                # time.sleep(0.05)
                                connectionSocket.recv(1024)
                                print(item1[0])
                                connectionSocket.send(item1[0].encode('utf-8'))
                                # time.sleep(0.05)
                                connectionSocket.recv(1024)
                                print(item1[1])
                                connectionSocket.send(str(item1[1]).encode('utf-8'))
                                # time.sleep(0.05)
                                connectionSocket.recv(1024)
                                print(item1[2])
                                connectionSocket.send(item1[2].encode('utf-8'))

                            connectionSocket.recv(1024)
                            # time.sleep(0.05)
                            connectionSocket.send('Items end'.encode('utf-8'))
                            c = 1
                        time.sleep(0.005)
                    connectionSocket.send(b'Done!')
                else:
                    time.sleep(0.025)
                    connectionSocket.send(b'Done!')
                print(itemList)

            elif data == 'Refresh'.encode('utf-8'):
                pass
            elif data == 'Bye!'.encode('utf-8'):
                addr1 = connectionSocket.recv(bufferSize).decode()
                addr2 = connectionSocket.recv(bufferSize).decode()
                addr_rec_tuple = (addr1, addr2)
                if addr_rec_tuple in clients:
                    print(f'This client has quitted: {addr_rec_tuple[0]}:{addr_rec_tuple[1]}')
                    itemList.remove(itemList[itemList.index(addr_rec_tuple) + 1])
                    itemList.remove(addr_rec_tuple)
                    clients.remove(addr_rec_tuple)
                    print('Active clients: ', clients)

                    print('Clients and items', itemList)

            connectionSocket.close()


    except error as error:
        print(str(error))
        listenSocket.close()

    except KeyboardInterrupt:
        listenSocket.close()
        print('Key pressed!')

    finally:
        listenSocket.close()

