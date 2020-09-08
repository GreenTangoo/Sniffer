import socket
import threading
import sys

BUFFER_SIZE = 1024
list_connections = []

threadLock = threading.Lock()

def send_all_other(conn):
    global BUFFER_SIZE
    global list_connections

    while True:
        try:
            data = conn.recv(BUFFER_SIZE)
            threadLock.acquire()

            for oneConnection in list_connections:
                if oneConnection is not conn:
                    oneConnection.send(data)
            
            threadLock.release()
        except Exception as ex:
            print("Some exception catched")
            print(ex)
            threadLock.release()
            return


def main():
    global list_connections
    global threadLock

    if len(sys.argv) <= 1:
        print("Usage: python3 <script_name> <listen_port>")
        return

    sock = socket.socket()
    sock.bind(("", int(sys.argv[1])))
    sock.listen(1)

    while True:
        conn, addr = sock.accept()
        print(addr)

        threadLock.acquire()
        list_connections.append(conn)
        threadLock.release()

        threading._start_new_thread(send_all_other, (conn, ))

if __name__ == '__main__':
    main()