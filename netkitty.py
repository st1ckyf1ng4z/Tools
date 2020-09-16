#!/usr/bin/env python3

import sys
import socket
import argparse
import threading
import subprocess

# this runs a command and returns the output
def run_command(cmd):
    # trim the newline
    cmd = cmd.rstrip()
    # run the command and get the output back
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                         shell=True)
    except subprocess.CalledProcessError as e:
        output = e.output
    # send the output back to the client
    return output

# this handles incoming client connections
def client_handler(client_socket):
    # check for upload
    if args.upload_destination is not None:
        # read in all of the bytes and write to our destination
        file_buffer = ""
        # keep reading data until none is available
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            else:
                file_buffer += data
        # now we take these bytes and try to write them out
        try:
            with open(args.upload_destination, "wb") as file_descriptor:
                file_descriptor.write(file_buffer.encode('utf-8'))
            # acknowledge that we wrote the file out
            client_socket.send(
                "Successfully saved file to %s\r\n" % args.upload_destination)
        except OSError:
            client_socket.send(
                "Failed to save file to %s\r\n" % args.upload_destination)
    # check for command execution
    if args.execute is not None:
        # run the command
        output = run_command(args.execute)
        client_socket.send(output)
    # now we go into another loop if a command shell was requested
    if args.command:
        while True:
            # show a simple prompt
            client_socket.send("<n3tk1tty:#> ".encode('utf-8'))
            # now we receive until we see a linefeed (enter key)
            cmd_buffer = b''
            while b"\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)
            # we have a valid command so execute it and send back the results
            response = run_command(cmd_buffer)
            # send back the response
            client_socket.send(response)

# this is for incoming connections
def server_loop():
    # if no target is defined we listen on all interfaces
    if args.target is None:
        target = "0.0.0.0"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, args.port))
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        # spin off a thread to handle our new client
        client_thread = threading.Thread(target=client_handler,
                                         args=(client_socket,))
        client_thread.start()

# if we don't listen we are a client... make it so.
def client_sender(buffer):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # connect to our target host
        client.connect((args.target, args.port))
        # if we detect input from stdin send it
        # if not we are going to wait for the user to punch some in
        if len(buffer):
            client.send(buffer.encode('utf-8'))
        while True:
            # now wait for data back
            recv_len = 1
            response = b''
            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data
                if recv_len < 4096:
                    break
            print(response.decode('utf-8'), end="")
            # wait for more input
            buffer = input("")
            buffer += "\n"
            # send it off
            client.send(buffer.encode('utf-8'))
    except socket.error as exc:
        print("[*] Exception! Exiting.")
        print(f"[*] Caught exception socket.error: {exc}")
        # teardown the connection
        client.close()

def main():
    # are we going to listen or just send data from STDIN?
    if not args.listen and args.target is not None and args.port > 0:
        # read in the buffer from the commandline
        # this will block, so send CTRL-D if not sending input
        # to stdin
        buffer = sys.stdin.read()
        # send data off
        client_sender(buffer)
    # we are going to listen and potentially
    # upload things, execute commands and drop a shell back
    # depending on our command line options above
    if args.listen:
        server_loop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', dest='target', metavar='', help='target ip')
    parser.add_argument('-p', '--port', dest='port', metavar='', help='target port', type=int)
    parser.add_argument('-l', '--listen', dest='listen', help='listen on [host]:[port] for incoming connections',
                        action='store_true')
    parser.add_argument('-e', '--execute', dest='execute', type=str, metavar='', help='execute the given file upon receiving a connection')
    parser.add_argument('-c', '--command', dest='command', help='initialize a command shell', action='store_true')
    parser.add_argument('-u', '--upload', dest='upload_destination', type=str, metavar='', help='upon receiving connection upload a file and write to [destination]')
    args = parser.parse_args()
    main()