# Reverse Engineered Chatroom Server

This project is a fully compatible replacement chat server for the provided chatroom server executable.
The reference implementation was provided only as a binary, so the server was created by reverse-engineering the network protocol through packet inspection, Wireshark traces, and behavioral matching.

This server is designed to match the reference server byte-for-byte, ensuring that the official client produces identical output when connected.

Features
✅ Full Protocol Compatibility

This server implements every packet type used by the official client:

* Handshake (0x9B → 0x9A)

* Nick change (0x0F)

* Join room (0x03)

* Leave room (0x06)

* List rooms (0x09)

* List users (0x0C)

* Room messages (0x15)

* Private messages (DM) (0x12)

* Status / OK / Error packets (0x9A, 0x9C)

All responses use the exact payload structure expected by the client, including special formatting rules, length bytes, and ordering.

## Reverse Engineering Tasks Completed
1. Decoded the binary packet formats

Using tcpdump + Wireshark, the following protocol fields were reverse-engineered:

7-byte headers:
[len:4][0x04][0x17][opcode]

Variable-length nickname/room/message fields

Room and user list encodings

DM encoding (server → client)

Status and error packet formats

2. Implemented the server from scratch

All networking logic is built using:

select() multiplexing

Non-blocking I/O loops

Dynamic client/room management

Protocol-accurate serialization/deserialization

3. Matched server behavior exactly

The server was made to perfectly match:

* Output ordering

* Packet sequencing

* Opcode usage

* Room/user listing formatting

* All accepted and rejected client commands

This ensures the client prints identical text when connected to this server or the reference, which is the requirement for full credit.

## To run reference server:

./rserver_ref_macos_arm64 -p 41700

## How to Build

make clean

make

## How to run my implementation:
./rserver -p 41700

## How to run provided client:

docker run --rm -it --platform=linux/amd64 --network host -v "$(pwd)":/a3 ubuntu:24.04 bash

./client-executable

\connect <server-ip>:41700

Acknowledgements

This project was developed by reverse-engineering the binary reference server:

tcpdump

Wireshark

Binary diffing

Experimentation with malformed packets

Careful comparison to the reference client’s printed output

If you want a more polished version, a short resume-style version, or a Markdown-enhanced version with diagrams, just tell me.

ChatGPT can make mistakes. Check important info.
