#!/usr/bin/env python3
"""
Wazuh Agent Controller
Script to register agents and send arbitrary payloads using the Wazuh protocol.
"""

import argparse
import hashlib
import json
import logging
import os
import socket
import ssl
import struct
import zlib
import base64
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad
from random import sample
from string import ascii_letters
from time import sleep
import flatbuffers
from Wazuh.SyncSchema import (
    Message, MessageType, Data, Start, StartAck, End, EndAck, ReqRet, Pair,
    Mode, Operation, Status
)


class Cipher:
    """Class to encrypt/decrypt messages using AES or Blowfish."""
    
    def __init__(self, data, key):
        self.block_size = 16
        self.data = data
        self.key_blowfish = key
        self.key_aes = key[:32]

    def encrypt_aes(self):
        iv = b'FEDCBA0987654321'
        cipher = AES.new(self.key_aes, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(self.data, self.block_size))

    def decrypt_aes(self):
        iv = b'FEDCBA0987654321'
        cipher = AES.new(self.key_aes, AES.MODE_CBC, iv)
        return cipher.decrypt(pad(self.data, self.block_size))

    def encrypt_blowfish(self):
        iv = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'
        cipher = Blowfish.new(self.key_blowfish, Blowfish.MODE_CBC, iv)
        return cipher.encrypt(self.data)

    def decrypt_blowfish(self):
        iv = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'
        cipher = Blowfish.new(self.key_blowfish, Blowfish.MODE_CBC, iv)
        return cipher.decrypt(self.data)


class FlatBufferSerializer:
    """Class to handle JSON to FlatBuffers serialization using Wazuh SyncSchema."""
    
    def __init__(self):
        self.builder = None
    
    def create_data_message(self, json_data):
        """Creates a Data message from JSON."""
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        
        self.builder = flatbuffers.Builder(1024)
        
        # Create string offsets
        id_offset = self.builder.CreateString(json_data.get('id', ''))
        index_offset = self.builder.CreateString(json_data.get('index', ''))
        
        # Create data vector
        data_bytes = json_data.get('data', b'')
        if isinstance(data_bytes, str):
            data_bytes = data_bytes.encode('utf-8')
        
        Data.DataStartDataVector(self.builder, len(data_bytes))
        for byte in reversed(data_bytes):
            self.builder.PrependByte(byte)
        data_vector = self.builder.EndVector(len(data_bytes))
        
        # Create Data table
        Data.DataStart(self.builder)
        Data.DataAddSeq(self.builder, json_data.get('seq', 0))
        Data.DataAddSession(self.builder, json_data.get('session', 0))
        Data.DataAddOperation(self.builder, json_data.get('operation', Operation.Operation.Upsert))
        Data.DataAddId(self.builder, id_offset)
        Data.DataAddIndex(self.builder, index_offset)
        Data.DataAddData(self.builder, data_vector)
        data_offset = Data.DataEnd(self.builder)
        
        # Create Message with Data content
        Message.MessageStart(self.builder)
        Message.MessageAddContentType(self.builder, MessageType.MessageType.Data)
        Message.MessageAddContent(self.builder, data_offset)
        message_offset = Message.MessageEnd(self.builder)
        
        self.builder.Finish(message_offset)
        return self.builder.Output()
    
    def create_start_message(self, json_data):
        """Creates a Start message from JSON."""
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        
        self.builder = flatbuffers.Builder(1024)
        
        # Create string offset
        module_offset = self.builder.CreateString(json_data.get('module', ''))
        
        # Create Start table
        Start.StartStart(self.builder)
        Start.StartAddMode(self.builder, json_data.get('mode', Mode.Mode.Full))
        Start.StartAddSize(self.builder, json_data.get('size', 0))
        Start.StartAddModule(self.builder, module_offset)
        Start.StartAddAgentId(self.builder, json_data.get('agent_id', 0))
        start_offset = Start.StartEnd(self.builder)
        
        # Create Message with Start content
        Message.MessageStart(self.builder)
        Message.MessageAddContentType(self.builder, MessageType.MessageType.Start)
        Message.MessageAddContent(self.builder, start_offset)
        message_offset = Message.MessageEnd(self.builder)
        
        self.builder.Finish(message_offset)
        return self.builder.Output()
    
    def create_start_ack_message(self, json_data):
        """Creates a StartAck message from JSON."""
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        
        self.builder = flatbuffers.Builder(1024)
        
        # Create string offset
        module_offset = self.builder.CreateString(json_data.get('module', ''))
        
        # Create StartAck table
        StartAck.StartAckStart(self.builder)
        StartAck.StartAckAddStatus(self.builder, json_data.get('status', Status.Status.Ok))
        StartAck.StartAckAddSession(self.builder, json_data.get('session', 0))
        StartAck.StartAckAddModule(self.builder, module_offset)
        start_ack_offset = StartAck.StartAckEnd(self.builder)
        
        # Create Message with StartAck content
        Message.MessageStart(self.builder)
        Message.MessageAddContentType(self.builder, MessageType.MessageType.StartAck)
        Message.MessageAddContent(self.builder, start_ack_offset)
        message_offset = Message.MessageEnd(self.builder)
        
        self.builder.Finish(message_offset)
        return self.builder.Output()
    
    def create_end_message(self, json_data):
        """Creates an End message from JSON."""
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        
        self.builder = flatbuffers.Builder(1024)
        
        # Create End table
        End.EndStart(self.builder)
        End.EndAddSession(self.builder, json_data.get('session', 0))
        end_offset = End.EndEnd(self.builder)
        
        # Create Message with End content
        Message.MessageStart(self.builder)
        Message.MessageAddContentType(self.builder, MessageType.MessageType.End)
        Message.MessageAddContent(self.builder, end_offset)
        message_offset = Message.MessageEnd(self.builder)
        
        self.builder.Finish(message_offset)
        return self.builder.Output()
    
    def create_end_ack_message(self, json_data):
        """Creates an EndAck message from JSON."""
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        
        self.builder = flatbuffers.Builder(1024)
        
        # Create string offset
        module_offset = self.builder.CreateString(json_data.get('module', ''))
        
        # Create EndAck table
        EndAck.EndAckStart(self.builder)
        EndAck.EndAckAddStatus(self.builder, json_data.get('status', Status.Status.Ok))
        EndAck.EndAckAddSession(self.builder, json_data.get('session', 0))
        EndAck.EndAckAddModule(self.builder, module_offset)
        end_ack_offset = EndAck.EndAckEnd(self.builder)
        
        # Create Message with EndAck content
        Message.MessageStart(self.builder)
        Message.MessageAddContentType(self.builder, MessageType.MessageType.EndAck)
        Message.MessageAddContent(self.builder, end_ack_offset)
        message_offset = Message.MessageEnd(self.builder)
        
        self.builder.Finish(message_offset)
        return self.builder.Output()
    
    def create_req_ret_message(self, json_data):
        """Creates a ReqRet message from JSON."""
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        
        self.builder = flatbuffers.Builder(1024)
        
        # Create string offset
        module_offset = self.builder.CreateString(json_data.get('module', ''))
        
        # Create Pair objects for seq vector
        seq_offsets = []
        for pair_data in json_data.get('seq', []):
            Pair.PairStart(self.builder)
            Pair.PairAddBegin(self.builder, pair_data.get('begin', 0))
            Pair.PairAddEnd(self.builder, pair_data.get('end', 0))
            seq_offsets.append(Pair.PairEnd(self.builder))
        
        # Create seq vector
        ReqRet.ReqRetStartSeqVector(self.builder, len(seq_offsets))
        for offset in reversed(seq_offsets):
            self.builder.PrependUOffsetTRelative(offset)
        seq_vector = self.builder.EndVector(len(seq_offsets))
        
        # Create ReqRet table
        ReqRet.ReqRetStart(self.builder)
        ReqRet.ReqRetAddSeq(self.builder, seq_vector)
        ReqRet.ReqRetAddSession(self.builder, json_data.get('session', 0))
        ReqRet.ReqRetAddModule(self.builder, module_offset)
        req_ret_offset = ReqRet.ReqRetEnd(self.builder)
        
        # Create Message with ReqRet content
        Message.MessageStart(self.builder)
        Message.MessageAddContentType(self.builder, MessageType.MessageType.ReqRet)
        Message.MessageAddContent(self.builder, req_ret_offset)
        message_offset = Message.MessageEnd(self.builder)
        
        self.builder.Finish(message_offset)
        return self.builder.Output()
    
    def json_to_flatbuffer(self, json_data):
        """Converts JSON data to FlatBuffers format based on message type."""
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        
        message_type = json_data.get('type', 'data').lower()
        
        if message_type == 'data':
            return self.create_data_message(json_data)
        elif message_type == 'start':
            return self.create_start_message(json_data)
        elif message_type == 'start_ack':
            return self.create_start_ack_message(json_data)
        elif message_type == 'end':
            return self.create_end_message(json_data)
        elif message_type == 'end_ack':
            return self.create_end_ack_message(json_data)
        elif message_type == 'req_ret':
            return self.create_req_ret_message(json_data)
        else:
            # Default to data message
            return self.create_data_message(json_data)
    
    def flatbuffer_to_json(self, flatbuffer_data):
        """Converts FlatBuffers data back to JSON format."""
        try:
            message = Message.Message.GetRootAsMessage(flatbuffer_data, 0)
            content_type = message.ContentType()
            
            result = {'type': 'unknown'}
            
            if content_type == MessageType.MessageType.Data:
                # For now, return a simplified structure
                result = {
                    'type': 'data',
                    'message': 'Data message deserialized successfully'
                }
            
            elif content_type == MessageType.MessageType.Start:
                result = {
                    'type': 'start',
                    'message': 'Start message deserialized successfully'
                }
            
            elif content_type == MessageType.MessageType.StartAck:
                result = {
                    'type': 'start_ack',
                    'message': 'StartAck message deserialized successfully'
                }
            
            elif content_type == MessageType.MessageType.End:
                result = {
                    'type': 'end',
                    'message': 'End message deserialized successfully'
                }
            
            elif content_type == MessageType.MessageType.EndAck:
                result = {
                    'type': 'end_ack',
                    'message': 'EndAck message deserialized successfully'
                }
            
            elif content_type == MessageType.MessageType.ReqRet:
                result = {
                    'type': 'req_ret',
                    'message': 'ReqRet message deserialized successfully'
                }
            
            return result
            
        except Exception as e:
            return {
                'type': 'error',
                'message': f'Deserialization error: {str(e)}'
            }


class WazuhAgent:
    """Class to simulate a Wazuh agent."""
    
    def __init__(self, manager_address, registration_address=None, cypher="aes", 
                 os="debian8", version="v4.3.0", authd_password=None, enable_flatbuffer=False):
        self.manager_address = manager_address
        self.registration_address = registration_address or manager_address
        self.cypher = cypher
        self.os = os
        self.version = version
        self.authd_password = authd_password
        self.enable_flatbuffer = enable_flatbuffer
        
        # Agent values (set during registration)
        self.id = None
        self.name = None
        self.key = None
        self.encryption_key = None
        
        # Global counter for unique names
        self.agent_count = 0
        
        # Persistent connection
        self.persistent_socket = None
        self.persistent_ssl_socket = None
        
        # File to save credentials
        self.credentials_file = "wazuh_agents.json"
        
        # FlatBuffers serializer
        self.flatbuffer_serializer = FlatBufferSerializer()

    def generate_agent_name(self):
        """Generates a unique name for the agent."""
        random_string = ''.join(sample(f"0123456789{ascii_letters}", 16))
        self.agent_count += 1
        return f"{self.agent_count}-{random_string}-{self.os}"

    def load_credentials(self):
        """Loads saved agent credentials."""
        if os.path.exists(self.credentials_file):
            try:
                with open(self.credentials_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️  Error loading credentials: {e}")
                return {}
        return {}

    def save_credentials(self, credentials):
        """Saves agent credentials."""
        try:
            with open(self.credentials_file, 'w') as f:
                json.dump(credentials, f, indent=2)
        except Exception as e:
            print(f"⚠️  Error saving credentials: {e}")

    def get_agent_credentials(self, agent_id):
        """Gets agent credentials by ID."""
        credentials = self.load_credentials()
        return credentials.get(agent_id)

    def list_registered_agents(self):
        """Lists all registered agents."""
        credentials = self.load_credentials()
        if not credentials:
            print("📋 No registered agents.")
            return []
        
        print("📋 Registered agents:")
        print("-" * 60)
        for agent_id, agent_data in credentials.items():
            print(f"ID: {agent_id}")
            print(f"  Name: {agent_data['name']}")
            print(f"  Key: {agent_data['key']}")
            print(f"  Manager: {agent_data['manager']}")
            print(f"  Cipher: {agent_data['cypher']}")
            print(f"  OS: {agent_data['os']}")
            print(f"  Version: {agent_data['version']}")
            print("-" * 60)
        
        return list(credentials.keys())

    def register_agent(self, agent_name=None):
        """Registers the agent with the manager."""
        if agent_name:
            self.name = agent_name
        else:
            self.name = self.generate_agent_name()
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            ssl_socket = context.wrap_socket(sock, server_hostname=self.registration_address)
            ssl_socket.connect((self.registration_address, 1515))

            if self.authd_password is None:
                event = f"OSSEC A:'{self.name}'\n".encode()
            else:
                event = f"OSSEC PASS: {self.authd_password} OSSEC A:'{self.name}'\n".encode()

            ssl_socket.send(event)
            recv = ssl_socket.recv(4096)
            registration_info = recv.decode().split("'")[1].split(" ")

            self.id = registration_info[0]
            self.key = registration_info[3]
            
            # Save credentials
            credentials = self.load_credentials()
            credentials[self.id] = {
                'name': self.name,
                'key': self.key,
                'manager': self.manager_address,
                'cypher': self.cypher,
                'os': self.os,
                'version': self.version
            }
            self.save_credentials(credentials)
            
            print(f"✅ Agent registered successfully:")
            print(f"   ID: {self.id}")
            print(f"   Name: {self.name}")
            print(f"   Key: {self.key}")
            print(f"   Credentials saved in: {self.credentials_file}")
            
        except Exception as e:
            print(f"❌ Error during registration: {e}")
            raise
        finally:
            ssl_socket.close()
            sock.close()

    def create_persistent_connection(self, port=1514):
        """Creates a persistent connection to the manager."""
        if self.persistent_socket is None:
            self.persistent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.persistent_socket.connect((self.manager_address, port))
            print(f"🔗 Persistent connection established to {self.manager_address}:{port}")

    def close_persistent_connection(self):
        """Closes the persistent connection."""
        if self.persistent_socket:
            self.persistent_socket.close()
            self.persistent_socket = None
            print("🔌 Persistent connection closed")

    def create_encryption_key(self):
        """Generates the encryption key using agent metadata."""
        if not all([self.id, self.name, self.key]):
            raise ValueError("Agent must be registered before creating encryption key")
            
        agent_id = self.id.encode()
        name = self.name.encode()
        key = self.key.encode()
        
        sum1 = hashlib.md5(hashlib.md5(name).hexdigest().encode() + 
                          hashlib.md5(agent_id).hexdigest().encode()).hexdigest().encode()
        sum1 = sum1[:15]
        sum2 = hashlib.md5(key).hexdigest().encode()
        self.encryption_key = sum2 + sum1

    def wazuh_padding(self, compressed_event):
        """Adds Wazuh's custom padding to the event."""
        padding = 8
        extra = len(compressed_event) % padding
        if extra > 0:
            padded_event = (b'!' * (padding - extra)) + compressed_event
        else:
            padded_event = (b'!' * padding) + compressed_event
        return padded_event

    def compose_event(self, message):
        """Composes the event from the raw message."""
        message = message.encode()
        return self.compose_event_from_data(message)
    
    def compose_event_from_data(self, data):
        """Composes the event from binary data."""
        random_number = b'55555'
        global_counter = b'1234567891'
        split = b':'
        local_counter = b'5555'
        msg = random_number + global_counter + split + local_counter + split + data
        msg_md5 = hashlib.md5(msg).hexdigest()
        event = msg_md5.encode() + msg
        return event

    def encrypt(self, padded_event):
        """Encrypts the event using AES or Blowfish."""
        if self.cypher == "aes":
            return Cipher(padded_event, self.encryption_key).encrypt_aes()
        elif self.cypher == "blowfish":
            return Cipher(padded_event, self.encryption_key).encrypt_blowfish()
        else:
            raise ValueError(f"Unsupported cipher: {self.cypher}")

    def headers(self, agent_id, encrypted_event):
        """Adds event headers for AES or Blowfish."""
        if self.cypher == "aes":
            header = f"!{agent_id}!#AES:".encode()
        elif self.cypher == "blowfish":
            header = f"!{agent_id}!:".encode()
        else:
            raise ValueError(f"Unsupported cipher: {self.cypher}")
        return header + encrypted_event

    def create_event(self, message):
        """Builds a complete event from a raw message."""
        # Normal text message
        event_data = message.encode()
        
        # Compose event
        event = self.compose_event_from_data(event_data)
        # Compress
        compressed_event = zlib.compress(event)
        # Padding
        padded_event = self.wazuh_padding(compressed_event)
        # Encrypt
        encrypted_event = self.encrypt(padded_event)
        # Add headers
        headers_event = self.headers(self.id, encrypted_event)
        return headers_event
    
    def create_event_from_binary(self, identifier, binary_data):
        """Builds a complete event from binary data (FlatBuffers)."""
        # Create the event structure with identifier and binary data
        random_number = b'55555'
        global_counter = b'1234567891'
        split = b':'
        local_counter = b'5555'
        
        # Combine identifier and binary data with s: prefix
        identifier_bytes = identifier.encode()
        s_prefix = b's:'
        msg = random_number + global_counter + split + local_counter + split + s_prefix + identifier_bytes + split + binary_data
        msg_md5 = hashlib.md5(msg).hexdigest()
        event = msg_md5.encode() + msg
        
        # Print the complete payload before encryption
        print(f"🔍 DEBUG - Complete payload before encryption:")
        print(f"   MD5: {msg_md5}")
        print(f"   Random: {random_number.decode()}")
        print(f"   Global Counter: {global_counter.decode()}")
        print(f"   Local Counter: {local_counter.decode()}")
        print(f"   Format: s:{identifier}:binary_data")
        print(f"   Binary Data Size: {len(binary_data)} bytes")
        print(f"   Binary Data Preview: {binary_data[:20]}...")
        print(f"   Complete Event: {event}")
        print(f"   Event Size: {len(event)} bytes")
        
        # Compress
        compressed_event = zlib.compress(event)
        # Padding
        padded_event = self.wazuh_padding(compressed_event)
        # Encrypt
        encrypted_event = self.encrypt(padded_event)
        # Add headers
        headers_event = self.headers(self.id, encrypted_event)
        
        return headers_event

    def send_payload(self, payload, protocol="TCP", port=1514, persistent=False):
        """Sends an arbitrary payload to the manager."""
        if not all([self.id, self.name, self.key, self.encryption_key]):
            raise ValueError("Agent must be registered and have encryption key")
        
        # Process FlatBuffers payload if needed
        processed_result = self.process_flatbuffer_payload(payload)
        
        if isinstance(processed_result, tuple) and len(processed_result) == 2:
            # FlatBuffers processing returned (identifier, binary_data)
            identifier, flatbuffer_data = processed_result
            if flatbuffer_data is not None:
                # Create event directly from binary data
                encrypted_event = self.create_event_from_binary(identifier, flatbuffer_data)
            else:
                # Fallback to normal processing
                encrypted_event = self.create_event(payload)
        else:
            # Normal processing
            encrypted_event = self.create_event(processed_result)
        
        # Send using persistent connection or new connection
        if persistent and self.persistent_socket:
            try:
                length = struct.pack('<I', len(encrypted_event))
                self.persistent_socket.send(length + encrypted_event)
                print(f"✅ Payload sent (persistent connection):")
                print(f"   Agent: {self.name} (ID: {self.id})")
                print(f"   Original payload: {payload}")
                if isinstance(processed_result, tuple) and processed_result[1] is not None:
                    print(f"   Processed as FlatBuffers binary: {len(processed_result[1])} bytes")
                return
            except Exception as e:
                print(f"⚠️  Error in persistent connection, creating new one: {e}")
                self.close_persistent_connection()
        
        # Connect and send
        if protocol.upper() == "TCP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.manager_address, port))
            length = struct.pack('<I', len(encrypted_event))
            sock.send(length + encrypted_event)
            sock.close()
        elif protocol.upper() == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(encrypted_event, (self.manager_address, port))
            sock.close()
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")
            
        print(f"✅ Payload sent successfully:")
        print(f"   Agent: {self.name} (ID: {self.id})")
        print(f"   Original payload: {payload}")
        if isinstance(processed_result, tuple) and processed_result[1] is not None:
            print(f"   Processed as FlatBuffers binary: {len(processed_result[1])} bytes")
        print(f"   Protocol: {protocol}")
        print(f"   Destination: {self.manager_address}:{port}")

    def load_existing_agent(self, agent_id, agent_name=None, agent_key=None):
        """Loads an existing agent with its credentials."""
        # Try to load from credentials file
        if agent_name is None and agent_key is None:
            agent_data = self.get_agent_credentials(agent_id)
            if agent_data:
                self.id = agent_id
                self.name = agent_data['name']
                self.key = agent_data['key']
                self.cypher = agent_data.get('cypher', 'aes')
                self.os = agent_data.get('os', 'debian8')
                self.version = agent_data.get('version', 'v4.3.0')
                self.manager_address = agent_data.get('manager', self.manager_address)
                print(f"✅ Agent loaded from saved credentials:")
                print(f"   ID: {self.id}")
                print(f"   Name: {self.name}")
                print(f"   Key: {self.key}")
            else:
                raise ValueError(f"No credentials found for agent ID: {agent_id}")
        else:
            # Use provided credentials
            self.id = agent_id
            self.name = agent_name
            self.key = agent_key
        
        self.create_encryption_key()

    def process_flatbuffer_payload(self, payload):
        """Processes payload with format 's:xxx:data' where data is JSON to be serialized as FlatBuffers."""
        if not self.enable_flatbuffer or not payload.startswith('s:'):
            return payload, None
        
        try:
            # Parse the format: s:xxx:data
            parts = payload.split(':', 2)
            if len(parts) != 3:
                print(f"⚠️  Invalid FlatBuffers payload format. Expected 's:xxx:data', got: {payload}")
                return payload, None
            
            prefix, identifier, json_data = parts
            
            # Parse JSON data
            try:
                json_obj = json.loads(json_data)
            except json.JSONDecodeError as e:
                print(f"⚠️  Invalid JSON in FlatBuffers payload: {e}")
                return payload, None
            
            # Add session ID if not present (for sync operations)
            if 'session' not in json_obj:
                import time
                json_obj['session'] = int(time.time())
            
            # Serialize to FlatBuffers
            flatbuffer_data = self.flatbuffer_serializer.json_to_flatbuffer(json_obj)
            
            print(f"✅ FlatBuffers payload processed:")
            print(f"   Message type: {json_obj.get('type', 'data')}")
            print(f"   Original JSON: {json_data}")
            print(f"   Serialized size: {len(flatbuffer_data)} bytes")
            print(f"   FlatBuffer data (binary): {len(flatbuffer_data)} bytes")
            
            # Return both the identifier and the binary data
            return identifier, flatbuffer_data
            
        except Exception as e:
            print(f"⚠️  Error processing FlatBuffers payload: {e}")
            return payload, None


def main():
    parser = argparse.ArgumentParser(description="Wazuh Agent Controller")
    parser.add_argument('-m', '--manager', required=True, help='Manager IP address')
    parser.add_argument('-r', '--registration-address', help='Registration IP address (defaults to manager)')
    parser.add_argument('-p', '--protocol', default='TCP', choices=['TCP', 'UDP'], help='Communication protocol')
    parser.add_argument('-c', '--cypher', default='aes', choices=['aes', 'blowfish'], help='Encryption method')
    parser.add_argument('-o', '--os', default='debian8', help='Agent operating system')
    parser.add_argument('-v', '--version', default='v4.3.0', help='Agent version')
    parser.add_argument('--authd-password', help='Registration password')
    parser.add_argument('--port', type=int, default=1514, help='Manager port (default 1514)')
    parser.add_argument('--persistent', action='store_true', help='Use persistent connection')
    parser.add_argument('--flatbuffer', action='store_true', help='Enable FlatBuffers processing for s:xxx:data format')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Register command
    register_parser = subparsers.add_parser('register', help='Register a new agent')
    register_parser.add_argument('-n', '--name', help='Agent name (optional, auto-generated)')
    
    # Send payload command
    send_parser = subparsers.add_parser('send', help='Send an arbitrary payload')
    send_parser.add_argument('--agent-id', required=True, help='Agent ID')
    send_parser.add_argument('--agent-name', help='Agent name (optional if saved)')
    send_parser.add_argument('--agent-key', help='Agent key (optional if saved)')
    send_parser.add_argument('--payload', required=True, help='Payload to send')
    
    # Register and send command
    register_send_parser = subparsers.add_parser('register-and-send', help='Register agent and send payload')
    register_send_parser.add_argument('-n', '--name', help='Agent name (optional)')
    register_send_parser.add_argument('--payload', required=True, help='Payload to send')
    
    # List agents command
    list_parser = subparsers.add_parser('list', help='List registered agents')
    
    # Persistent connection command
    persistent_parser = subparsers.add_parser('persistent', help='Persistent connection mode')
    persistent_parser.add_argument('--agent-id', required=True, help='Agent ID')
    persistent_parser.add_argument('--agent-name', help='Agent name (optional if saved)')
    persistent_parser.add_argument('--agent-key', help='Agent key (optional if saved)')
    persistent_parser.add_argument('--payload', required=True, help='Payload to send')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create agent instance
    agent = WazuhAgent(
        manager_address=args.manager,
        registration_address=args.registration_address,
        cypher=args.cypher,
        os=args.os,
        version=args.version,
        authd_password=args.authd_password,
        enable_flatbuffer=args.flatbuffer
    )
    
    try:
        if args.command == 'register':
            # Only register
            agent.register_agent(args.name)
            agent.create_encryption_key()
            print("\n📋 Agent information for future use:")
            print(f"   --agent-id {agent.id}")
            print(f"   --agent-name {agent.name}")
            print(f"   --agent-key {agent.key}")
            
        elif args.command == 'send':
            # Load existing agent and send payload
            agent.load_existing_agent(args.agent_id, args.agent_name, args.agent_key)
            agent.send_payload(args.payload, args.protocol, args.port, args.persistent)
            
        elif args.command == 'register-and-send':
            # Register and send payload
            agent.register_agent(args.name)
            agent.create_encryption_key()
            sleep(1)  # Small pause to ensure registration completes
            agent.send_payload(args.payload, args.protocol, args.port, args.persistent)
            
        elif args.command == 'list':
            # List registered agents
            agent.list_registered_agents()
            
        elif args.command == 'persistent':
            # Persistent connection mode
            agent.load_existing_agent(args.agent_id, args.agent_name, args.agent_key)
            agent.create_persistent_connection(args.port)
            try:
                agent.send_payload(args.payload, args.protocol, args.port, persistent=True)
            finally:
                agent.close_persistent_connection()
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
