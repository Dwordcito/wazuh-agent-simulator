# Wazuh Agent Controller

A Python tool to simulate Wazuh agents and send arbitrary payloads using the Wazuh protocol. This tool is useful for testing Wazuh manager configurations, penetration testing, and understanding the Wazuh agent-manager communication protocol.

## Features

- **Agent Registration**: Register new agents with a Wazuh manager
- **Payload Transmission**: Send arbitrary payloads using the Wazuh protocol
- **Multiple Encryption Methods**: Support for AES and Blowfish encryption
- **Persistent Connections**: Maintain persistent connections for efficient communication
- **Credential Management**: Save and load agent credentials for reuse
- **Multiple Protocols**: Support for TCP and UDP communication
- **FlatBuffers Support**: Serialize JSON data to FlatBuffers format for efficient transmission

## Installation

1. **Clone or download the project**
2. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Quick Start

Use the provided shell script for easy execution:
```bash
./run.sh --help
```

### Manual Execution

Activate the virtual environment and run directly:
```bash
source venv/bin/activate
python wazuh_agent_controller.py --help
```

### Available Commands

#### 1. Register a New Agent
```bash
./run.sh -m 192.168.1.100 register
```

#### 2. Register and Send Payload
```bash
./run.sh -m 192.168.1.100 register-and-send --payload "Test message"
```

#### 3. Send Payload with Existing Agent
```bash
./run.sh -m 192.168.1.100 send --agent-id 001 --payload "Test message"
```

#### 4. List Registered Agents
```bash
./run.sh list
```

#### 5. Persistent Connection Mode
```bash
./run.sh -m 192.168.1.100 persistent --agent-id 001 --payload "Test message"
```

## Command Line Options

### Global Options
- `-m, --manager`: Manager IP address (required)
- `-r, --registration-address`: Registration IP address (defaults to manager)
- `-p, --protocol`: Communication protocol (TCP/UDP, default: TCP)
- `-c, --cypher`: Encryption method (aes/blowfish, default: aes)
- `-o, --os`: Agent operating system (default: debian8)
- `-v, --version`: Agent version (default: v4.3.0)
- `--authd-password`: Registration password
- `--port`: Manager port (default: 1514)
- `--persistent`: Use persistent connection
- `--flatbuffer`: Enable FlatBuffers processing for s:xxx:data format

### Register Command
- `-n, --name`: Agent name (optional, auto-generated)

### Send Command
- `--agent-id`: Agent ID (required)
- `--agent-name`: Agent name (optional if saved)
- `--agent-key`: Agent key (optional if saved)
- `--payload`: Payload to send (required)

## Examples

### Basic Registration
```bash
./run.sh -m 192.168.1.100 register
```

### Register with Custom Name
```bash
./run.sh -m 192.168.1.100 register -n "test-agent-01"
```

### Send Test Message
```bash
./run.sh -m 192.168.1.100 send --agent-id 001 --payload "Security alert: Failed login attempt"
```

### Use Different Encryption
```bash
./run.sh -m 192.168.1.100 -c blowfish register-and-send --payload "Test with Blowfish"
```

### UDP Communication
```bash
./run.sh -m 192.168.1.100 -p UDP send --agent-id 001 --payload "UDP test message"
```

### Persistent Connection
```bash
./run.sh -m 192.168.1.100 persistent --agent-id 001 --payload "Persistent connection test"
```

### FlatBuffers Serialization (Wazuh SyncSchema)
```bash
# Send Data message for document synchronization
./run.sh -m 192.168.1.100 --flatbuffer send --agent-id 001 --payload 's:data001:{"type":"data","seq":1,"session":1234567890,"operation":0,"id":"doc123","index":"security_events","data":"document content"}'

# Send Start message for sync session
./run.sh -m 192.168.1.100 --flatbuffer send --agent-id 001 --payload 's:start001:{"type":"start","mode":0,"size":1024,"module":"indexer","agent_id":12345}'

# Send StartAck message
./run.sh -m 192.168.1.100 --flatbuffer send --agent-id 001 --payload 's:startack001:{"type":"start_ack","status":0,"session":1234567890,"module":"indexer"}'
```

## Technical Details

### Encryption Algorithms

The tool supports two encryption methods:

1. **AES**: Uses AES-256 in CBC mode with fixed IV
2. **Blowfish**: Uses Blowfish in CBC mode with fixed IV

### Protocol Details

- **Registration**: SSL/TLS connection on port 1515
- **Event Transmission**: TCP/UDP on port 1514
- **Message Format**: `!agent_id!#AES:encrypted_data` or `!agent_id!:encrypted_data`

### Event Processing Pipeline

1. **Compose Event**: Create event structure with MD5 hash
2. **Compress**: Use zlib compression
3. **Padding**: Add Wazuh-specific 8-byte padding
4. **Encrypt**: Apply AES or Blowfish encryption
5. **Add Headers**: Include protocol headers
6. **Transmit**: Send via TCP or UDP

### FlatBuffers Processing Pipeline (Wazuh SyncSchema)

1. **Parse Format**: Extract identifier and JSON data from `s:xxx:data` format
2. **Validate JSON**: Ensure valid JSON structure
3. **Add Session ID**: Automatically add session ID if not present
4. **Serialize**: Convert JSON to FlatBuffers binary format using Wazuh SyncSchema
5. **Format**: Create final payload as `s:identifier:flatbuffer_serializado`

### Supported Message Types

- **Data**: Document/data synchronization with sequence numbers
- **Start**: Begin synchronization session
- **StartAck**: Acknowledge synchronization session start
- **End**: End synchronization session
- **EndAck**: Acknowledge synchronization session end
- **ReqRet**: Request retransmission of missing sequences

### Enums

- **Mode**: Full (0), Delta (1)
- **Operation**: Upsert (0), Delete (1)
- **Status**: Ok (0), PartialOk (1), Error (2), Offline (3)

## Security Considerations

⚠️ **Important**: This tool is designed for testing and educational purposes. Please ensure you have proper authorization before using it against any Wazuh deployment.

### Known Limitations

- Uses fixed initialization vectors (security weakness)
- Predictable event composition values
- Deterministic key derivation

## Troubleshooting

### Import Error with Crypto
If you encounter `ImportError: No module named 'Crypto'`, ensure you have installed `pycryptodome`:
```bash
pip install pycryptodome
```

### Connection Issues
- Verify the manager IP address and port
- Check firewall settings
- Ensure the Wazuh manager is running and accessible

### Registration Failures
- Verify the registration password if required
- Check SSL/TLS configuration
- Ensure port 1515 is open for registration

## File Structure

```
simulate-agent/
├── wazuh_agent_controller.py  # Main script
├── requirements.txt           # Python dependencies
├── run.sh                    # Convenience script
├── README.md                 # This file
├── schema.fbs                # Wazuh SyncSchema FlatBuffers definition
├── Wazuh/                    # Generated FlatBuffers Python code
│   ├── __init__.py
│   └── SyncSchema/
│       ├── __init__.py
│       ├── Message.py
│       ├── MessageType.py
│       ├── Data.py
│       ├── Start.py
│       ├── StartAck.py
│       ├── End.py
│       ├── EndAck.py
│       ├── ReqRet.py
│       ├── Pair.py
│       ├── Mode.py
│       ├── Operation.py
│       └── Status.py
└── wazuh_agents.json         # Saved agent credentials (created automatically)
```

## License

This tool is provided for educational and testing purposes. Use responsibly and ensure you have proper authorization for any testing activities.
