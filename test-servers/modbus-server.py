import random
import threading
import time
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusDeviceContext, ModbusServerContext
from pymodbus import ModbusDeviceIdentification


def monitor_values(context, device_ids):
    """Periodically print the first 10 values of each Modbus data block every 1 second."""
    while True:
        try:
            print("\n--- Modbus Server Live Values ---")
            
            for device_id in device_ids:
                print(f"\n=== Device/Unit ID {device_id} ===")
                
                # Access the data blocks from each device context
                coils = context[device_id].getValues(1, 0, count=10)  # Function code 1: Coils
                discrete_inputs = context[device_id].getValues(2, 0, count=10)  # Function code 2: Discrete Inputs
                holding_registers = context[device_id].getValues(3, 0, count=10)  # Function code 3: Holding Registers
                input_registers = context[device_id].getValues(4, 0, count=10)  # Function code 4: Input Registers
                
                print(f"  Coils (first 10): {coils}")
                print(f"  Discrete Inputs (first 10): {discrete_inputs}")
                print(f"  Holding Registers (first 10): {holding_registers}")
                print(f"  Input Registers (first 10): {input_registers}")
            
            print("-------------------------------")
            
            time.sleep(1)  # Sleep for 1 second
        except Exception as e:
            print(f"Error in monitor_values: {e}")
            break


def setup_server_context():
    """Create a multi-device Modbus server with 3 different devices."""
    
    # Device 1: PLC Controller
    store1 = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(0, [True if i % 3 == 0 else False for i in range(1000)]),
        co=ModbusSequentialDataBlock(0, [bool(i % 2) for i in range(1000)]),
        hr=ModbusSequentialDataBlock(0, list(range(1000))),
        ir=ModbusSequentialDataBlock(0, [random.randint(0, 65535) for _ in range(1000)])
    )
    
    # Device 5: Sensor Array
    store5 = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(0, [True] * 100 + [False] * 900),
        co=ModbusSequentialDataBlock(0, [False] * 1000),
        hr=ModbusSequentialDataBlock(0, [5000 + i for i in range(1000)]),
        ir=ModbusSequentialDataBlock(0, [random.randint(1000, 5000) for _ in range(1000)])
    )
    
    # Device 10: Actuator Bank
    store10 = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(0, [False] * 1000),
        co=ModbusSequentialDataBlock(0, [True] * 500 + [False] * 500),
        hr=ModbusSequentialDataBlock(0, [10000 + i for i in range(1000)]),
        ir=ModbusSequentialDataBlock(0, [random.randint(500, 2000) for _ in range(1000)])
    )
    
    # Create context with multiple devices
    devices = {1: store1, 5: store5, 10: store10}
    context = ModbusServerContext(devices=devices, single=False)
    
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'xAI Test Server'
    identity.ProductCode = 'XAI-MODBUS'
    identity.VendorUrl = 'https://x.ai'
    identity.ProductName = 'Modbus Multi-Device Test Server'
    identity.ModelName = 'Model 2.0'
    identity.MajorMinorRevision = '2.0'
    
    return context, identity, list(devices.keys())


if __name__ == "__main__":
    context, identity, device_ids = setup_server_context()
    print("Starting Modbus TCP Server on localhost:5002...")
    print("Device 1 (PLC Controller): Full data blocks")
    print("Device 5 (Sensor Array): Sensor simulation data")
    print("Device 10 (Actuator Bank): Actuator control data")
    
    # Start the monitoring thread - pass device_ids explicitly
    monitor_thread = threading.Thread(target=monitor_values, args=(context, device_ids), daemon=True)
    monitor_thread.start()
    
    # Start the Modbus server
    StartTcpServer(context=context, identity=identity, address=("localhost", 5002))
