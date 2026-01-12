from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException, ModbusIOException


def handle_modbus(args):
    output_str = ''
    success = False
    
    # Handle new scanning actions
    if args.action == 'scan_units':
        return scan_unit_ids(args)
    elif args.action == 'scan_registers':
        return scan_register_range(args)
    
    # Existing functionality
    for attempt in range(1, args.retries + 1):
        client = ModbusTcpClient(args.target, port=args.port, timeout=args.timeout)
        try:
            client.connect()
            
            if args.action in ['read', 'enumerate']:
                if args.function == 'coils':
                    response = client.read_coils(args.address, count=args.count, device_id=args.unit_id)
                    data = response.bits[:args.count] if not response.isError() else None
                elif args.function == 'discrete_inputs':
                    response = client.read_discrete_inputs(args.address, count=args.count, device_id=args.unit_id)
                    data = response.bits[:args.count] if not response.isError() else None
                elif args.function == 'holding_registers':
                    response = client.read_holding_registers(args.address, count=args.count, device_id=args.unit_id)
                    data = response.registers if not response.isError() else None
                elif args.function == 'input_registers':
                    response = client.read_input_registers(args.address, count=args.count, device_id=args.unit_id)
                    data = response.registers if not response.isError() else None
                
                if response.isError():
                    output_str += f"Error: {response}\n"
                else:
                    if args.action == 'read':
                        output_str += f"Read response: {data}\n"
                    elif args.action == 'enumerate':
                        for i, val in enumerate(data):
                            output_str += f"{args.function.capitalize().replace('_', ' ')} {args.address + i}: {val}\n"
            
            elif args.action == 'write':
                if args.function in ['discrete_inputs', 'input_registers']:
                    output_str += f"Cannot write to read-only function: {args.function}\n"
                else:
                    # Single write; count is ignored for write
                    if args.function == 'coils':
                        response = client.write_coil(args.address, bool(args.value), device_id=args.unit_id)
                    elif args.function == 'holding_registers':
                        response = client.write_register(args.address, args.value, device_id=args.unit_id)
                    
                    if response.isError():
                        output_str += f"Error: {response}\n"
                    else:
                        output_str += f"Write successful: {response}\n"
            
            success = True
        except (ConnectionException, ModbusIOException) as e:
            output_str += f"Attempt {attempt} failed: {str(e)}\n"
        except Exception as e:
            output_str += f"Unexpected error on attempt {attempt}: {str(e)}\n"
        finally:
            client.close()
        
        if success:
            break
    
    if not success:
        output_str += "All retries failed.\n"
    elif not output_str:
        output_str = "Operation completed with no output."
    
    return output_str


def scan_unit_ids(args):
    """Scan for active Modbus Unit/Slave IDs on the target"""
    output_str = f"=== Scanning Unit IDs on {args.target}:{args.port} ===\n"
    output_str += f"Range: {args.unit_start} to {args.unit_end}\n"
    output_str += f"Probing: All function codes at multiple addresses\n\n"
    
    active_units = {}  # Dictionary to store unit_id -> discovered_functions
    
    # Define probe strategies: (function_name, read_method, addresses_to_try)
    probe_strategies = [
        ('Coils', 'read_coils', [0, 1, 100, 1000]),
        ('Discrete Inputs', 'read_discrete_inputs', [0, 1, 100, 1000]),
        ('Holding Registers', 'read_holding_registers', [0, 1, 100, 1000, 40001]),
        ('Input Registers', 'read_input_registers', [0, 1, 100, 1000, 30001])
    ]
    
    client = ModbusTcpClient(args.target, port=args.port, timeout=args.timeout)
    
    try:
        client.connect()
        
        for unit_id in range(args.unit_start, args.unit_end + 1):
            found_functions = []
            
            for func_name, method_name, addresses in probe_strategies:
                read_method = getattr(client, method_name)
                
                # Try each address for this function
                for address in addresses:
                    try:
                        response = read_method(address, count=1, device_id=unit_id)
                        
                        if not response.isError():
                            # Device responded successfully!
                            if func_name not in found_functions:
                                found_functions.append(func_name)
                            break  # Found it, no need to try other addresses
                            
                    except Exception:
                        # Silent fail - try next address
                        continue
            
            # If ANY function responded, mark this unit as active
            if found_functions:
                active_units[unit_id] = found_functions
                output_str += f"[✓] Unit ID {unit_id}: ACTIVE\n"
                output_str += f"    Detected Functions: {', '.join(found_functions)}\n"
        
        if not active_units:
            output_str += "\n[!] No active units found in specified range.\n"
        else:
            output_str += f"\n=== Summary ===\n"
            output_str += f"Active Units Found: {len(active_units)}\n"
            output_str += f"Unit IDs: {', '.join(map(str, active_units.keys()))}\n"
            
            # Detailed breakdown
            output_str += f"\n=== Function Support Details ===\n"
            for unit_id, functions in active_units.items():
                output_str += f"Unit {unit_id}: {', '.join(functions)}\n"
    
    except Exception as e:
        output_str += f"\n[ERROR] Connection failed: {str(e)}\n"
    finally:
        client.close()
    
    return output_str




def scan_register_range(args):
    """Scan a range of registers to discover accessible addresses"""
    output_str = f"=== Scanning {args.function.replace('_', ' ').title()} ===\n"
    output_str += f"Target: {args.target}:{args.port} | Unit ID: {args.unit_id}\n"
    output_str += f"Range: {args.address} to {args.address + args.count - 1}\n\n"
    
    accessible_registers = []
    client = ModbusTcpClient(args.target, port=args.port, timeout=args.timeout)
    
    try:
        client.connect()
        
        # Determine which read function to use
        if args.function == 'coils':
            read_func = client.read_coils
            is_bit_type = True
        elif args.function == 'discrete_inputs':
            read_func = client.read_discrete_inputs
            is_bit_type = True
        elif args.function == 'holding_registers':
            read_func = client.read_holding_registers
            is_bit_type = False
        elif args.function == 'input_registers':
            read_func = client.read_input_registers
            is_bit_type = False
        
        # Scan in chunks for efficiency (read multiple at once)
        chunk_size = min(100, args.count)
        
        for start_addr in range(args.address, args.address + args.count, chunk_size):
            end_addr = min(start_addr + chunk_size, args.address + args.count)
            count_to_read = end_addr - start_addr
            
            try:
                response = read_func(start_addr, count=count_to_read, device_id=args.unit_id)
                
                if not response.isError():
                    if is_bit_type:
                        data = response.bits[:count_to_read]
                    else:
                        data = response.registers
                    
                    for i, val in enumerate(data):
                        addr = start_addr + i
                        accessible_registers.append((addr, val))
                        output_str += f"[✓] Address {addr}: {val}\n"
                else:
                    output_str += f"[✗] Address range {start_addr}-{end_addr-1}: Not accessible (Error: {response})\n"
            
            except Exception as e:
                output_str += f"[✗] Address range {start_addr}-{end_addr-1}: Error ({str(e)})\n"
        
        if not accessible_registers:
            output_str += "\n[!] No accessible registers found in specified range.\n"
        else:
            output_str += f"\n=== Summary ===\n"
            output_str += f"Accessible Registers: {len(accessible_registers)}\n"
            output_str += f"First Address: {accessible_registers[0][0]}\n"
            output_str += f"Last Address: {accessible_registers[-1][0]}\n"
    
    except Exception as e:
        output_str += f"\n[ERROR] Connection failed: {str(e)}\n"
    finally:
        client.close()
    
    return output_str
