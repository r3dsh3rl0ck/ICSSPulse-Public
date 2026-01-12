import time
import random
from threading import Thread
from opcua import Server, ua
class IndustrialOPCServer:
    def __init__(self):
        # Initialize the server
        self.server = Server()
        self.server.set_endpoint("opc.tcp://localhost:4840/freeopcua/server/")
        self.server.set_server_name("Industrial Simulation Server")
        
        # Set up the address space
        self.setup_address_space()
        
        # Variables for simulation
        self.running = False
        self.simulation_thread = None
        
    def setup_address_space(self):
        # Get the root objects node
        objects = self.server.get_objects_node()
        
        # Create our main factory object
        self.factory = objects.add_object("ns=2;i=1", "Factory")
        
        # Create production line object
        self.production_line = self.factory.add_object("ns=2;i=2", "ProductionLine1")
        
        # Add temperature sensors
        self.temp_sensors = self.production_line.add_object("ns=2;i=3", "TemperatureSensors")
        
        # Create individual temperature sensor variables
        self.temp_sensor_1 = self.temp_sensors.add_variable("ns=2;i=10", "Sensor1_Temperature", 20.0)
        self.temp_sensor_2 = self.temp_sensors.add_variable("ns=2;i=11", "Sensor2_Temperature", 25.0)
        self.temp_sensor_3 = self.temp_sensors.add_variable("ns=2;i=12", "Sensor3_Temperature", 22.0)
        
        # Make temperature sensors writable (for demonstration)
        self.temp_sensor_1.set_writable()
        self.temp_sensor_2.set_writable()
        self.temp_sensor_3.set_writable()
        
        # Add motor control section
        self.motors = self.production_line.add_object("ns=2;i=4", "Motors")
        
        # Create motor variables
        self.motor1_speed = self.motors.add_variable("ns=2;i=20", "Motor1_Speed", 0)
        self.motor1_status = self.motors.add_variable("ns=2;i=21", "Motor1_Status", False)
        self.motor2_speed = self.motors.add_variable("ns=2;i=22", "Motor2_Speed", 0)
        self.motor2_status = self.motors.add_variable("ns=2;i=23", "Motor2_Status", False)
        
        # Make motor controls writable
        self.motor1_speed.set_writable()
        self.motor1_status.set_writable()
        self.motor2_speed.set_writable()
        self.motor2_status.set_writable()
        
        # Add system information
        self.system_info = self.factory.add_object("ns=2;i=5", "SystemInfo")
        self.uptime = self.system_info.add_variable("ns=2;i=30", "Uptime", 0)
        self.total_production = self.system_info.add_variable("ns=2;i=31", "TotalProduction", 0)
        
    def simulate_industrial_data(self):
        """Simulate realistic industrial data changes"""
        uptime_counter = 0
        production_counter = 0
        
        while self.running:
            try:
                # Simulate temperature fluctuations
                base_temp_1 = 20.0 + random.uniform(-2, 3)
                base_temp_2 = 25.0 + random.uniform(-1.5, 2.5)
                base_temp_3 = 22.0 + random.uniform(-1, 2)
                
                self.temp_sensor_1.set_value(round(base_temp_1, 2))
                self.temp_sensor_2.set_value(round(base_temp_2, 2))
                self.temp_sensor_3.set_value(round(base_temp_3, 2))
                
                # Simulate motor behavior
                if self.motor1_status.get_value():
                    current_speed = self.motor1_speed.get_value()
                    # Simulate speed variations during operation
                    new_speed = max(0, current_speed + random.uniform(-5, 5))
                    self.motor1_speed.set_value(int(new_speed))
                    production_counter += random.randint(1, 3)
                
                if self.motor2_status.get_value():
                    current_speed = self.motor2_speed.get_value()
                    new_speed = max(0, current_speed + random.uniform(-3, 3))
                    self.motor2_speed.set_value(int(new_speed))
                    production_counter += random.randint(1, 2)
                
                # Update system information
                uptime_counter += 1
                self.uptime.set_value(uptime_counter)
                self.total_production.set_value(production_counter)
                
                time.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                print(f"Simulation error: {e}")
                break
    
    def start(self):
        """Start the OPC UA server"""
        try:
            self.server.start()
            print("OPC UA Server started at opc.tcp://localhost:4840/freeopcua/server/")
            print("Server is running. Press Ctrl+C to stop.")
            
            # Start simulation thread
            self.running = True
            self.simulation_thread = Thread(target=self.simulate_industrial_data)
            self.simulation_thread.daemon = True
            self.simulation_thread.start()
            
        except Exception as e:
            print(f"Failed to start server: {e}")
    
    def stop(self):
        """Stop the OPC UA server"""
        self.running = False
        if self.simulation_thread:
            self.simulation_thread.join(timeout=5)
        self.server.stop()
        print("Server stopped.")
if __name__ == "__main__":
    server = IndustrialOPCServer()
    
    try:
        server.start()
        # Keep the server running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()