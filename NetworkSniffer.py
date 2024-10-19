import socket
import struct
from ctypes import *
from colorama import Fore, Style, init
import time

init()

class IPHeader(Structure):
    _fields_ = [
        ("ihl",              c_ubyte, 4),
        ("version",          c_ubyte, 4),
        ("tos",              c_ubyte),
        ("len",              c_ushort),
        ("id",               c_ushort),
        ("offset",           c_ushort),
        ("ttl",              c_ubyte),
        ("protocol_num",     c_ubyte),
        ("sum",              c_ushort),
        ("src",              c_uint32),
        ("dst",              c_uint32)
    ]

    def __new__(self, data=None):
        return self.from_buffer_copy(data)

    def __init__(self, data=None):
        if data:
            self.source_ip = socket.inet_ntoa(struct.pack("@I", self.src))
            self.destination_ip = socket.inet_ntoa(struct.pack("@I", self.dst))
            self.protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
            self.protocol = self.protocols.get(self.protocol_num, str(self.protocol_num))

def conn():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.bind(("0.0.0.0", 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return sock
    except Exception as e:
        print(f"Error creating socket: {e}")
        exit(1)

def print_ascii_art():
    ascii_art = f"""
    {Fore.CYAN}
  _    _            _    _   _      _   
 | |  | |          | |  | \\ | |    | |  
 | |__| | __ _  ___| | _|  \\| | ___| |_     {Fore.RED}
 |  __  |/ _` |/ __| |/ / . ` |/ _ \\ __|
 | |  | | (_| | (__|   <| |\\  |  __/ |_ 
 |_|  |_|\\__,_|\\___|_|\\_\\_| \\_|\\___|\\__|
                                       
    {Style.RESET_ALL}
    """
    print(ascii_art)

def print_help_menu():
    help_text = f"""
    {Fore.CYAN}
    ===============================
             Help Menu
    ===============================
    
    {Fore.YELLOW}Description:{Style.RESET_ALL}
    This packet sniffer captures network packets based on user-defined criteria.
    
    {Fore.YELLOW}Options to Capture Packets:{Style.RESET_ALL}
    1. {Fore.GREEN}TCP:{Style.RESET_ALL} Capture TCP packets.
    2. {Fore.GREEN}UDP:{Style.RESET_ALL} Capture UDP packets.
    3. {Fore.GREEN}ICMP:{Style.RESET_ALL} Capture ICMP packets.
    4. {Fore.GREEN}All packets:{Style.RESET_ALL} Capture all types of packets.

    {Fore.YELLOW}Controls:{Style.RESET_ALL}
    - Start the sniffer by selecting the desired option from the menu.
    - Press Ctrl+C to stop capturing packets.
    - If no packets are captured in the last 15 seconds, the sniffer will automatically exit.

    {Fore.YELLOW}Log File:{Style.RESET_ALL}
    - Captured packet details are saved in "captured_packets.log".
    
    {Fore.CYAN}===============================
    {Style.RESET_ALL}
    """
    print(help_text)
def get_user_choice():
    print("\nSelect the type of packets to capture:")
    print("1. TCP")
    print("2. UDP")
    print("3. ICMP")
    print("4. All packets")
    print("5. Help")

    choice = input("Enter your choice (1-5): ")
    
    if choice == '1':
        return socket.IPPROTO_TCP
    elif choice == '2':
        return socket.IPPROTO_UDP
    elif choice == '3':
        return socket.IPPROTO_ICMP
    elif choice == '4':
        return socket.IPPROTO_IP 
    elif choice == '5':
        print_help_menu()
        return get_user_choice()  # Allow the user to choose again
    else:
        print(f"{Fore.YELLOW}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
        return get_user_choice()

def main():
    print_ascii_art()
    protocol_choice = get_user_choice()
    sniffer = conn()
    
    log_file = open("captured_packets.log", "w")
    print(f"{Fore.GREEN}Sniffer Started! Press Ctrl+C to stop.{Style.RESET_ALL}\n")
    
    start_time = time.time() 
    packet_found = False 

    try:
        while True:
            raw_pack = sniffer.recvfrom(65535)[0]
            ip_header = IPHeader(raw_pack[0:20])
            packet_size = len(raw_pack)  
            
            if ip_header.protocol_num == protocol_choice or protocol_choice == socket.IPPROTO_IP:
                packet_found = True
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                packet_info = (
                    f"[{timestamp}] Protocol: {ip_header.protocol} | "
                    f"Source: {ip_header.source_ip} | "
                    f"Destination: {ip_header.destination_ip} | "
                    f"Size: {packet_size} bytes\n"
                )
                
                print(f"{Fore.YELLOW}{packet_info}{Style.RESET_ALL}")
                
                log_file.write(packet_info)
                log_file.flush()
                
                start_time = time.time()
            
            if time.time() - start_time > 15 and not packet_found:
                print(f"{Fore.YELLOW}No packets captured in the last 15 seconds. Exiting...{Style.RESET_ALL}")
                break
                
    except KeyboardInterrupt:
        if not packet_found:
            print(f"{Fore.YELLOW}No packets captured.{Style.RESET_ALL}")
        print("\nExiting...")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
    finally:
        log_file.close()  
        try:
            sniffer.close()
        except Exception as e:
            print(f"{Fore.RED}Error closing socket: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
