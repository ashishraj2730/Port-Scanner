import nmap
import socket
import time
from datetime import datetime

print("=" * 60)
print("          ADVANCED PORT SCANNER USING NMAP")
print("=" * 60)

target = input("Enter Target IP/Hostname: ").strip()

try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print("\n[ERROR] Invalid Hostname/IP")
    exit()

port_range = input("Enter Port Range (Example: 1-1000): ").strip()

scanner = nmap.PortScanner()

print("\nScanning...")
start = time.time()

try:
    scanner.scan(
        hosts=target_ip,
        ports=port_range,
        arguments='-sV'
    )

except Exception as e:
    print("Scan Error:", e)
    exit()

end = time.time()

report = []

print("\n" + "=" * 60)
print(f"Target : {target_ip}")
print("=" * 60)

print("{:<8}{:<12}{:<18}{}".format(
    "PORT",
    "STATE",
    "SERVICE",
    "VERSION"
))

print("-" * 60)

open_ports = 0

for host in scanner.all_hosts():

    for proto in scanner[host].all_protocols():

        ports = scanner[host][proto].keys()

        for port in sorted(ports):

            state = scanner[host][proto][port]['state']

            if state == "open":

                service = scanner[host][proto][port]['name']

                version = scanner[host][proto][port].get('product', '')

                print("{:<8}{:<12}{:<18}{}".format(
                    port,
                    state.upper(),
                    service,
                    version
                ))

                report.append(
                    f"{port}\t{state}\t{service}\t{version}"
                )

                open_ports += 1

print("-" * 60)

print(f"Total Open Ports : {open_ports}")
print(f"Scan Time        : {end-start:.2f} Seconds")

filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

with open(filename, "w") as f:

    f.write("ADVANCED PORT SCANNER REPORT\n")
    f.write("=" * 50 + "\n")
    f.write(f"Target : {target_ip}\n")
    f.write(f"Date   : {datetime.now()}\n\n")

    f.write("PORT\tSTATE\tSERVICE\tVERSION\n")

    for line in report:
        f.write(line + "\n")

    f.write("\n")
    f.write(f"Total Open Ports : {open_ports}\n")
    f.write(f"Scan Time : {end-start:.2f} Seconds\n")

print(f"\nReport Saved : {filename}")
