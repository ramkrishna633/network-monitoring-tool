# Network Monitor (netmon.py)

A Python-based network monitoring tool that:
- Captures network activity in real-time  
- Logs data to a CSV file for analysis  
- Scans open ports  
- Detects SSH login attempts  

## Usage
```bash
python netmon.py -i "Wi-Fi 2" --log netmon_log.csv --scan-ports 20 --scan-window 10 --ssh-window 20 --ssh-attempts 15
