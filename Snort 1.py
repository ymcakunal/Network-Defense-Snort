#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import pandas as pd
import re
import matplotlib.pyplot as plt
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email import encoders
from matplotlib.backends.backend_pdf import PdfPages

def update_logs(logs_file, new_logs_file):
    
    # Read the last timestamp from new_logs_file
    with open(new_logs_file, 'r') as f:
        last_timestamp = None
        for line in f:
            match = re.search(r'\d{2}/\d{2}-\d{2}:\d{2}:\d{2}.\d{6}', line)
            if match:
                last_timestamp = match.group()

    # Append logs after last_timestamp from logs_file to new_logs_file
    if last_timestamp:
        with open(logs_file, 'r') as f:
            logs = f.readlines()

        with open(new_logs_file, 'a') as f:
            write_logs = False
            for line in logs:
                match = re.search(r'\d{2}/\d{2}-\d{2}:\d{2}:\d{2}.\d{6}', line)
                if match:
                    if match.group() > last_timestamp:
                        write_logs = True
#                     elif match.group() <= last_timestamp:     # new added and below 1
                        
                    elif write_logs:
                        write_logs = False
                        
                if write_logs:
                    f.write(line)  # Ye Line add kar new logs to new file
                    
            


    # Clear new_logs_file before last_timestamp
        with open(new_logs_file, 'r') as f:
            lines = f.readlines()
            #print(lines)   # Ye Lines new log file se saari line jo add ho gyi hai vo dega

        with open(new_logs_file, 'w') as f:
            write_logs = True    # Ye line delete kar raha hai logs ko
            for line in lines:
                #print(line)  Yaha lines ko saari line mil rahi hai
                match = re.search(r'\d{2}/\d{2}-\d{2}:\d{2}:\d{2}.\d{6}', line)
                if match and match.group() > last_timestamp:
                    #print(match) # Yaha match ko sirf new log mil rahe hai
                    f.write(match.string)
#                     write_logs = True
                    
#                 if write_logs:
#                     f.write(line)


# Usage
update_logs("/var/log/snort/alert.log", "/var/log/snort/log.txt")

logs_path = r"/var/log/snort/log.txt"

# # Read the log file into a list
# with open(logs_path, 'r') as file:
#     logs = file.readlines()

# # Remove the top 40 lines from the logs list
# logs = logs[121:]

def analyze_log(log):
    # Perform analysis on the log and determine the severity level and other details
    # You can define your own logic here based on your specific criteria

    # Example logic to determine severity level
    if "Nmap TCP SYN scan detected" in log:
        attack_vector = 'Nmap Reconnasine'
        advice = 'Close your ports'
    elif "P2P BitTorrent transfer" in log:
        attack_vector = 'P2P'
        advice = 'Peer to Peer Removal'
    elif "BAD-TRAFFIC same SRC/DST" in log:
        attack_vector = 'Bad Traffic'
        advice = 'Reconnect your device'
    elif "ICMP" in log:
        attack_vector = "ICMP Attack"
        advice = "Close your Open Port"
    else:
        attack_vector=None
        advice=None  
    return attack_vector, advice



def extract_ip_timestamp(log):
    # Regular expression patterns to extract IP addresses and timestamp
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    timestamp_pattern = r'\d{2}/\d{2}-\d{2}:\d{2}:\d{2}.\d{6}'
    priority_pattern = r'Priority: (\d+)'
    protocol_pattern = r'{(\w+)}'
    # Extract timestamp
    timestamp_match = re.search(timestamp_pattern, log)
    timestamp = timestamp_match.group() if timestamp_match else None

    # Extract source IP
    source_ip_match = re.search(ip_pattern, log)
    source_ip = source_ip_match.group() if source_ip_match else None

    # Extract destination IP
    destination_ip_match = re.search(ip_pattern, log[source_ip_match.end():]) if source_ip_match else None
    destination_ip = destination_ip_match.group() if destination_ip_match else None
     # Extract priority
    priority_match = re.search(priority_pattern, log)
    print("Final Piroirty",priority_match)
    priority = int(priority_match.group(1)) if priority_match else None
    print("priority ::",priority,timestamp)
    max_priority = 0
    while True:
    # Get the priority value from user or any other source
    #priority = int(input("Enter priority value (or -1 to exit): "))
    	if priority == -1:
    	    break
    
    	if priority > max_priority:
    	    max_priority = priority
    
    	print("Priority set to:", max_priority,timestamp)

    print("Maximum priority value obtained:", max_priority)
     # Extract protocol
    protocol_match = re.search(protocol_pattern, log)
    protocol = protocol_match.group(1) if protocol_match else None

    return timestamp, source_ip, destination_ip,priority,protocol


# ------------------------------------------------------------------------------------------------------------------------------------------#


#priority = 0
#max_priority = 0

#while True:
    # Get the priority value from user or any other source
 #   priority = int(input("Enter priority value (or -1 to exit): "))
    
  #  if priority == -1:
   #     break
    
    #if priority > max_priority:
     #   max_priority = priority
    
   # print("Priority set to:", max_priority)

#print("Maximum priority value obtained:", max_priority)


# ------------------------------------------------------------------------------------------------------------------------------------------#

# # Read the log file into a list
with open(logs_path, 'r') as file:
    logs = file.readlines()

# # Remove the top 40 lines from the logs list
# logs = logs[121:]

# Analyze logs and extract IP addresses and timestamp
log_analyses = []
timestamps = []
source_ips = []
destination_ips = []
protocols = []
attack_vectors = []
advices = []
priority = []
ip_types = []  # List to store IP types (private or public)

for log in logs:
    # Analyze log
    attack_vector, advice = analyze_log(log)
    log_analyses.append(priority)

    # Extract timestamp, source IP, and destination IP
    timestamp, source_ip, destination_ip, priority, protocol = extract_ip_timestamp(log)
    timestamps.append(timestamp)
    source_ips.append(source_ip)
    destination_ips.append(destination_ip)
    
    # Extract protocol
    protocols.append(protocol)
    
    # Add attack vector and advice
    attack_vectors.append(attack_vector)
    advices.append(advice)
    
    # Determine IP type (private or public)
    if source_ip:
        if source_ip.startswith("192.") or source_ip.startswith("10."):
            ip_types.append("Private")
        else:
            ip_types.append("Public")
    else:
        ip_types.append(None)

# Create a DataFrame with the log details
data = {
    'Timestamp': timestamps,
    'Source IP': source_ips,
    'Destination IP': destination_ips,
    'Protocol': protocols,
    'Attack Vector': attack_vectors,
    'IP Type': ip_types,
    'Priority':priority,
}
df = pd.DataFrame(data)

# Set priority 1 logs to low severity level
df['Priority'] = log_analyses

# Reorder the columns
columns = ['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Attack Vector', 'IP Type', 'Priority']
df = df.reindex(columns=columns)

# Save the DataFrame to an Excel file
output_path = r'/var/log/snort/1.xlsx'
df.to_excel(output_path, index=False)
print(f"Report saved to: {output_path}")

# Create a PDF file and add the table and charts to it
pdf_path = r'/var/log/snort/1.pdf'
with PdfPages(pdf_path) as pdf:
    # Add custom header at the top of the first page
    fig, ax = plt.subplots(figsize=(12, 0.5))
    ax.axis('off')
    header_text = 'Empowering Network Defense: Threat Intelligence Insights with Snort3 NIDS'
    fig.text(0.5, 0.9, header_text, ha='center', fontsize=25, weight='bold')
    pdf.savefig(fig, bbox_inches='tight')
    plt.close()

    # Add table with header to the PDF
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.axis('off')
    table = ax.table(cellText=df.values, colLabels=df.columns, cellLoc='center', loc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1, 2)
    pdf.savefig(fig, bbox_inches='tight')
    plt.close()

    # Analyze IP addresses for pie chart
    ip_counts = df['Source IP'].value_counts()

    # Plot pie chart for all IP addresses
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.pie(ip_counts, labels=ip_counts.index, autopct='%1.1f%%')
    ax.set_title('Distribution of IP Addresses')
    ax.axis('equal')
    pdf.savefig(fig, bbox_inches='tight')
    plt.close()

    # Analyze IP types for pie chart
    ip_type_counts = df['IP Type'].value_counts()

    # Plot pie chart for IP types
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.pie(ip_type_counts, labels=ip_type_counts.index, autopct='%1.1f%%')
    ax.set_title('Distribution of IP Types')
    ax.axis('equal')
    pdf.savefig(fig, bbox_inches='tight')
    plt.close()

    # Analyze protocols for pie chart
    protocol_counts = df['Protocol'].value_counts()

    # Plot pie chart for protocols
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%')
    ax.set_title('Distribution of Protocols')
    ax.axis('equal')
    pdf.savefig(fig, bbox_inches='tight')
    plt.close()

    print(f"Report saved to: {pdf_path}")
    

# Send email if priority is equal to or greater than 4
if max_priority is not None and max_priority >= 4:
    print(priority) 
    # Sender and receiver email addresses
    sender_email = "example@gmail.com"
    receiver_email = "example@gmail.com"
    sender_password = 'fnidrg'

    # Email subject and body
    subject = "Network Security Report"
    body = "Please find the network security report attached."

    # Create a multipart message and set the headers
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    # Add body to the email
    message.attach(MIMEText(body, "plain"))

    # Open the file in bytestream mode
    with open(pdf_path, "rb") as attachment:
        # Add file as application/octet-stream
        # Email clients can usually download this automatically as an attachment
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())

    # Encode file in ASCII characters to send by email
    encoders.encode_base64(part)

    # Add header as key/value pair to attachment part
    part.add_header(
        "Content-Disposition",
        f"attachment; filename= {pdf_path}",
    )

    # Add attachment to message and convert message to string
    message.attach(part)
    text = message.as_string()

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, text)
        print("Email sent successfully!")
else:
    print("Priority is not equal to or greater than 4. Email not sent.")
    #print(Priority)
    
## ----------------------------------         Final Code ------------------------------------------------------------##

