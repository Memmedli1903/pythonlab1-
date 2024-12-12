import re
import json
import csv
from pathlib import Path

# Fayl yollarını təyin edirik
log_file_path = Path('server_logs.txt')  # Server loglarının saxlandığı faylın yolu
dangerous_ip_file_path = Path('index.html')  # Təhlükəli IP-lərin olduğu HTML faylın yolu

# Log faylını oxumaq
if log_file_path.is_file():  # Əgər log faylı mövcuddursa
    with log_file_path.open('r') as log_file:
        log_entries = log_file.readlines()  # Log faylının bütün sətirlərini oxuyuruq
else:
    raise FileNotFoundError(f"Log faylı tapılmadı: {log_file_path}")

# Təhlükəli IP-ləri əldə etmək
threat_ips = []  # Təhlükəli IP-lərin siyahısı
if dangerous_ip_file_path.is_file():  # Əgər HTML faylı mövcuddursa
    with dangerous_ip_file_path.open('r') as html_file:
        for line in html_file:  # Faylın hər bir sətrini oxuyuruq
            match = re.search(r'<td>(\d+\.\d+\.\d+\.\d+)</td>', line)  # Regex ilə IP-ləri tapırıq
            if match:
                threat_ips.append(match.group(1))  # Tapılan IP-ni siyahıya əlavə edirik
else:
    raise FileNotFoundError(f"HTML faylı tapılmadı: {dangerous_ip_file_path}")

# Loglardan məlumatları çıxarmaq üçün regex
def parse_log_entry(log):
    pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] \"(\w+) .+\" (\d+) .+'
    match = re.match(pattern, log)
    return match.groups() if match else None

parsed_logs = []  # Pars edilmiş log məlumatları
failed_attempts = {}  # Uğursuz girişlərin sayını saxlamaq üçün lüğət

for log_entry in log_entries:
    result = parse_log_entry(log_entry)
    if result:
        ip, date, method, status = result
        parsed_logs.append({"ip": ip, "date": date, "method": method, "status": status})
        if status == '401':  # Əgər uğursuz girişdirsə
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

# 5-dən çox uğursuz giriş edən IP-lər
frequent_failed_logins = {ip: count for ip, count in failed_attempts.items() if count > 5}

with open('frequent_failed_logins.json', 'w') as json_file:
    json.dump(frequent_failed_logins, json_file, indent=4)

# Təhlükəli IP-lərlə uyğunluq
matched_threat_ips = [entry for entry in parsed_logs if entry['ip'] in threat_ips]
with open('matched_threat_ips.json', 'w') as json_file:
    json.dump(matched_threat_ips, json_file, indent=4)

# Uğursuz girişləri və təhlükəli IP-ləri birləşdirmək
combined_data = {
    "frequent_failed_logins": frequent_failed_logins,
    "matched_threat_ips": matched_threat_ips
}
with open('security_report.json', 'w') as json_file:
    json.dump(combined_data, json_file, indent=4)

# Mətn faylına uğursuz girişlər yazmaq
with open('failed_logins_report.txt', 'w') as txt_file:
    for ip, count in failed_attempts.items():
        txt_file.write(f"IP: {ip}, Failed Attempts: {count}\n")

# CSV faylı yaratmaq
with open('log_analysis_report.csv', 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["IP", "Date", "Method", "Status", "Failed Attempts"])
    for log in parsed_logs:
        failed_count = failed_attempts.get(log['ip'], 0)
        csv_writer.writerow([log['ip'], log['date'], log['method'], log['status'], failed_count])

print('Proses uğurla tamamlandı')