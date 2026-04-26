# Wazuh → DFIR-IRIS Холболтын Бүрэн Заавар

## Товч танилцуулга

Энэхүү заавар нь :contentReference[oaicite:0]{index=0} системээс үүссэн alert-уудыг :contentReference[oaicite:1]{index=1} рүү автоматаар илгээх custom integration хэрхэн хийхийг тайлбарлана.

Энэ интеграцийн зорилго:
- SIEM → Incident Response автомат урсгал үүсгэх
- Alert triage процессыг хурдасгах
- SOC workflow-ийг бодит орчинд ойртуулах

---

## Архитектур
[ Wazuh Manager ]
↓
[ custom-iris.py ]
↓
[ IRIS API (/alerts/add) ]
↓
[ IRIS Alert Dashboard ]


---

## 1. Script байршуулах

### Файл зам

```bash
/var/ossec/integrations/custom-iris.py

Permission тохиргоо
sudo chmod 750 /var/ossec/integrations/custom-iris.py
sudo chown root:wazuh /var/ossec/integrations/custom-iris.py

⚠️ Хэрэв permission буруу бол Wazuh script ажиллуулахгүй

2. Python орчин бэлтгэх
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install requests

Шалгах:

python3 -c "import requests; print('OK')"
3. Integration Script (custom-iris.py)

Доорх script нь:

Wazuh alert JSON уншина
Severity map хийнэ
IRIS API руу POST request илгээнэ
#!/usr/bin/env python3
import sys
import json
import requests


def format_alert_details(alert_json):
    rule = alert_json.get("rule", {})
    agent = alert_json.get("agent", {})
    mitre = rule.get("mitre", {})

    mitre_ids = ", ".join(mitre.get("id", ["N/A"]))
    mitre_tactics = ", ".join(mitre.get("tactic", ["N/A"]))
    mitre_techniques = ", ".join(mitre.get("technique", ["N/A"]))

    details = [
        f"Rule ID: {rule.get('id', 'N/A')}",
        f"Rule Level: {rule.get('level', 'N/A')}",
        f"Description: {rule.get('description', 'N/A')}",
        f"Agent: {agent.get('name', 'N/A')}",
        f"MITRE: {mitre_ids}",
        f"Location: {alert_json.get('location', 'N/A')}",
        f"Log: {alert_json.get('full_log', 'N/A')}"
    ]

    return "\\n".join(details)


def map_severity(level):
    try:
        level = int(level)
    except:
        return 1

    if level < 5:
        return 2
    elif level < 7:
        return 3
    elif level < 10:
        return 4
    elif level < 13:
        return 5
    else:
        return 6


def main():
    if len(sys.argv) < 4:
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    with open(alert_file) as f:
        alert = json.load(f)

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    payload = {
        "alert_title": rule.get("description"),
        "alert_description": format_alert_details(alert),
        "alert_source": "Wazuh",
        "alert_source_ref": alert.get("id"),
        "alert_source_link": "",
        "alert_source_content": alert,
        "alert_severity_id": map_severity(rule.get("level")),
        "alert_status_id": 3,
        "alert_context": {
            "source": "wazuh",
            "type": "siem_alert"
        },
        "alert_source_event_time": alert.get("timestamp"),
        "alert_tags": f"wazuh,{agent.get('name')}",
        "alert_customer_id": 1
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    requests.post(hook_url, json=payload, headers=headers, verify=False)


if __name__ == "__main__":
    main()
4. Wazuh тохиргоо

Файл нээх:

sudo nano /var/ossec/etc/ossec.conf

Дараах хэсгийг нэмнэ:

<integration>
  <name>custom-iris.py</name>
  <hook_url>https://IRIS-IP/alerts/add</hook_url>
  <api_key>YOUR_API_KEY</api_key>
  <alert_format>json</alert_format>
  <level>3</level>
</integration>
5. Service restart
sudo systemctl restart wazuh-manager

Docker:

docker compose restart wazuh.manager
6. Гар тест хийх
Test JSON үүсгэх
nano /tmp/test.json
{
  "id": "test-001",
  "timestamp": "2026-04-26T04:21:20Z",
  "rule": {
    "id": "100001",
    "level": 7,
    "description": "Test Alert"
  },
  "agent": {
    "id": "001",
    "name": "lab-agent",
    "ip": "192.168.1.10"
  }
}
Script ажиллуулах
python3 /var/ossec/integrations/custom-iris.py \
/tmp/test.json \
"API_KEY" \
"https://IRIS-IP/alerts/add"
7. Troubleshooting (маш чухал)
1. Script ажиллахгүй
tail -f /var/ossec/logs/ossec.log
2. IRIS руу хүрэхгүй
curl -k https://IRIS-IP/alerts/add
3. 401 Unauthorized

✔ API key буруу

4. 400 Bad Request

✔ Дараах field-үүд дутуу:

alert_title
alert_description
alert_source
alert_severity_id
alert_status_id
alert_customer_id
5. Script permission алдаа
chmod 750 custom-iris.py
chown root:wazuh custom-iris.py
6. requests module байхгүй
pip3 install requests
8. SOC workflow дээрх ашиглалт

Энэхүү интеграци нь:

Alert → IRIS case creation автомат болгоно
Analyst triage хурдан болно
Incident tracking төвлөрнө

Use-case:

Brute-force attack → IRIS alert
Malware detection → IRIS case
Privilege escalation → SOC triage
9. Дүгнэлт

Энэ integration хийснээр:

✔ SIEM → IR автомат урсгал
✔ SOC ажиллагаа хурдасна
✔ Incident management сайжирна

Next Step (advanced)
Auto case creation
Playbook trigger
SOAR integration
Threat intel enrichment

---

