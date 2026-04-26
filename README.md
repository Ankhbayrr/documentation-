# Wazuh → DFIR-IRIS Холболтын Бүрэн Заавар

## Товч танилцуулга

Энэхүү заавар нь Wazuh SIEM системээс үүссэн alert-уудыг DFIR-IRIS Incident Response платформ руу автоматаар илгээх custom integration хэрхэн хийхийг тайлбарлана.

Энэ интеграцийн зорилго:

- SIEM → Incident Response автомат урсгал үүсгэх
- Alert triage процессыг хурдасгах
- SOC workflow-ийг бодит орчинд ойртуулах

---

## Архитектур

```text
[ Wazuh Manager ]
        ↓
[ custom-iris.py ]
        ↓
[ IRIS API (/alerts/add) ]
        ↓
[ IRIS Alert Dashboard ]
```

---

## 1. Script байршуулах

### Файл үүсгэх

```bash
sudo nano /var/ossec/integrations/custom-iris.py
```

### Permission тохируулах

```bash
sudo chmod 750 /var/ossec/integrations/custom-iris.py
sudo chown root:wazuh /var/ossec/integrations/custom-iris.py
```

> Анхаарах: Permission буруу байвал Wazuh integration script ажиллуулахгүй.

---

## 2. Python орчин бэлтгэх

```bash
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install requests
```

`requests` module суусан эсэхийг шалгах:

```bash
python3 -c "import requests; print('OK')"
```

Хэрэв `OK` гэж хэвлэгдэж байвал Python орчин бэлэн байна.

---

## 3. Integration Script

Доорх script нь Wazuh alert JSON уншиж, severity mapping хийж, DFIR-IRIS API руу alert илгээнэ.

`/var/ossec/integrations/custom-iris.py` файл дотор дараах кодыг хадгална:

```python
#!/usr/bin/env python3
import sys
import json
import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        f"Rule Description: {rule.get('description', 'N/A')}",
        f"Agent ID: {agent.get('id', 'N/A')}",
        f"Agent Name: {agent.get('name', 'N/A')}",
        f"Agent IP: {agent.get('ip', 'N/A')}",
        f"MITRE IDs: {mitre_ids}",
        f"MITRE Tactics: {mitre_tactics}",
        f"MITRE Techniques: {mitre_techniques}",
        f"Location: {alert_json.get('location', 'N/A')}",
        f"Full Log: {alert_json.get('full_log', 'N/A')}"
    ]

    return "\n".join(details)


def map_severity(level):
    try:
        level = int(level)
    except Exception:
        return 1

    if level < 5:
        return 2
    elif 5 <= level < 7:
        return 3
    elif 7 <= level < 10:
        return 4
    elif 10 <= level < 13:
        return 5
    elif level >= 13:
        return 6

    return 1


def main():
    if len(sys.argv) < 4:
        print("Usage: custom-iris.py <alert_file> <api_key> <hook_url>")
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    try:
        with open(alert_file, "r") as f:
            alert = json.load(f)
    except Exception as e:
        print(f"Failed to read alert file: {e}")
        sys.exit(1)

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    payload = {
        "alert_title": rule.get("description", "Wazuh Alert"),
        "alert_description": format_alert_details(alert),
        "alert_source": "Wazuh",
        "alert_source_ref": alert.get("id", "unknown"),
        "alert_source_link": "",
        "alert_source_content": {
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "agent_ip": agent.get("ip"),
            "location": alert.get("location"),
            "decoder": alert.get("decoder", {}).get("name"),
            "full_log": alert.get("full_log"),
            "timestamp": alert.get("timestamp"),
            "raw_alert": alert
        },
        "alert_severity_id": map_severity(rule.get("level")),
        "alert_status_id": 3,
        "alert_context": {
            "source": "wazuh",
            "type": "siem_alert",
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "agent_name": agent.get("name"),
            "agent_id": agent.get("id"),
            "location": alert.get("location")
        },
        "alert_source_event_time": alert.get("timestamp"),
        "alert_note": "",
        "alert_tags": f"wazuh,{agent.get('name', 'unknown')}",
        "alert_customer_id": 1
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            hook_url,
            headers=headers,
            json=payload,
            verify=False,
            timeout=10
        )

        if response.status_code not in [200, 201]:
            print(f"IRIS API error: {response.status_code}")
            print(response.text)
            sys.exit(1)

        print("Alert successfully sent to DFIR-IRIS")

    except Exception as e:
        print(f"Failed to send alert to DFIR-IRIS: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 4. Wazuh тохиргоо хийх

Wazuh manager тохиргооны файлыг нээнэ:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Дараах integration хэсгийг нэмнэ:

```xml
<integration>
  <name>custom-iris.py</name>
  <hook_url>https://IRIS-IP/alerts/add</hook_url>
  <api_key>YOUR_API_KEY</api_key>
  <alert_format>json</alert_format>
  <level>3</level>
</integration>
```

Жишээ:

```xml
<integration>
  <name>custom-iris.py</name>
  <hook_url>https://192.168.1.149/alerts/add</hook_url>
  <api_key>YOUR_IRIS_API_KEY</api_key>
  <alert_format>json</alert_format>
  <level>3</level>
</integration>
```

> `IRIS-IP` болон `YOUR_API_KEY` хэсгийг өөрийн орчны бодит мэдээллээр солино.

---

## 5. Wazuh restart хийх

### Systemd орчин

```bash
sudo systemctl restart wazuh-manager
```

Статус шалгах:

```bash
sudo systemctl status wazuh-manager
```

### Docker орчин

```bash
docker compose restart wazuh.manager
```

эсвэл container нэрээр:

```bash
docker restart wazuh.manager
```

---

## 6. Гар тест хийх

### Test JSON үүсгэх

```bash
nano /tmp/test-alert.json
```

Дараах test alert-ийг хадгална:

```json
{
  "id": "test-001",
  "timestamp": "2026-04-26T04:21:20Z",
  "rule": {
    "id": "100001",
    "level": 7,
    "description": "Test Wazuh Alert",
    "mitre": {
      "id": ["T1078"],
      "tactic": ["Defense Evasion"],
      "technique": ["Valid Accounts"]
    }
  },
  "agent": {
    "id": "001",
    "name": "lab-agent",
    "ip": "192.168.1.10"
  },
  "decoder": {
    "name": "test-decoder"
  },
  "location": "test-location",
  "full_log": "This is a test Wazuh alert for DFIR-IRIS integration"
}
```

### Script ажиллуулах

```bash
python3 /var/ossec/integrations/custom-iris.py \
/tmp/test-alert.json \
"YOUR_API_KEY" \
"https://IRIS-IP/alerts/add"
```

Амжилттай бол дараах message гарна:

```text
Alert successfully sent to DFIR-IRIS
```

---

## 7. IRIS API-г curl ашиглан шалгах

Script-ээс тусдаа API endpoint зөв ажиллаж байгаа эсэхийг шалгах:

```bash
curl -k -X POST "https://IRIS-IP/alerts/add" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_title": "Manual Wazuh Test Alert",
    "alert_description": "Manual API test from curl",
    "alert_source": "Wazuh",
    "alert_source_ref": "manual-test-001",
    "alert_source_link": "",
    "alert_source_content": {
      "rule_id": "100001",
      "rule_level": 7,
      "agent_name": "lab-agent"
    },
    "alert_severity_id": 4,
    "alert_status_id": 3,
    "alert_context": {
      "source": "wazuh",
      "type": "manual_test"
    },
    "alert_customer_id": 1
  }'
```

---

## 8. Troubleshooting

### 8.1 Wazuh integration log шалгах

```bash
sudo tail -f /var/ossec/logs/ossec.log
```

Docker ашиглаж байгаа бол:

```bash
docker logs -f wazuh.manager
```

---

### 8.2 Script permission алдаа

Шинж тэмдэг:

```text
Permission denied
```

Засах:

```bash
sudo chmod 750 /var/ossec/integrations/custom-iris.py
sudo chown root:wazuh /var/ossec/integrations/custom-iris.py
```

---

### 8.3 Python `requests` module байхгүй

Шинж тэмдэг:

```text
ModuleNotFoundError: No module named 'requests'
```

Засах:

```bash
pip3 install requests
```

эсвэл:

```bash
sudo apt install -y python3-requests
```

---

### 8.4 IRIS 401 Unauthorized

Шалтгаан:

- API key буруу
- API key copy хийхдээ дутуу хуулсан
- `Authorization: Bearer` header буруу дамжсан

Шалгах:

```bash
curl -k -H "Authorization: Bearer YOUR_API_KEY" https://IRIS-IP/
```

---

### 8.5 IRIS 400 Bad Request

Шалтгаан нь ихэвчлэн required field дутуу байдаг.

Заавал байх ёстой field-үүд:

```text
alert_title
alert_description
alert_source
alert_source_ref
alert_severity_id
alert_status_id
alert_customer_id
```

---

### 8.6 SSL certificate алдаа

Self-signed HTTPS certificate ашиглаж байгаа үед SSL алдаа гарч болно.

Энэ script дээр дараах тохиргоо ашигласан:

```python
verify=False
```

Мөн warning дарахын тулд:

```python
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

> Production орчинд боломжтой бол valid TLS certificate ашиглах нь зөв.

---

### 8.7 Wazuh alert ирэхгүй байх

Дараах зүйлсийг шалгана:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

Хэрэв alert өөрөө үүсэхгүй байвал integration script ажиллахгүй. Эхлээд Wazuh alert generation зөв эсэхийг шалгана.

---

## 9. Severity Mapping

Wazuh rule level-ийг IRIS severity ID руу дараах байдлаар map хийж байна:

| Wazuh Rule Level | IRIS Severity ID | Тайлбар |
|---|---:|---|
| 0–4 | 2 | Low |
| 5–6 | 3 | Medium |
| 7–9 | 4 | High |
| 10–12 | 5 | Critical |
| 13–15 | 6 | Very Critical |
| Unknown | 1 | Informational |

---

## 10. SOC workflow дээр ашиглах

Энэхүү integration нь дараах SOC workflow-д ашиглагдана:

```text
Detection → Alert Forwarding → IRIS Triage → Investigation → Case Management → Reporting
```

Жишээ use-case:

- SSH brute-force илэрвэл IRIS дээр alert үүсэх
- Malware detection илэрвэл analyst triage хийх
- Privilege escalation alert илэрвэл incident response workflow эхлэх
- CIS compliance failure илэрвэл ticket/case болгон хянах

---

## 11. Баталгаажуулах checklist

Доорх checklist-ээр тохиргоогоо шалгана:

- [ ] `custom-iris.py` файл зөв зам дээр байгаа
- [ ] Script executable permission-тэй байгаа
- [ ] Owner нь `root:wazuh`
- [ ] `requests` module суусан
- [ ] `ossec.conf` дотор integration зөв нэмэгдсэн
- [ ] IRIS API key зөв
- [ ] IRIS URL зөв
- [ ] Wazuh manager restart хийсэн
- [ ] `/var/ossec/logs/ossec.log` дээр integration error байхгүй
- [ ] Test alert IRIS дээр харагдаж байгаа

---

## 12. Дүгнэлт

Энэхүү тохиргоог хийснээр Wazuh SIEM дээр үүссэн alert-ууд DFIR-IRIS платформ руу автоматаар дамжиж, SOC analyst alert triage болон incident response ажиллагааг илүү төвлөрсөн байдлаар гүйцэтгэх боломжтой болно.

Үндсэн үр дүн:

- SIEM alert автоматаар IRIS руу орно
- Analyst triage хурдан болно
- Incident tracking төвлөрнө
- SOC сургалт болон бодит blue-team ажиллагаанд ашиглах боломжтой

---

## 13. Дараагийн сайжруулалт

Цаашид дараах боломжуудыг нэмэх боломжтой:

- Auto case creation
- Analyst auto-assignment
- MITRE ATT&CK mapping enrichment
- Threat intelligence enrichment
- SOAR playbook trigger
- Telegram эсвэл Discord notification
- IRIS case template автомат бөглөх
