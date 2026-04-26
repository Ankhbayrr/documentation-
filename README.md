# 🛡️ Wazuh → IRIS интеграц (Шинэчилсэн гарын авлага)

## 🎯 Зорилго

Энэхүү заавар нь Wazuh SIEM дээр үүссэн alert-уудыг **IRIS Incident Response System** рүү API ашиглан автоматаар илгээх бүрэн процессийг тайлбарлана.

---

# 🧱 Архитектур

```
Wazuh → Integration Script → IRIS API (/alerts/add) → IRIS Alerts
```

---

# 1️⃣ IRIS API Key авах

1. IRIS руу нэвтрэх

   ```
   https://SERVER_IP
   ```

2. Login хийх

3. **Settings → API Keys**

4. Шинэ API key үүсгэх

5. Copy хийх:

   ```
   YOUR_IRIS_API_KEY
   ```

---

# 2️⃣ IRIS API endpoint

ШИНЭ зөв endpoint:

```
POST https://SERVER_IP/alerts/add
```

Header:

```json
{
  "Authorization": "Bearer YOUR_IRIS_API_KEY",
  "Content-Type": "application/json"
}
```

---

# 3️⃣ Curl ашиглан тест хийх (ШАЛГАХ)

Доорх нь **баталгаатай ажиллах payload**:

```bash
curl -k -X POST "https://192.168.1.149/alerts/add" \
  -H "Authorization: Bearer YOUR_IRIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_title": "Wazuh Alert - CIS Ubuntu Linux",
    "alert_description": "Ensure inactive password lock is configured.",
    "alert_source": "Wazuh",
    "alert_source_ref": "1776860982.803392",
    "alert_source_link": "",
    "alert_source_content": {
      "rule_id": "19007",
      "rule_level": 7,
      "agent_name": "ankhaa-Vitualbox",
      "decoder": "sca",
      "result": "failed"
    },
    "alert_severity_id": 3,
    "alert_status_id": 3,
    "alert_context": {
      "source": "wazuh",
      "type": "sca"
    },
    "alert_source_event_time": "2026-04-22T20:29:42",
    "alert_note": "Auto from Wazuh",
    "alert_tags": "wazuh,sca",
    "alert_iocs": [],
    "alert_assets": [
      {
        "asset_name": "ankhaa-Vitualbox",
        "asset_description": "Linux host",
        "asset_type_id": 1,
        "asset_ip": "",
        "asset_domain": "",
        "asset_tags": "linux,wazuh",
        "asset_enrichment": {}
      }
    ],
    "alert_customer_id": 1,
    "alert_classification_id": 1
  }'
```

---

# 4️⃣ Wazuh Integration Script

Файл үүсгэх:

```bash
nano /var/ossec/integrations/custom-iris
```

---

## 📌 Python Script (ШИНЭ)

```python
#!/usr/bin/env python3

import sys
import json
import requests
from datetime import datetime, UTC

API_URL = "https://192.168.1.149/alerts/add"
API_KEY = "YOUR_IRIS_API_KEY"

# alert унших (last line fix)
with open(sys.argv[1], "r") as f:
    lines = [l.strip() for l in f if l.strip()]
    alert = json.loads(lines[-1])

rule = alert.get("rule", {})
agent = alert.get("agent", {})
data = alert.get("data", {})
sca = data.get("sca", {})
check = sca.get("check", {})

# severity mapping (IRIS)
level = rule.get("level", 0)
if level >= 12:
    severity = 4
elif level >= 8:
    severity = 3
elif level >= 5:
    severity = 2
else:
    severity = 1

payload = {
    "alert_title": rule.get("description"),
    "alert_description": check.get("description", "Wazuh alert"),
    "alert_source": "Wazuh",
    "alert_source_ref": alert.get("id"),
    "alert_source_link": "",
    "alert_source_content": {
        "rule_id": rule.get("id"),
        "rule_level": level,
        "agent_name": agent.get("name"),
        "decoder": alert.get("decoder", {}).get("name"),
        "result": check.get("result")
    },
    "alert_severity_id": severity,
    "alert_status_id": 3,
    "alert_context": {
        "source": "wazuh",
        "type": "sca"
    },
    "alert_source_event_time": alert.get("timestamp"),
    "alert_note": "Auto from Wazuh",
    "alert_tags": "wazuh,sca",
    "alert_iocs": [],
    "alert_assets": [
        {
            "asset_name": agent.get("name"),
            "asset_description": "Wazuh monitored host",
            "asset_type_id": 1,
            "asset_ip": agent.get("ip", ""),
            "asset_domain": "",
            "asset_tags": "linux,wazuh",
            "asset_enrichment": {}
        }
    ],
    "alert_customer_id": 1,
    "alert_classification_id": 1
}

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

requests.post(API_URL, json=payload, headers=headers, verify=False)
```

---

# 5️⃣ Permission

```bash
chmod 750 /var/ossec/integrations/custom-iris
chown root:wazuh /var/ossec/integrations/custom-iris
```

---

# 6️⃣ ossec.conf тохируулах

```xml
<integration>
  <name>custom-iris</name>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
```

---

# 7️⃣ Restart

```bash
systemctl restart wazuh-manager
```

---

# 8️⃣ Тест хийх

```bash
tail -n 1 /var/ossec/logs/alerts/alerts.json > /tmp/test.json

python3 /var/ossec/integrations/custom-iris /tmp/test.json dummy dummy
```

---

# 9️⃣ Амжилт шалгах

IRIS → **Alerts хэсэгт шинэ alert гарсан байна**

---

# ⚠️ Алдаа засах

## 415 Unsupported Media Type

➡ JSON буруу
➡ Header буруу
➡ newline орсон

---

## 401 Unauthorized

➡ API key буруу

---

## Alert ирэхгүй

➡ level бага
➡ integration ажиллахгүй

---

# 🚀 Дүгнэлт

Та одоо:

* Wazuh → IRIS интеграц хийсэн
* Автомат alert pipeline үүсгэсэн
* SOC workflow ашиглах боломжтой болсон

---

Хэрвээ дараагийн шат руу явбал:
👉 IRIS дээр **case auto-create + playbook automation + SOAR integration** хийж болно
