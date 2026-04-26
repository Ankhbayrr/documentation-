# Wazuh → DFIR-IRIS Холболтын Заавар

## Товч тайлбар

Энэхүү заавар нь Wazuh SIEM системээс гарсан alert-уудыг DFIR-IRIS систем рүү custom Python script ашиглан илгээхийг тайлбарлана.

---

## Архитектур

Wazuh → Custom Script → IRIS API

---

## 1. Script байрлуулах

Зам:
/var/ossec/integrations/custom-iris.py

Permission тохируулах:

sudo chmod 750 /var/ossec/integrations/custom-iris.py
sudo chown root:wazuh /var/ossec/integrations/custom-iris.py

---

## 2. Python шаардлага

sudo apt update
sudo apt install -y python3 python3-pip
pip3 install requests

---

## 3. Script

(Өмнөх хэсэгт өгсөн Python кодыг ашиглана)

---

## 4. Wazuh тохиргоо

Файл:
/var/ossec/etc/ossec.conf

Дараахыг нэмнэ:

<integration>
  <name>custom-iris.py</name>
  <hook_url>https://IRIS-IP/alerts/add</hook_url>
  <api_key>YOUR_API_KEY</api_key>
  <alert_format>json</alert_format>
  <level>3</level>
</integration>

---

## 5. Wazuh restart

sudo systemctl restart wazuh-manager

Docker:

docker compose restart wazuh.manager

---

## 6. Гар тест

python3 custom-iris.py /tmp/test.json API_KEY https://IRIS-IP/alerts/add

---

## 7. Алдаа шалгах

Лог харах:

tail -f /var/ossec/logs/ossec.log

API тест:

curl -k -X POST https://IRIS-IP/alerts/add -H "Authorization: Bearer API_KEY" -H "Content-Type: application/json"

---

## 8. Нийтлэг алдаа

Permission алдаа:

chmod 750 custom-iris.py

requests module байхгүй:

pip3 install requests

401 алдаа:

API key буруу

400 алдаа:

Шаардлагатай field дутуу:
- alert_title
- alert_description
- alert_source
- alert_source_ref
- alert_severity_id
- alert_status_id
- alert_customer_id

---

## Үр дүн

Амжилттай тохируулсны дараа:

- Wazuh alert-ууд IRIS дээр автоматаар орно
- SOC analyst шууд triage хийх боломжтой
