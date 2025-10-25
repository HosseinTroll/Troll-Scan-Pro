# 🛡️ Troll-Scan-Pro

ابزار اسکن امنیتی دامنه با قابلیت‌های پیشرفته برای تحلیل و بررسی اطلاعات عمومی وب‌سایت‌ها.  
این اسکریپت با زبان پایتون نوشته شده و مناسب برای علاقه‌مندان به امنیت سایبری، تست نفوذ، و تحلیل دامنه‌هاست.

---

## 🚀 قابلیت‌ها

- 🔍 دریافت اطلاعات WHOIS و IP دامنه
- 🔐 بررسی گواهی SSL و جزئیات امنیتی
- 🌐 استخراج رکوردهای DNS (A, MX, NS, TXT)
- 🔎 اسکن پورت‌های رایج (21, 22, 80, 443, 8080)
- 🧠 تحلیل متادیتا صفحات HTML
- 🧨 حالت Deep Scan برای بررسی آسیب‌پذیری‌ها از طریق CVE API

---

## ⚙️ نصب در ترموکس

```bash
pkg install jq -y
git clone https://github.com/HosseinTroll/Troll-Scan-Pro.git
cd Troll-Scan-Pro
python Troll-Scan.py --url target.com --deep
-----------
  [ وقتی خروجی به این شکل نمایش داده شد :
reports/target-20251025-184046.json
 یعنی گزارش آماده دریافت است ✅️
-
pkg install jq -y
jq . reports/target.ir-20251025-184046.json
