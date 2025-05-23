# SSH Cracker

ابزاری قدرتمند برای تست اتصالات SSH که با زبان Go نوشته شده است. این ابزار به شما امکان می‌دهد تا اتصالات SSH را با ترکیبات مختلف نام کاربری/رمز عبور در برابر لیستی از آدرس‌های IP آزمایش کنید.

## ⚠️ هشدار

این ابزار فقط برای اهداف آموزشی و تست است. همیشه قبل از تست هر اتصال SSH، اطمینان حاصل کنید که مجوز لازم را دارید. نویسنده مسئول سوء استفاده از این ابزار نیست.

## 🚀 ویژگی‌ها

- تست چند نخی اتصالات SSH
- پشتیبانی از ترکیبات چندگانه نام کاربری/رمز عبور
- نمایش پیشرفت در زمان واقعی
- یکپارچه‌سازی با Discord برای اتصالات موفق
- پشتیبانی از چند پلتفرم (ویندوز و لینوکس)
- سیستم لایسنس برای کنترل دسترسی

## 📋 پیش‌نیازها

- Go نسخه 1.16 یا بالاتر
- Python نسخه 3.7 یا بالاتر (برای سرور لایسنس)
- Git

### وابستگی‌های پایتون

سرور لایسنس به پکیج‌های پایتون زیر نیاز دارد:
```bash
pip install flask
```

### وابستگی‌های Go

پروژه از پکیج‌های Go زیر استفاده می‌کند:
- `golang.org/x/crypto/ssh` - برای مدیریت اتصالات SSH

برای نصب وابستگی‌ها:
```bash
go mod download
```

## 🛠️ نصب

### 1. کلون کردن مخزن

```bash
git clone https://github.com/Matrix-Community-ORG/SSHCracker.git
cd SSHCracker
```

### 2. پیکربندی سرور لایسنس

1. فایل `app.py` را ویرایش کنید و رمز عبور ادمین را تنظیم کنید:
```python
PASSWORD = 'YOUR_ADMIN_PASSWORD'  # این را به یک رمز عبور امن تغییر دهید
```

2. سرور لایسنس را اجرا کنید:
```bash
python app.py
```

### 3. ساخت SSH Cracker

#### برای لینوکس:
```bash
go build -o ssh-cracker ssh.go
```

#### برای ویندوز:
```bash
go build -o ssh-cracker.exe ssh.go
```

## 🔧 پیکربندی

قبل از اجرای ابزار، باید چند مورد را پیکربندی کنید:

1. فایل `ssh.go` را ویرایش کنید و ثابت‌های زیر را به‌روزرسانی کنید:
```go
const (
    APIEndpoint = "http://your-api-endpoint.com:8000/check-license"
    WebhookURL  = "https://discord.com/api/webhooks/your-webhook-url"
)
```

2. لیست‌های نام کاربری و رمز عبور خود را ایجاد کنید:
   - یک فایل با نام‌های کاربری (هر خط یک نام کاربری)
   - یک فایل با رمزهای عبور (هر خط یک رمز عبور)

## 🚀 نحوه استفاده

1. برنامه را اجرا کنید:
```bash
# لینوکس
./ssh-cracker

# ویندوز
ssh-cracker.exe
```

2. در هنگام درخواست:
   - کلید لایسنس خود را وارد کنید
   - مسیر فایل لیست نام‌های کاربری را وارد کنید
   - مسیر فایل لیست رمزهای عبور را وارد کنید
   - مسیر فایل لیست IP را وارد کنید
   - مقدار تایم‌اوت را تنظیم کنید (به ثانیه)
   - حداکثر تعداد اتصالات همزمان را تنظیم کنید

3. برنامه:
   - یک فایل ترکیبی از نام‌های کاربری و رمزهای عبور ایجاد می‌کند
   - شروع به تست اتصالات SSH می‌کند
   - پیشرفت را در زمان واقعی نمایش می‌دهد
   - اتصالات موفق را در `su-goods.txt` ذخیره می‌کند
   - اعلان‌ها را به Discord ارسال می‌کند (در صورت پیکربندی)

## 📊 خروجی

برنامه اطلاعات زیر را در زمان واقعی نمایش می‌دهد:
- تعداد کل اتصالات بررسی شده
- سرعت اتصال (IP/s)
- زمان سپری شده
- زمان باقی‌مانده
- تعداد اتصالات موفق

اتصالات موفق در `su-goods.txt` با فرمت زیر ذخیره می‌شوند:
```
IP:PORT@USERNAME:PASSWORD
```

## 🔒 سیستم لایسنس

ابزار از یک سیستم لایسنس برای کنترل دسترسی استفاده می‌کند. برای ایجاد لایسنس:

1. به API سرور لایسنس دسترسی پیدا کنید:
```
http://your-api-endpoint.com:8000/create-lic?password=YOUR_ADMIN_PASSWORD&name=USER_NAME&expire=DAYS
```

2. آدرس‌های IP را به لایسنس اضافه کنید:
```
http://your-api-endpoint.com:8000/add-ip?password=YOUR_ADMIN_PASSWORD&lic=LICENSE_KEY&ip=IP_ADDRESS
```

## 🤝 مشارکت

مشارکت‌ها مورد استقبال قرار می‌گیرند! لطفاً Pull Request ارسال کنید.

## 📝 لایسنس

این پروژه تحت لایسنس MIT منتشر شده است - برای جزئیات به فایل [LICENSE](LICENSE) مراجعه کنید.

## 👨‍💻 نویسنده

- **SudoLite** - *کار اولیه*

## 🙏 قدردانی

- از تمام مشارکت‌کنندگان تشکر می‌کنیم
- الهام گرفته از نیاز به تست کارآمد اتصالات SSH 