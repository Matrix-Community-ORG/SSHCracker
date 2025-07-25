# 🚀 SSHCracker نسخه ۲.۶ - ابزار پیشرفته SSH Brute Force

[![نسخه Go](https://img.shields.io/badge/Go-1.18+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![مجوز](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![پلتفرم](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=for-the-badge)](https://github.com/)
[![انتشار](https://img.shields.io/github/v/release/Matrix-Community-ORG/SSHCracker?style=for-the-badge)](https://github.com/Matrix-Community-ORG/SSHCracker/releases)
[![نسخه](https://img.shields.io/badge/Version-2.6-blue?style=for-the-badge)](https://github.com/Matrix-Community-ORG/SSHCracker)

یک ابزار قدرتمند و پرسرعت SSH brute force نوشته شده با Go که دارای **معماری پیشرفته worker چندلایه**، تشخیص پیشرفته honeypot، آمار بلادرنگ و قابلیت‌های جامع شناسایی سیستم می‌باشد.

## 🌟 امکانات کلیدی

### 🔥 قابلیت‌های اصلی
- **⚡ Worker های چندلایه بهبود یافته** - معماری انقلابی پردازش همزمان
- **🚀 افزایش ۱۰ برابری کارایی** - تا ۱۰۰۰+ اتصال همزمان در هر worker
- **🍯 تشخیص پیشرفته Honeypot** - ۹ الگوریتم هوشمند با worker های اختصاصی
- **📊 داشبورد بلادرنگ** - ردیابی زنده پیشرفت با آمار بهبود یافته
- **🎯 مدیریت هوشمند اهداف** - مدیریت کارآمد wordlist و target
- **🔍 شناسایی عمیق سیستم** - جمع‌آوری جامع اطلاعات سرور
- **📁 فرمت‌های خروجی زیبا** - لاگ بهبود یافته با ایموجی و داده‌های ساختاریافته

### 🛡️ امنیت و کارایی
- **🚀 پشتیبانی چندپلتفرمه** - سازگاری با Linux، Windows، macOS
- **⚙️ مدیریت هوشمند Worker** - pool های جداگانه برای SSH و تشخیص honeypot
- **🔒 عملیات Thread-Safe** - عملیات اتمی برای محیط‌های همزمان بالا
- **🎛️ پیکربندی پیشرفته** - timeout، حالت مخفی، تنظیم کارایی

## 🆕 جدید در نسخه ۲.۶

### 🎯 معماری ساده‌شده و عملکرد بهبود یافته
- **پردازش یکپارچه**: تشخیص honeypot اکنون مستقیماً در pipeline پردازش SSH اجرا می‌شود
- **حذف overhead صف**: صف worker های جداگانه honeypot برای عملکرد بهتر حذف شد
- **کاهش استفاده از حافظه**: معماری ساده‌شده ۵۰٪ حافظه کمتری استفاده می‌کند
- **پردازش تک‌لایه**: تشخیص مستقیم honeypot بدون لایه‌های اضافی worker
- **کنترل بهتر منابع**: الگوهای قابل پیش‌بینی‌تر استفاده از CPU و حافظه

### 🚀 بهبودهای فنی
- **مدل Worker ساده‌شده**: حذف struct `ServerInfoWithClient` و worker های اختصاصی honeypot
- **تشخیص مستقیم**: تشخیص honeypot مستقیماً در `processSSHTask` ادغام شد
- **کد تمیزتر**: کاهش پیچیدگی با pipeline پردازش یکپارچه
- **دیباگ بهتر**: معماری ساده‌تر عیب‌یابی را آسان‌تر می‌کند
- **عملکرد پایدار**: استفاده ثابت‌تر از منابع بدون گلوگاه‌های صف

### 🛡️ امکانات حفظ شده
- **تمام ۹ الگوریتم Honeypot**: قابلیت تشخیص کامل حفظ شده
- **پردازش چندنخی**: ۲۵ اتصال همزمان در هر worker حفظ شده
- **آمار بلادرنگ**: ردیابی پیشرفت و متریک‌های بهبود یافته
- **پشتیبانی چندپلتفرمه**: همه پلتفرم‌ها همچنان پشتیبانی می‌شوند

## 🚀 شروع سریع

### گزینه ۱: دانلود باینری از پیش ساخته‌شده (توصیه شده)
```bash
# به صفحه انتشارات مراجعه کنید و برای پلتفرم خود دانلود کنید:
# https://github.com/Matrix-Community-ORG/SSHCracker/releases/latest

# قابل اجرا کنید (Linux/macOS):
chmod +x ssh-cracker-*

# اجرا:
./ssh-cracker-*
```

### گزینه ۲: ساخت از کد منبع
```bash
# کلون ریپازیتوری
git clone https://github.com/Matrix-Community-ORG/SSHCracker.git
cd SSHCracker

# ساخت
go build ssh.go

# اجرا
./ssh
```

## 📋 راهنمای استفاده

### استفاده اساسی
1. **اجرای ابزار**: `./ssh-cracker-*`
2. **پیکربندی ورودی‌ها**:
   - فایل wordlist نام کاربری (مثال: `users.txt`)
   - فایل wordlist رمز عبور (مثال: `passwords.txt`)
   - فایل لیست اهداف (مثال: `targets.txt`)
   - timeout اتصال (توصیه: ۵-۱۰ ثانیه)
   - حداکثر اتصالات همزمان (توصیه: ۱۰-۵۰)

### نمونه فرمت فایل‌ها

**نام کاربری (`users.txt`)**:
```
root
admin
administrator
user
ubuntu
```

**رمز عبور (`passwords.txt`)**:
```
123456
password
admin
root
12345678
```

**اهداف (`targets.txt`)**:
```
192.168.1.1:22
10.0.0.1:22
example.com:2222
```

## 🍯 سیستم تشخیص Honeypot (BETA)

تشخیص پیشرفته honeypot ما از ۹ الگوریتم پیچیده استفاده می‌کند:

| الگوریتم | روش تشخیص |
|-----------|------------|
| **تشخیص الگو** | امضاها و artifact های شناخته شده honeypot |
| **تحلیل زمان پاسخ** | الگوهای زمان‌بندی غیرعادی |
| **رفتار دستور** | پاسخ‌های غیرطبیعی دستورات سیستم |
| **تحلیل فایل سیستم** | ساختارهای فایل جعلی یا شبیه‌سازی شده |
| **پیکربندی شبکه** | تنظیمات port و سرویس مشکوک |
| **تست کارایی** | ویژگی‌های کارایی سیستم |
| **تشخیص ناهنجاری** | رفتارهای غیرعادی سیستم |
| **تحلیل سرویس** | فرآیندها و سرویس‌های در حال اجرا |
| **تحلیل محیط** | متغیرهای محیط سیستم |

> **⚠️ توجه**: در حال حاضر در مرحله BETA - تأیید دستی honeypot های تشخیص داده شده توصیه می‌شود.

## 📊 فایل‌های خروجی

| فایل | توضیح |
|------|-------|
| `su-goods.txt` | اعتبارات SSH با موفقیت شکسته شده |
| `detailed-results.txt` | نتایج جامع اسکن با اطلاعات سیستم |
| `honeypots.txt` | honeypot های تشخیص داده شده با امتیاز اطمینان |
| `combo.txt` | ترکیبات اعتبار تولید شده (موقت) |

## ⚙️ پیکربندی پیشرفته

### حالت‌های کارایی

**🏃 حالت پرسرعت**:
- Timeout: ۳ ثانیه
- اتصالات حداکثر: ۵۰
- برای شبکه‌های سریع استفاده کنید

**🥷 حالت مخفی**:
- Timeout: ۱۰ ثانیه
- اتصالات حداکثر: ۵
- برای شناسایی دقیق استفاده کنید

## 🔧 نیازمندی‌های نصب

### پیش‌نیازها
- **Go**: نسخه ۱.۱۸ یا بالاتر
- **Git**: برای کلون کردن (اگر از کد منبع ساخته می‌شود)
- **دسترسی شبکه**: به سیستم‌های هدف

### پلتفرم‌های پشتیبانی شده
- ✅ Linux (x64, ARM64)
- ✅ Windows (x64)
- ✅ macOS (Intel, Apple Silicon)

## 🛠️ عیب‌یابی

### مشکلات رایج
```bash
# مجوز رد شد
chmod +x ssh-cracker-*

# خطاهای ماژول
go mod download && go mod tidy

# تعداد زیاد فایل باز
ulimit -n 65536
```

### نکات کارایی
- timeout را براساس تأخیر شبکه تنظیم کنید
- با تعداد اتصال کمتر شروع کنید
- منابع سیستم را در طول اسکن نظارت کنید

## 📱 انجمن و پشتیبانی

### 🌐 به انجمن‌های ما بپیوندید
- **انجمن انگلیسی**: [@MatrixORG](https://t.me/MatrixORG)
- **انجمن فارسی**: [@MatrixFa](https://t.me/MatrixFa)
- **گروه چت**: [@DD0SChat](https://t.me/DD0SChat)

### 💬 کمک دریافت کنید
1. [Issues](https://github.com/Matrix-Community-ORG/SSHCracker/issues) را بررسی کنید
2. به انجمن‌های تلگرام ما بپیوندید
3. گزارش‌های باگ تفصیلی ایجاد کنید

## ⚠️ استفاده قانونی و اخلاقی

**🚨 اطلاعیه مهم**: این ابزار برای موارد زیر طراحی شده:
- ✅ تست نفوذ مجاز
- ✅ اهداف آموزشی
- ✅ تحقیقات امنیتی
- ✅ سیستم‌های خودتان

**❌ استفاده نکنید برای**:
- تلاش‌های دسترسی غیرمجاز
- فعالیت‌های غیرقانونی
- سیستم‌هایی که مالک آن نیستید بدون مجوز

**کاربران کاملاً مسئول رعایت قوانین و مقررات قابل اجرا هستند.**

## 🤝 مشارکت

ما از مشارکت‌ها استقبال می‌کنیم! روش کار:

1. **Fork** کنید ریپازیتوری را
2. **ایجاد** کنید شاخه ویژگی: `git checkout -b feature/AmazingFeature`
3. **Commit** کنید تغییرات: `git commit -m 'Add AmazingFeature'`
4. **Push** کنید به شاخه: `git push origin feature/AmazingFeature`
5. **باز** کنید یک Pull Request

## 📄 مجوز

این پروژه تحت **مجوز MIT** منتشر شده - [LICENSE](LICENSE) را برای جزئیات ببینید.

## 🏆 تقدیر و تشکر

- **Matrix Community** - توسعه و نگهداری
- **Go Community** - کتابخانه‌های عالی SSH
- **محققان امنیت** - الگوریتم‌های تشخیص honeypot
- **مشارکت‌کنندگان** - گزارش‌های باگ و درخواست‌های ویژگی

---

<div align="center">

**⭐ اگر این پروژه مفید است ستاره بدهید! ⭐**

ساخته شده با ❤️ توسط [Matrix Community](https://github.com/Matrix-Community-ORG)

</div>
