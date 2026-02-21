# قرارداد نمره‌دهی پایپلاین (Grading Contract)

پایپلاین نمره‌دهی بر دو روش کار می‌کند:

1. **نمره‌دهی بر اساس تست (test-based)**: اگر خروجی `go test -json` در دسترس باشد و حداقل یک تست پاس شده وجود داشته باشد، نمرهٔ هر استپ بر اساس **عملکرد واقعی** تعیین می‌شود؛ یعنی فقط وقتی نمره می‌گیرید که تست‌های مربوط به آن فیچر **پاس** شده باشند.
2. **نمره‌دهی fallback (کد-کلیدواژه)**: اگر خروجی تست در دسترس نباشد یا هیچ تستی پاس نشده باشد، نمره بر اساس وجود کلمات کلیدی در کد (grep) محاسبه می‌شود.

برای گرفتن نمرهٔ کامل بر اساس **کارکرد واقعی**، باید تست‌هایی بنویسید که نام آن‌ها با الگوهای زیر مطابقت داشته باشد و **همهٔ آن تست‌ها پاس** شوند.

## الگوهای تست برای هر استپ

نام تست‌ها (مثلاً `TestHandshake`) مهم است. پایپلاین فقط تست‌های **پاس‌شده** را می‌بیند و با الگوی نام تطبیق می‌دهد.

### Step 2 – Handshake (۱۵ نمره)

- حداقل یکی از این الگوها در **نام** یک تست پاس‌شده دیده شود:  
  `Handshake`, `KeyExchange`, `Auth`, `UUID`, `KeyDerive`, `Curve25519`, `HKDF`
- برای نمرهٔ کامل (۱۵): حداقل دو دسته از رفتارها با تست پاس‌شده پوشش داده شوند (مثلاً handshake + auth).

**تست‌های پیشنهادی:**  
`TestHandshake`, `TestKeyExchange`, `TestAuth` یا `TestAuthenticateUser`

---

### Step 3 – Encryption (۱۵ نمره)

- حداقل یکی از این الگوها در نام تست پاس‌شده:  
  `Encrypt`, `Frame`, `ChaCha`, `AEAD`, `Replay`, `ReadFrame`, `WriteFrame`
- برای نمرهٔ کامل: حداقل دو دسته (مثلاً encrypt + frame یا replay).

**تست‌های پیشنهادی:**  
`TestEncryption`, `TestFrame` یا `TestReadFrame`/`TestWriteFrame`, `TestReplayProtection`

---

### Step 4 – Fallback (۱۵ نمره)

- حداقل یکی از این الگوها در نام تست پاس‌شده:  
  `Fallback`, `Peek`, `NonReflex`, `ProxyDetect`

**تست‌های پیشنهادی:**  
`TestFallback`, `TestPeek` یا `TestFallbackToWebServer`

---

### Step 5 – Advanced (۲۰ نمره)

- حداقل یکی از این الگوها در نام تست پاس‌شده:  
  `Morph`, `Padding`, `Timing`, `Profile`, `TrafficProfile`, `GetPacketSize`, `GetDelay`, `AddPadding`
- برای نمرهٔ کامل: حداقل دو دسته (مثلاً profile + padding/timing).

**تست‌های پیشنهادی:**  
`TestTrafficMorphing`, `TestPaddingControl`, `TestTimingControl`, `TestTrafficProfile`

---

### Integration (۱۰ نمره)

برای نمرهٔ یکپارچگی، باید تست‌های **پاس‌شده** وجود داشته باشند که این سه رفتار را پوشش دهند:

- **Handshake** (یا `Integration.*Handshake`)
- **Fallback** (یا `Integration.*Fallback`)
- **Replay** (یا `Integration.*Replay`)

هر کدام تا ۳ نمره؛ جمع با سقف ۱۰ و اعمال gate بر اساس coverage (مستندات submission).

---

## نکات مهم

- **Build و تست‌ها باید سبز باشند.** اگر `go test ./...` با خطا تمام شود، نمرهٔ واحد و یکپارچگی صفر می‌شود و نمره‌دهی استپ‌ها به fallback (کد-کلیدواژه) می‌رود.
- **Coverage** روی نمرهٔ Integration اثر می‌گذارد (زیر ۲۰٪ سقف ۵، زیر ۴۰٪ سقف ۷).
- **نام تست** باید با الگوها مطابقت داشته باشد؛ محل فایل (مثلاً `proxy/reflex/...` یا `tests/...`) مهم نیست.
- اگر هیچ تستی پاس نشود یا خروجی `go test -json` در دسترس نباشد، پایپلاین فقط با **fallback** (جستجوی کلیدواژه در کد) نمره می‌دهد؛ در آن حالت نمره بر اساس «وجود کد» است نه «کارکرد واقعی».

با رعایت این قرارداد، نمره‌دهی تا حد ممکن بر اساس **درست کار کردن فیچرها** خواهد بود.

## تست‌های مرجع (Grading Tests)

در ریپو یک مجموعه **تست یکپارچگی مرجع** وجود دارد که همان رفتار استپ‌ها را روی پیاده‌سازی شما اجرا می‌کند:

- مسیر: `xray-core/proxy/reflex/grading/`
- مستندات همان پکیج: [README در grading](https://github.com/soroushdeimi/reflex/blob/main/xray-core/proxy/reflex/grading/README.md)

این تست‌ها handshake واقعی (ارسال REFX + بسته کلاینت)، پاسخ سرور، قالب frame، و **fallback** (ارسال GET و بررسی رسیدن به وب‌سرور fallback) را چک می‌کنند. اگر این تست‌ها پاس شوند، پایپلاین در حالت test-based نمرهٔ بهتری به استپ‌های مربوط می‌دهد.
