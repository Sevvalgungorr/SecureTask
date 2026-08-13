# SecureTask

![CI](https://github.com/Sevvalgungorr/SecureTask/actions/workflows/ci.yml/badge.svg)

Güvenlik bulgusu takip uygulaması: hangi sistemde ne bulundu, ne kadar kritik, ne zamana kadar kapatılmalı. FastAPI ile yazılmış REST API + web arayüzü. Kullanıcılar kimlik sağlayıcı (OIDC) üzerinden giriş yapar, yalnızca kendi bulgularını görür; yöneticiler tüm bulguları ve denetim günlüğünü görebilir.

Bir açık envanteri hassas veridir — hangi sistemin nesinin kırık olduğunu tarif eder. Bu yüzden uygulamanın asıl konusu listenin kendisi değil, **ona kimin eriştiği ve kimin ne değiştirdiği**: kimlik doğrulama, yetkilendirme ve denetlenebilirlik.

![Giriş ekranı](docs/images/login.png)

## Tehdit modeli

Her güvenlik özelliği bir soruya cevap verir; liste olsun diye eklenmemiştir.

| Tehdit | Kontrol | Nasıl doğrulandı |
| --- | --- | --- |
| Parolanın uygulamaya girilmesi / çalınması | OIDC ile SSO — parola yalnızca sağlayıcıya girilir, PKCE (S256) | Uçtan uca giriş akışı, `test_logout.py` |
| Sahte veya kurcalanmış token | `id_token`/erişim token'ı JWKS ile yerel doğrulama (RS256 sabitlenmiş) | Manuel pentest: forge/tamper → 401 |
| Başkasının bulgu envanterini okuma (IDOR) | Her sorgu `owner_id` ile sınırlı; sahibi olmayan kayıt **404** döner, 403 değil | `test_findings.py::test_findings_are_isolated_per_user` |
| Yetkisiz yönetim erişimi | `require_role("admin")` ile korunan `/admin/*` uçları | `test_findings.py::test_admin_sees_all_findings_others_forbidden` |
| Riskin sessizce yok edilmesi (kritikliği düşürme, "risk kabul" ile kapatma) | Denetim günlüğü değişikliği açıkça yazar: `severity critical→low`, `status open→accepted_risk` | `test_audit.py::test_severity_and_status_changes_are_spelled_out` |
| Ele geçirilmiş bir oturumun riski kabul edip kapatması | **Step-up MFA**: `accepted_risk`'e geçiş, token'daki `amr`/`acr` ile ikinci faktör kanıtlanmadıkça reddedilir (fail-closed) | `test_step_up.py` (8 test) |
| Riskin gerekçesiz ve süresiz kabul edilmesi | Kabul için **gerekçe zorunlu** (en az 15 karakter) ve **bitiş tarihi zorunlu** (en fazla 90 gün); süre dolunca bulgu yeni SLA ile yeniden açılır | `test_risk_acceptance.py` (12 test) |
| Denetim kaydının düzenlenmesi, silinmesi veya tarihinin geriye alınması | Günlük **ekleme-yalnız zincir**: her kayıt kendini bir öncekinin hash'iyle imzalar; `/admin/audit/verify` kırılmanın yerini söyler | `test_audit_chain.py` — kayıt düzenlenerek, silinerek, tarihi değiştirilerek sınanır |
| Otomasyonun insan kararını ezmesi | Araçlar risk kabulüne **dokunmaz**; kritikliği yalnızca **aracın kendi değerlendirmesi yükseldiğinde** yükseltir, asla düşürmez | `test_import.py` · `test_monitor.py` |
| İzlemenin iç ağa yönlendirilmesi (SSRF) | Hedefler önceden **kayıtlı** olmalı; ad çözümlenip **her** IP kontrol edilir, özel/loopback/link-local reddedilir — hem kayıtta hem koşuda | `test_monitor.py::test_a_private_address_is_refused_at_registration` |
| İz silme / kaydın kaybolması | Denetim kaydı bulgudan bağımsız yaşar (FK değil), bulgu silinse bile kalır | `test_audit.py::test_audit_survives_finding_deletion` |
| Kaba kuvvet ve kötüye kullanım | IP başına istek sınırı (rate limit), 429 | Arayüzde uyarı, manuel test |
| Yetkisiz erişim denemesinin görünmezliği | 401/403 dönen her istek `access_denied` olarak günlüğe yazılır | Panodaki "Reddedilen erişimler" grafiği |
| Günlük satırı uydurma (CWE-117) | Günlüğe yazılan değerlerde CR/LF temizlenir (`_sanitize_log`) | Kod incelemesi |
| Depolanmış XSS (bulgu başlığı, varlık adı, kullanıcı adı) | Kullanıcı verisi DOM'a yalnızca `textContent` ile girer | Beyaz kutu incelemede bulunup düzeltildi (PR #9) |
| Tarayıcı tarafı saldırı yüzeyi | CSP, HSTS, `X-Frame-Options: DENY`, `nosniff`, Referrer-Policy, Permissions-Policy | Yanıt başlıkları |
| Bağımlılıklardaki bilinen açıklar | `pip-audit` her push'ta çalışır, bulursa derlemeyi kırar | CI `security` işi |
| Kendi kodumuzda riskli kalıplar | `bandit` statik analizi (orta ve üzeri) | CI `security` işi |

**Kapsam dışı (bilinçli):** çok kiracılı (multi-tenant) izolasyon, bulgu paylaşımı,
şifreli alan bazlı depolama, token iptali kontrolü (introspection). Sonuncusu
bilinen bir açık: token JWKS ile *yerel* doğrulandığı için, sağlayıcıda oturum
iptal edilse bile token süresi dolana kadar geçerli kalır.

### Tarama çıktısı içe aktarma

```bash
nuclei -u https://hedef -jsonl -o scan.jsonl
curl -X POST http://localhost:8000/import/nuclei \
     -H "Authorization: Bearer $TOKEN" --data-binary @scan.jsonl
# {"created":12,"reopened":1,"unchanged":34,"kept_accepted":2,"skipped":0}
```

Hem JSON dizisi hem satır-başına-nesne (JSONL) kabul edilir; bozuk bir satır
taramanın geri kalanını kaybettirmez, sayılır. Aynı hedef ikinci kez taranınca
kopya oluşmaz: eşleşme `(sahip, varlık, template-id)` üzerinden yapılır.

**Bir tarama iş ekleyebilir ve işin bitmediğini kanıtlayabilir; bir kararı silemez:**

| Mevcut durum | Tarama onu yine görürse |
| --- | --- |
| Yok | Yeni bulgu oluşturulur, SLA kritiklikten atanır |
| Açık / Triyaj | Dokunulmaz — **kritikliği de değişmez.** Biri "yüksek"i bilerek "düşük"e çektiyse, sonraki tarama bunu veto edemez |
| Düzeltildi | **Yeniden açılır** ve yeni SLA alır — kanıt, işaretin aksini söylüyor |
| Risk kabul | **Dokunulmaz.** Taramanın onu yine görmesi, o kararın beklenen sonucudur; ikinci faktör istemiş bir kararı bir içe aktarma sessizce geri alamaz |

Tek istek en fazla `MAX_RESULTS` (1000) sonuç işler — kimliği doğrulanmış bir
kullanıcı da veritabanını doldurmanın ucuz bir yolu olmamalı. Her içe aktarma
denetim günlüğüne bir özet satırı bırakır.

### İzleme

```bash
curl -X POST http://localhost:8000/assets -H "Authorization: Bearer $TOKEN" \
     -d '{"host":"app.example.test","label":"Portal"}'
curl -X POST http://localhost:8000/monitor/run -H "Authorization: Bearer $TOKEN"
# {"checked":1,"created":5,"escalated":0,"reopened":0,"resolved":0,...}
```

Her varlık için üç şey kontrol edilir: **TLS sertifikasının kalan süresi**
(30/14/0 güne göre orta/yüksek/kritik), **HTTPS erişilebilirliği** ve
**güvenlik başlıklarının varlığı**. Hepsi salt-okunur — bir TLS el sıkışması ve
bir GET; tarayıcının yapmayacağı hiçbir şey yapılmaz. Fuzzing, brute-force ve
enjeksiyon denemesi yoktur: bu envanteri **izlemek**, taramak değil.

Bozulan bir kontrol bulgu açar; düzelen kontrol **kendi açtığı** bulguyu
kapatır. Elle girilmiş bir bulguyu asla kapatmaz.

**SSRF koruması.** İzleme, sunucunun kullanıcı adına dışarı bağlantı kurması
demektir — yani tam bir SSRF şekli. Bu yüzden hedef istekle birlikte gelemez:
önce kaydedilir, kayıt sırasında **ve** her koşuda adı çözümlenip **çözümlendiği
her IP** kontrol edilir. Özel, loopback, link-local veya ayrılmış alana düşen
hedefler reddedilir.

Ağının *içinde* çalışan bir kurulumda ise kontrol edilmesi gereken her şey
zaten özeldir; `MONITOR_ALLOW_PRIVATE=true` bunu açar — birinin verdiği bir
karar olarak, sessiz bir boşluk olarak değil.

### Step-up doğrulama nasıl çalışır

Bir bulgunun durumu `accepted_risk`'e geçerken — yeni kayıtta da, güncellemede de —
token'ın ikinci bir faktör taşıdığı doğrulanır: `amr` claim'i `OIDC_MFA_AMR`
listesinden bir değer içermeli (parolayı ifade eden `pwd` bilinçli olarak listede
değildir), ya da `acr` claim'i `OIDC_MFA_ACR` ile eşleşmeli.

Kontrol **fail-closed**: hiçbir claim yoksa oturum tek faktörlü sayılır ve işlem
reddedilir. Sağlayıcının hangi değerleri ürettiği standartlaşmamıştır, bu yüzden
her ikisi de ortam değişkeniyle ayarlanır; **Güvenlik** sekmesi oturumun `amr`
değerini gösterir, böylece doğru değerler gerçek bir token'dan okunabilir.

Yalnızca *geçiş* korunur: zaten kabul edilmiş bir bulgunun başlığı ikinci faktör
olmadan da düzeltilebilir. Kontrolü karşılayan kabul, denetim günlüğüne
`mfa doğrulandı` olarak yazılır; reddedilen deneme ise 403 olduğu için
`access_denied` kaydına düşer ve panodaki grafikte görünür.

### Risk kabulü: gerekçe, sahip ve bitiş

Bir riski kabul etmek bulguyu kapatır — ama "düzeltildi" ile aynı şey değildir:
sorun yerinde durur, biri onunla yaşamaya karar vermiştir. O kararın kanıtı
yoksa kabul, bulgu listesini temizlemenin ucuz yoludur. Bu yüzden üç şey
zorunludur:

| Alan | Kural |
| --- | --- |
| Gerekçe | En az 15 karakter — `-` veya `ok` gerekçe değildir |
| Bitiş tarihi | Zorunlu, geçmiş olamaz, **en fazla 90 gün**; sonsuza kadar kabul yoktur |
| Kabul eden | İstekten değil, **ikinci faktörü geçen oturumdan** yazılır — kimse başkasını onaylayan gösteremez |

`POST /risk/expire` süresi dolmuş kabulleri tarar ve bulguyu yeni bir SLA ile
yeniden açar; olan biten günlüğe yazılır. Tarih böylece bir not olmaktan çıkar:
karar kendiliğinden geri gelir ve **yeniden verilmek zorunda kalır** — yeniden
kabul ikinci faktörü tekrar ister. Zamanaşımıyla kalıcılaşan risk kabulü, bu
uygulamanın engellemek için var olduğu şeydir.

Bulgu kabul durumundan çıkarsa gerekçe, tarih ve onaylayan temizlenir; eski bir
kabulün kalıntısı yeni bir kararın arkasına saklanamaz.

### Denetim günlüğü neden bir zincir

Yöneticinin düzenleyebildiği bir günlük, o yöneticinin tuttuğu bir defterdir —
bu uygulamanın var olma sebebi olan tek kayıt için, hiçbir şey kaydetmemekle
aynı kapıya çıkar. Bu yüzden her kayıt, kendi içeriğini bir önceki kaydın
hash'iyle birlikte imzalar (SHA-256):

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/admin/audit/verify
# {"ok":true,"checked":128,"broken_at":null,"reason":null}
```

İmzaya kaydın `id`'si ve sunucu tarafındaki zaman damgası da girer: bir satırı
düzenlemek, silmek, sıralamayı değiştirmek veya tarihini geriye almak sonraki
bütün hash'leri bozar. Doğrulama yürüyüşü kırılmanın **nerede** ve **neden**
olduğunu söyler.

Bu, kurcalamayı imkânsız kılmaz — **belli eder**. Ulaşılabilir hedef budur:
günlüğü değiştiren kişi sonraki her kaydı yeniden yazmak zorundadır ve elinde
daha eski bir hash bulunan herkes bunu görebilir.

Zincirden önce yazılmış kayıtlar geriye dönük imzalanmadı: onları şimdi
imzalamak "değiştirilmemiştir" demek olurdu ve buradaki hiçbir şey bunu
bilemez. Doğrulama onları geçerli saymaz, **zincirsiz** olarak raporlar.

## Özellikler

- 🔐 **OpenID Connect / SSO girişi** — parola yalnızca kimlik sağlayıcıya girilir, uygulama görmez (PKCE korumalı)
- 🚪 **Gerçek çıkış (single logout)** — sağlayıcının oturumu da kapatılır, sonraki giriş yeniden kimlik sorar
- 🔎 **Bulgu kaydı** — başlık, kanıt, **varlık**, kritiklik, durum
- 🎯 **Kritiklik ve SLA** — `low` / `medium` / `high` / `critical`; tarih verilmezse kritikliğe göre hesaplanır (7 / 14 / 30 / 90 gün)
- 🔁 **Durum akışı** — Açık → Triyaj → Düzeltildi **veya** Risk kabul (ikisi de kapatır, ikisi ayrı şeydir)
- 🔑 **Step-up MFA** — bir riski kabul etmek ikinci faktör ister; parola tek başına yetmez
- 📝 **Risk kabul kütüğü** — gerekçe ve bitiş tarihi zorunlu (en fazla 90 gün); süre dolunca bulgu kendiliğinden yeniden açılır
- 📥 **Tarama çıktısı içe aktarma** — nuclei JSON/JSONL; yeniden taramada tekilleştirir, kapatılmış ama hâlâ görülen bulguyu yeniden açar
- 📡 **İzleme** — kayıtlı varlıklarda TLS sertifikası süresi, erişilebilirlik ve güvenlik başlıkları; bozulan kontrol bulgu açar, düzelen kontrol kendi bulgusunu kapatır
- 👤 **Kullanıcıya özel envanter** — herkes yalnızca kendi bulgularına erişir
- 🛡️ **Rol bazlı yetki (RBAC)** — yöneticiye özel uçlar
- 📋 **Denetim günlüğü** — kim, ne zaman, ne yaptı; kritiklik ve durum değişiklikleri ayrıca yazılır
- ⛓️ **Değiştirilemez günlük** — her kayıt bir öncekinin hash'iyle imzalanır; düzenleme, silme veya tarih değiştirme zinciri kırar ve doğrulama nerede kırıldığını söyler
- 📊 **Pano** — açık bulgu, kapatma oranı, SLA aşımı, kritiklik dağılımı; yöneticiye ayrıca reddedilen erişim denemeleri
- ✅ **Otomatik testler** — pytest ile 81 test, CI üzerinde her değişiklikte çalışır
- 🔬 **CI'da güvenlik taraması** — `pip-audit` (bağımlılık CVE'leri) + `bandit` (statik analiz), bulursa derlemeyi kırar

![Pano](docs/images/dashboard.png)

Grafikler dış bir kütüphane kullanmaz, saf SVG ile çizilir — uygulamanın kendi
Content-Security-Policy başlığı zaten dışarıdan script yüklenmesine izin vermez.
Kritiklik rampası tek hue'lu sıralı bir ölçektir ve açık/koyu tema için ayrı ayrı
doğrulanmıştır; `--danger` yalnızca "dikkat gerekiyor" (SLA aşımı) için ayrılmıştır,
hiçbir zaman bir kritiklik seviyesi için kullanılmaz.

> **Not:** Bu depodaki tüm örnek veriler uydurmadır (`*.example.test`). Gerçek
> sistem adları, IP'ler ve bulgu detayları bir açık envanterinin en hassas
> kısmıdır; herkese açık bir depoya konmaz.

## Teknolojiler

`Python` · `FastAPI` · `PostgreSQL` · `SQLAlchemy` · `Alembic` · `Pydantic` · `OAuth2 / OpenID Connect` · `JWT / JWKS` · `pytest` · `pip-audit` · `bandit` · `Docker`

## Otomatik API dokümanı

FastAPI, tüm uçlar için otomatik ve interaktif bir dokümantasyon üretir — sunucu ayaktayken **`/docs`** adresinde:

![API dokümanı](docs/images/api-docs.png)

Swagger arayüzü **kendi sunucumuzdan** servis edilir (`app/static/vendor/`),
bir CDN'den değil. Sebebi ikili: uygulamanın kendi CSP başlığı dış script
yüklemeyi zaten yasaklıyor (varsayılan sayfa bu yüzden boş geliyordu), ve tüm
API yüzeyini gösteren bir sayfaya üçüncü taraf bir script sunucusu koymak, bu
uygulamanın takip etmek için var olduğu tedarik zinciri riskinin ta kendisi.
Yan fayda: dokümantasyon internetsiz bir makinede de çalışır.

## Kimlik doğrulama akışı

Kimlik sağlayıcı (openidx) `state` parametresini kullanmadığı için akış klasik yönlendirmeden farklıdır; güvenlik **PKCE (S256)** ile sağlanır ve parola hiçbir zaman bu uygulamaya girilmez.

1. `GET /auth/login` — PKCE üretir, imzalı oturum çerezinde saklar, `/oauth/authorize`'a yönlendirir
2. Sağlayıcı `/callback?login_session=…`'e döner (henüz oturum yok)
3. `/callback`, tarayıcıyı sağlayıcının **kendi giriş sayfasına** yönlendirir — parola orada girilir
4. Giriş sonrası sağlayıcı `/callback?code=…`'e döner
5. `/callback`, kodu + doğrulayıcıyı `/oauth/token`'da token'a çevirir, `id_token`'ı JWKS ile doğrular, kullanıcıyı `(issuer, sub)` ile eşleştirir

API istekleri `Authorization: Bearer <access_token>` ile kimlik doğrular; JWT'ler JWKS'e karşı yerel olarak doğrulanır (RS256 sabitlenmiş).

## Kurulum ve çalıştırma

### Docker ile (önerilen)

```bash
cp .env.example .env      # değerleri doldur
docker compose up --build
```

### Native (Python)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # DATABASE_URL, OIDC ayarları, SESSION_SECRET
alembic upgrade head      # veritabanı şemasını kur
uvicorn app.main:app --reload
```

Sonra:
- **API:** http://localhost:8000
- **Arayüz:** http://localhost:8000/app
- **API dokümanı:** http://localhost:8000/docs

## Testler ve güvenlik taraması

```bash
pip install -r requirements-dev.txt
pytest                                      # 81 test
pip-audit -r requirements.txt --strict      # bağımlılıklarda bilinen CVE var mı
bandit -r app --severity-level medium       # kendi kodumuzda riskli kalıplar
```

Son ikisi CI'da ayrı bir iş olarak her push ve pull request'te çalışır ve
**başarısız olursa derlemeyi kırar**. Bilerek: başkasının yamalanmamış
yazılımını takip eden bir uygulama, yamalanmamış yazılımla dağıtılmamalı.
Bir bulgu gerçekten geçerli değilse `--ignore-vuln` ile ve **gerekçesi
yazılarak** susturulur.

Testler ayrı bir `securetask_test` veritabanı kullanır ve kimlik doğrulamayı taklit eder (OIDC sağlayıcısına bağlanmaz). Her `push` ve `pull request`'te GitHub Actions üzerinde otomatik çalışır.

## Uç noktalar

| Metod | Yol | Erişim |
| --- | --- | --- |
| `GET` | `/auth/login`, `/callback` | Giriş akışı |
| `GET` | `/auth/me`, `/auth/logout` | Bearer |
| `POST` `GET` `PUT` `DELETE` | `/findings`, `/findings/{id}` | Bearer (yalnızca sahibi) |
| `POST` | `/import/nuclei` | Bearer (tarama çıktısı) |
| `POST` `GET` `DELETE` | `/assets`, `/assets/{id}` | Bearer (yalnızca sahibi) |
| `POST` | `/monitor/run` | Bearer (kendi varlıkları) |
| `POST` | `/risk/expire` | Bearer (süresi dolan kabulleri yeniden açar) |
| `GET` | `/audit/me` | Bearer (kendi geçmişi) |
| `GET` `DELETE` | `/admin/findings`, `/admin/findings/{id}` | Yalnızca `admin` |
| `GET` | `/admin/audit` | Yalnızca `admin` |
| `GET` | `/admin/audit/verify` | Yalnızca `admin` (zincir doğrulama) |

## Veri modeli

```
Finding    id · title · description · asset · severity · status · due_date
           source · source_ref · source_severity · owner_id
           accepted_reason · accepted_until · accepted_at · accepted_by_id
Asset      id · host · label · is_active · owner_id
User       id · username · email · oidc_issuer · oidc_sub · is_active
AuditLog   id · created_at · user_id · action · finding_id · detail
           prev_hash · entry_hash
```

`severity` ∈ {low, medium, high, critical} · `status` ∈ {open, triaged, fixed, accepted_risk}

## Proje yapısı

```
app/
  main.py       # API uçları
  auth.py       # OIDC giriş + token doğrulama
  models.py     # veritabanı tabloları (Finding, User, AuditLog)
  audit.py      # denetim günlüğü: ekleme-yalnız hash zinciri + doğrulama
  importers.py  # tarayıcı çıktısı ayrıştırma (nuclei)
  monitor.py    # kayıtlı varlık kontrolleri + SSRF koruması
  schemas.py    # istek/yanıt doğrulama (Pydantic)
  database.py   # veritabanı bağlantısı
  config.py     # ortam ayarları
  static/       # web arayüzü
alembic/        # veritabanı migration'ları
tests/          # pytest test paketi
.github/workflows/ci.yml   # sürekli entegrasyon
```

## Sıradaki işler

- **Token iptali kontrolü (introspection)** — sağlayıcıda oturum kapatılınca token'ın burada da geçersiz olması
- **Zincir doğrulamasının dışa aktarılması** — bir kontrol noktası hash'ini dışarı yazmak, böylece tüm günlüğü yeniden yazan biri bile yakalanabilsin

## License

MIT — see [LICENSE](LICENSE).
