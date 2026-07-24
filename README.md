# SecureTask

![CI](https://github.com/Sevvalgungorr/SecureTask/actions/workflows/ci.yml/badge.svg)

OpenID Connect ile korunan, kullanıcıya özel bir görev yönetim uygulaması. FastAPI ile yazılmış REST API + basit bir web arayüzü. Kullanıcılar kimlik sağlayıcı (OIDC) üzerinden giriş yapar, yalnızca kendi görevlerini görür; yöneticiler tüm görevleri ve denetim günlüğünü görebilir.

![Giriş ekranı](docs/images/login.png)

## Özellikler

- 🔐 **OpenID Connect / SSO girişi** — parola yalnızca kimlik sağlayıcıya girilir, uygulama görmez (PKCE korumalı)
- 👤 **Kullanıcıya özel görevler** — herkes yalnızca kendi görevlerine erişir
- 🛡️ **Rol bazlı yetki (RBAC)** — yöneticiye özel uçlar
- 📋 **Denetim günlüğü (audit log)** — kim, ne zaman, ne yaptı; kullanıcı kendi geçmişini de görebilir
- 🎯 **Öncelik ve bitiş tarihi** — görevlerde renkli etiket ve tarih
- 🖥️ **Web arayüzü** — giriş, görev yönetimi, filtreler, admin paneli
- ✅ **Otomatik testler** — pytest ile 10 test, CI üzerinde her değişiklikte çalışır

## Teknolojiler

`Python` · `FastAPI` · `PostgreSQL` · `SQLAlchemy` · `Alembic` · `Pydantic` · `OAuth2 / OpenID Connect` · `JWT / JWKS` · `pytest` · `Docker`

## Otomatik API dokümanı

FastAPI, tüm uçlar için otomatik ve interaktif bir dokümantasyon üretir — sunucu ayaktayken **`/docs`** adresinde:

![API dokümanı](docs/images/api-docs.png)

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

## Testler

```bash
pip install -r requirements-dev.txt
pytest
```

Testler ayrı bir `securetask_test` veritabanı kullanır ve kimlik doğrulamayı taklit eder (OIDC sağlayıcısına bağlanmaz). Her `push` ve `pull request`'te GitHub Actions üzerinde otomatik çalışır.

## Uç noktalar

| Metod | Yol | Erişim |
| --- | --- | --- |
| `GET` | `/auth/login`, `/callback` | Giriş akışı |
| `GET` | `/auth/me` | Bearer |
| `POST` `GET` `PUT` `DELETE` | `/tasks`, `/tasks/{id}` | Bearer (yalnızca sahibi) |
| `GET` | `/audit/me` | Bearer (kendi geçmişi) |
| `GET` `DELETE` | `/admin/tasks`, `/admin/tasks/{id}` | Yalnızca `admin` |
| `GET` | `/admin/audit` | Yalnızca `admin` |

## Proje yapısı

```
app/
  main.py       # API uçları
  auth.py       # OIDC giriş + token doğrulama
  models.py     # veritabanı tabloları (Task, User, AuditLog)
  schemas.py    # istek/yanıt doğrulama (Pydantic)
  database.py   # veritabanı bağlantısı
  config.py     # ortam ayarları
  static/       # web arayüzü
alembic/        # veritabanı migration'ları
tests/          # pytest test paketi
.github/workflows/ci.yml   # sürekli entegrasyon
```
