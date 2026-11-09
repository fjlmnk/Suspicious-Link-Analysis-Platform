# Suspicious Link Analysis Platform – Malicious URL and Phishing Detection System

> **Практичне завдання №5: Реалізація програмного забезпечення з використанням AI-агентів**  
> **Використаний AI-агент / Середовище розробки:** Google Antigravity (Advanced Agentic Coding Environment)

Безпечний веб-застосунок для аналізу URL-адрес та виявлення шкідливих веб-сайтів, фішингових атак, розповсюдження шкідливого ПЗ та інших кіберзагроз за допомогою багатовекторної розвідки загроз (Threat Intelligence).

---

## Oсновні функціональні можливості 

1. **Аналіз безпеки посилань (URL Security Analysis)**:
   - Перевірка синтаксису, протоколу (HTTP/HTTPS) та структури посилання.
   - Захист від SSRF-атак: блокування приватних адрес (localhost, 127.0.0.1, 10.x, 192.168.x).
   - Виявлення підозрілих TLD (.xyz, .top), IP-based URL та скорочувачів посилань.

2. **Інтеграція зовнішніх провайдерів загроз (Threat Intelligence)**:
   - **VirusTotal v3 API**: Перевірка за базами 70+ світових антивірусних вендорів.
   - **Google Safe Browsing v4 API**: Виявлення фішингу, шкідливих сайтів та соціальної інженерії.
   - **URLhaus (abuse.ch) API**: Перевірка активних посилань розповсюдження вірусів, ботнетів та експлойтів.

3. **Агрегація вердиктів та розрахунок індексу ризику**:
   - Розрахунок чисельного індексу небезпеки від **0 до 100**.
   - Підсумкова класифікація: **`SAFE`** (0–29), **`SUSPICIOUS`** (30–69), **`DANGEROUS`** (70–100).
   - Генерація зрозумілого пояснення для користувача з конкретними рекомендаціями дій.

4. **Генерація офіційних PDF-звітів**:
   - Експорт детального аудиторського звіту безпеки у форматі PDF (ReportLab) з логотипами, кодуванням кольорів та таблицею детекцій.

5. **Історія сканувань та ролі користувачів**:
   - Перегляд збереженої історії перевірок із сортуванням та фільтрацією за статусом і рівнем загрози.
   - Ролі: **Звичайний користувач** (Regular User) та **Співробітник компанії** (Company Employee) з можливістю надсилання звітів команді безпеки (SOC / Security Team).

6. **Демонстраційний режим (Demo Mode)**:
   - 6 готових інтерактивних сценаріїв для тестування без витрачання квот реальних API-ключів.

---

## Використаний стек технологій

| Рівень | Технології |
|---|---|
| **AI-агент** | **Google Antigravity** |
| **Frontend** | React 18, TypeScript, Tailwind CSS, Vite, Lucide React |
| **Backend** | Python 3.10+, FastAPI, Pydantic v2, SQLAlchemy (Async) |
| **База даних** | SQLite (`aiosqlite`) / PostgreSQL |
| **Threat APIs**| VirusTotal v3, Google Safe Browsing v4, URLhaus (abuse.ch) |
| **PDF генерація**| ReportLab |
| **Тестування** | Pytest, Pytest-Asyncio, HTTPX |
| **Контейнеризація** | Docker, Docker Compose |

---

## Інструкція із запуску (Quick Start)

### Варіант 1: Запуск в один клік (Windows)
У кореневій папці двічі клікніть:
```text
start_all.bat
```
*Скрипт автоматично запустить бэкенд на порту 8000 та фронтенд на порту 5173 у двох окремих вікнах.*

### Варіант 2: Запуск через термінал

#### 1. Запуск Backend (FastAPI):
```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- API Docs (Swagger): **http://127.0.0.1:8000/docs**

#### 2. Запуск Frontend (React + Vite):
У другому вікні термінала:
```powershell
cd frontend
npm install
npm run dev
```
- Веб-інтерфейс: **http://localhost:5173**

### Варіант 3: Запуск через Docker
```powershell
docker-compose up --build
```
- Додаток буде доступний за адресою: **http://localhost:3000**

---

## Тестування та перевірка якості

Для запуску набору з 49 автоматизованих модульних тестів:
```powershell
cd backend
.\venv\Scripts\pytest tests/ -v
```
Для запуску наскрізного верифікаційного конвеєра:
```powershell
cd backend
$env:PYTHONPATH="."
.\venv\Scripts\python.exe tests/verify_pipeline.py
```

Детальний академічний звіт із процесом планування, розробки та виправлення помилок дивіться у файлі **[`PRACTICAL_5_REPORT.md`](PRACTICAL_5_REPORT.md)**.
