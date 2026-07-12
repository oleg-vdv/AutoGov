# Руководство пользователя AutoGov

Пошагово: от «поднять за 2 минуты» до продакшн-развёртывания с TLS/mTLS и
подписанными артефактами.

---

## 1. Быстрый старт (демо, ~2 минуты)

Требуется Docker с плагином Compose.

```bash
git clone https://github.com/oleg-vdv/AutoGov.git
cd AutoGov/deploy
docker compose up --build
```

Что поднимется:
- **controlplane** на `http://localhost:8443`;
- **shadow-n8n** — намеренно «теневой» инстанс n8n (то, что продукт должен найти);
- **agent** — сенсор, который через ~30 c обнаружит n8n и отправит находки.

Откройте `http://localhost:8443`, войдите токеном **`dev-admin`**. Увидите:
инвентарь инстансов, находки с риск-скором и объяснением, карту доступа,
кнопки экспорта отчётов.

Демо-токены (dev): `dev-admin` (admin), `dev-analyst` (analyst),
`dev-viewer` (viewer). Демо работает по HTTP — только для локальной проверки.

---

## 2. Запуск без Docker (сборка из исходников)

Нужен Go 1.24+.

```bash
git clone https://github.com/oleg-vdv/AutoGov.git
cd AutoGov
make build           # → bin/agent, bin/controlplane, bin/autogov-sign
make test            # прогнать тесты
```

### Control plane

```bash
cp deploy/controlplane.example.json /etc/autogov/controlplane.json
# отредактируйте токены и notify
./bin/controlplane -config /etc/autogov/controlplane.json
```

### Агент (на каждом защищаемом хосте)

```bash
cp deploy/agent.example.json /etc/autogov/agent.json
# впишите control_plane_url и token
./bin/agent -config /etc/autogov/agent.json          # как демон
./bin/agent -config /etc/autogov/agent.json -once     # один проход, для проверки
```

---

## 3. Конфигурация control plane

`controlplane.json`:

| Поле | Смысл |
|---|---|
| `listen` | адрес прослушивания, напр. `:8443` |
| `data_dir` | каталог хранилища (snapshot + аудит-лог) |
| `mode` | `onprem` (по умолчанию, внешний egress запрещён) или `saas` |
| `allow_external_egress` | явное разрешение внешних адресатов в on-prem (трансграничная передача!) |
| `tls.cert_file/key_file` | серверный TLS |
| `tls.client_ca_file` | CA для **mTLS агентов** (если задан — `/ingest` требует клиентский сертификат) |
| `agent_tokens` | список bearer-токенов для агентов |
| `api_tokens` | карта `токен → роль` (`viewer`/`analyst`/`admin`) |
| `vuln_feed` | путь к офлайн-фиду уязвимостей (JSON) |
| `notify` | каналы оповещений (см. §6) |
| `risk_weights` | (опц.) переопределение весов риск-скоринга |

### Роли (RBAC)

| Роль | Что видит/может |
|---|---|
| `viewer` | сводка, инстансы, находки, хосты |
| `analyst` | + карта доступа (чувствительно!), смена статуса находок, автодокументация |
| `admin` | + whitelisting, экспорт отчётов, аудит-лог |

---

## 4. Конфигурация агента

`agent.json` — включайте только нужные коллекторы (принцип наименьших
привилегий, ТЗ §9):

| Поле | Смысл |
|---|---|
| `control_plane_url` | адрес control plane (https в проде) |
| `token` | agent-токен из `agent_tokens` |
| `interval_seconds` | периодичность полного скана |
| `docker_socket` | путь к сокету, или `"off"` чтобы отключить Docker-коллектор |
| `scan_roots` | доп. каталоги для поиска `~/.n8n`/compose/`.env` |
| `net_targets` | список `host:port` для сетевого фингерпринта |
| `n8n_api_base` / `n8n_api_key` | (опц.) авторизованная инвентаризация воркфлоу через API (ключ даёт клиент-админ) |
| `tls.*` | клиентский сертификат для mTLS, CA |
| `release.*` | проверка подписи артефакта (см. §7) |

> **Docker-сокет = root-эквивалент.** Монтируйте его **read-only**
> (`:/var/run/docker.sock:ro`). Без сокета агент деградирует (не видит
> контейнеры), но продолжает работать по процессам/ФС/сети — не требует root.

---

## 5. Продакшн: TLS и mTLS

Агент общается с control plane только исходящими соединениями. Для пилота
включите mTLS:

```bash
# 1. Свой CA
openssl req -x509 -newkey ed25519 -days 3650 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=AutoGov CA"

# 2. Серверный сертификат control plane (CN/SAN = ваш хостнейм)
openssl req -newkey ed25519 -nodes -keyout server.key -out server.csr \
  -subj "/CN=controlplane.internal"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -out server.crt

# 3. Клиентский сертификат агента
openssl req -newkey ed25519 -nodes -keyout agent.key -out agent.csr \
  -subj "/CN=agent-01"
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -out agent.crt
```

В `controlplane.json`: `tls.cert_file/key_file` = server.*, `tls.client_ca_file`
= ca.crt. В `agent.json`: `tls.client_cert_file/key_file` = agent.*, `tls.ca_file`
= ca.crt. Теперь `/ingest` принимает только агентов с валидным клиентским
сертификатом **и** токеном.

---

## 6. Оповещения и SIEM

`notify` в `controlplane.json`:

```json
"notify": {
  "min_severity": "medium",
  "syslog": [{ "network": "udp", "address": "10.0.0.10:514" }],
  "webhooks": [{ "url": "https://hooks.internal/autogov" }],
  "smtp": { "address": "mail.internal:25", "from": "autogov@corp", "to": ["soc@corp"] }
}
```

- **syslog/CEF** — находки уходят в Wazuh/Splunk в формате CEF (готово к SOC).
- **on-prem egress-guard**: в `mode: onprem` внешние адресаты (публичные IP)
  **отклоняются при старте** — защита от трансграничной передачи (Закон РК
  № 94-V). Чтобы разрешить (например, Telegram) — `allow_external_egress: true`
  с осознанием последствий.

---

## 7. Подписанные артефакты (проверка целостности агента, ТЗ §9)

Гарантирует, что на хосте запущен именно ваш неизменённый бинарник.

```bash
# 1. Один раз: сгенерировать релизный ключ (приватный храните офлайн!)
./bin/autogov-sign keygen -out-dir keys

# 2. При каждом релизе: подписать бинарники
./bin/autogov-sign sign -key keys/release.key -version 0.1.0 \
  -out manifest.json bin/agent bin/controlplane

# 3. Проверить (то же делает агент при старте)
./bin/autogov-sign verify -pub keys/release.pub -manifest manifest.json -dir bin
```

Разложите на хост `manifest.json` и публичный ключ, в `agent.json`:

```json
"release": {
  "manifest_path": "/etc/autogov/manifest.json",
  "public_key": "<содержимое release.pub>",
  "enforce": true
}
```

При `enforce: true` агент **откажется стартовать**, если его бинарник изменён
или подпись невалидна (fail-closed). При `enforce: false` — только предупреждение
(для плавного внедрения).

---

## 8. Управление ложными срабатываниями (whitelisting)

Легитимные (санкционированные ИТ) инстансы — в белый список, чтобы продукт не
«кричал» на CI/CD-контейнеры:

- В UI: у находки кнопка «В белый список».
- Через API (admin):

```bash
curl -H "Authorization: Bearer <admin>" -H "Content-Type: application/json" \
  -X POST https://cp/api/v1/whitelist \
  -d '{"kind":"image","pattern":"ci/*","reason":"sanctioned CI runners"}'
```

`kind`: `host` | `image` | `engine` | `instance` | `identity`; `pattern`
поддерживает `*` и `?`. Правило сразу пересчитывает находки.

---

## 9. Отчёты

Экспорт (роль admin):

```bash
curl -H "Authorization: Bearer <admin>" "https://cp/api/v1/reports/export?format=json" -o report.json
curl -H "Authorization: Bearer <admin>" "https://cp/api/v1/reports/export?format=csv"  -o findings.csv
curl -H "Authorization: Bearer <admin>" "https://cp/api/v1/reports/export?format=pdf"  -o report.pdf
```

JSON — машиночитаемый источник истины; CSV — находки для таблиц; PDF —
человекочитаемая сводка для CISO.

---

## 10. Проверка критериев приёмки (ТЗ §12)

На тестовом периметре с намеренно поднятыми «теневыми» инстансами:

1. Поднимите несколько n8n: в Docker, через `npx n8n`, только на `localhost:5678`,
   и на LAN. → все должны появиться в инвентаре.
2. Проверьте карту «креды → целевые системы» и риск-категории.
3. Снимите дамп трафика агента (`tcpdump`) — убедитесь, что **ни одного
   значения секрета** не уходит (только имена и SHA-256-отпечатки).
4. Разверните `mode: onprem` — убедитесь, что нет исходящих во внешние сервисы.
5. Проверьте, что находки приходят в Wazuh (syslog/CEF) и экспортируется отчёт.

---

## Частые вопросы

**Агент требует root?** Нет. Для Docker-инспекции нужен доступ к сокету
(read-only), для остального — обычные права. Без сокета функции деградируют, а
не отваливаются.

**Расшифровывает ли агент креды n8n?** Никогда. Только факт наличия, тип и
целевую систему.

**Работает ли в air-gapped?** Да: нет внешних зависимостей, PDF/подпись/
объяснения генерируются локально, вуль-фид — офлайн-файл.

**Windows-хосты?** В MVP — Linux-first. Windows-агент — Этап Э2.
