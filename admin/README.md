# WAF с ML

## 1. Создание бота

@BotFather - находим этого бота и пишем ему:
```
/newbot
```

придумать название и username для бота

он выдаст токен:
```
7555826056:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

скопировать его

---

## 2. Настройка

```
cp .env.example .env
```

открыть .env, вставить:
```
TELEGRAM_BOT_TOKEN=токен_от_botfather
LICENSE_KEY_HASH=хэш_от_владельца
```

---

## 3. Запуск

```
docker compose up -d --build
```

проверить:
```
docker compose ps
```

должно быть 4 сервиса Up

---

## 4. Активация бота

в телеге пишем своему боту:
```
/activate ключ_от_владельца
```

---

## 5. Проверка

http://localhost:8081 - тестовый сайт

кликаем на любую атаку - в телегу приходит уведомление

---

## 6. Проверка ML

```
curl "http://localhost:8082/test?text=SELECT * FROM users WHERE id=1"
```

ответ:
```json
{
  "ml_prediction": "SQLI", 
  "ml_confidence": "89.3%",
  "action": "block"
}
```

другие примеры:
```
curl "http://localhost:8082/test?text=<script>alert(1)</script>"
curl "http://localhost:8082/test?text=; cat /etc/passwd"
curl "http://localhost:8082/test?text=../../../etc/passwd"
```

---

## 7. Блокировка

в уведомлении есть кнопки - жмёшь "Блок 1 час", ждёшь 5 сек

проверить:
```
curl http://localhost:8081/waf/blocklist
```

---

## 8. Команды

```
docker compose up -d          # запуск
docker compose down           # стоп
docker compose logs -f        # логи
docker compose restart        # рестарт
```
