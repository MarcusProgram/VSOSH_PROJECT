# Генерация ключей для заказчиков

## Сгенерировать ключ

```
cd ~/Документы/VSOSH_PROJECT/server/tools
python generate_license.py
```

выдаст:
```
key:  6f7e380a65d19812369b40ef28ddc2bb
hash: 0c7e6f0a5a12ac0b497607d47aa1a18e6ee8073fa72768b7b28b345d234e12b9
```

или руками:
```
openssl rand -hex 16
echo -n "ключ" | sha256sum
```

## Что отдать заказчику

- папку admin/ (зипом)
- key
- hash

## Лог ключей

все выданные ключи сохраняются в `tools/licenses_log.json`
