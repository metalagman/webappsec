# Proof of Deploy

> [English version](README.md)

[`webappsec.metalagman.dev`](https://webappsec.metalagman.dev/ru/) — открытая демонстрация проверяемой цепочки поставки веб-сайта: исходный код → CI-сборка → подписанный артефакт → deployment → production-байты.

Сайт объясняет роль SBOM, CVE-сопоставления, SLSA provenance, воспроизводимой сборки, Sigstore/Cosign, подписанного deployment manifest, внешнего верификатора, браузерного SRI и `importmap.integrity`. Исходный код, конфигурации Cloudflare Worker и GitHub Actions опубликованы в этом репозитории.

## Локальная проверка

Требуется Node.js 22. Точные версии npm-зависимостей зафиксированы в `package-lock.json`.

```sh
npm ci
npm run check
npm run deploy:validate
npm run deploy:verifier:validate
```

`npm run deploy:validate` собирает сайт и выполняет локальный `wrangler deploy --dry-run`; сеть и учётные данные Cloudflare для этого не нужны.

## Онлайн-проверка текущего deployment

[`verify.webappsec.metalagman.dev`](https://verify.webappsec.metalagman.dev/ru/) автоматически проверяет релиз, который сейчас обслуживает основной сайт. Доверенный workflow GitHub Actions заранее проверяет подписи Cosign, аттестации, SBOM/CVE-доказательства и воспроизводимую сборку. При каждом открытии верификатора браузер отдельно скачивает production-файлы, сверяет их SHA-256 с подписанным манифестом, проверяет SRI для входного скрипта и таблицы стилей, полный `importmap.integrity` для всех JS-модулей и убеждается, что версия Worker не изменилась во время проверки.

Снимок для верификатора создаётся только после успешного запуска [Verify production](https://github.com/metalagman/webappsec/actions/workflows/verify-production.yml). Привилегированный workflow повторно проверяет неизменяемые доказательства релиза, deployment и верификации, собирает отдельный Worker `webappsec-verifier`, проверяет Version URL до переключения трафика и запускает hosted Chromium после публикации. Production разрешает credentialless CORS только для точного origin верификатора на запросы `GET`/`HEAD` и раскрывает только заголовки идентичности. Секреты остаются в GitHub Environment `production`; статические файлы верификатора их не содержат.

## Контракт деплоя Cloudflare

`wrangler.jsonc` описывает единственный Worker `webappsec`, Static Assets из `dist`, обязательный Worker-first wrapper, публичные Version URLs и Custom Domain `webappsec.metalagman.dev`. Custom Domain автоматически создаёт нужные DNS- и TLS-записи средствами Cloudflare Workers, поэтому отдельная конфигурация Terraform не требуется.

Worker отдаёт тело ответа, полученное от Static Assets binding, без преобразований. Он добавляет security headers, разделяет политику кэширования для content-hashed ресурсов и HTML, отклоняет неизвестные `Host` и перенаправляет HTTP-запросы к разрешённому хосту на HTTPS. На Version URLs Cloudflare добавляет `X-Robots-Tag: noindex`. Заголовки `X-Webappsec-Release` и `X-Webappsec-Worker-Version` берутся из Cloudflare Version Metadata; release workflow передаёт дайджест манифеста как version tag. До переключения трафика Cloudflare отдаёт tag со значением `unknown` на Version URL, поэтому preview gate связывает точные байты с version ID, а production gate после переключения требует дайджест манифеста.

Production job использует GitHub Environment `production` и два Environment secrets:

- `CLOUDFLARE_API_TOKEN` — custom token, ограниченный нужным аккаунтом Cloudflare и зоной `metalagman.dev`: **Account / Workers Scripts / Write** и **Zone / Workers Routes / Write**;
- `CLOUDFLARE_ACCOUNT_ID` — идентификатор аккаунта Cloudflare.

Для деплоя не требуются право DNS Write, Global API Key или доступ к другим зонам. Секреты задаются только в GitHub Environment и никогда не помещаются в репозиторий, артефакты релиза или логи.

Деплой обязан использовать подписанный content-addressed релиз, повторно проверять его до загрузки и вызывать зафиксированную версию Wrangler с тегом, равным дайджесту манифеста. Исходный код Worker, общий модуль content-addressing policy и `wrangler.jsonc` входят в манифест как входные файлы деплоя, поэтому их подмена меняет идентичность релиза.

Первый запуск выполняется вручную из SemVer-тега и создаёт Worker, Version URL и Custom Domain:

```sh
gh workflow run deploy.yml --ref <tag> -f release=<tag> -f bootstrap=true
```

Последующие публикации загружают новую версию без переключения трафика, проверяют её Version URL по точным байтам, SRI, security headers, `noindex` и в headless Chromium, после чего направляют 100% трафика на тот же `version_id`:

```sh
gh workflow run deploy.yml --ref <tag> -f release=<tag> -f bootstrap=false
```

Каждый успешный переход публикует отдельный неизменяемый GitHub Release `deployment-<action>-<tag>-<run-id>`. В нём находятся каноническая запись deployment, отчёт production-верификатора, их SHA-256 индекс и три keyless Cosign bundles. Запись фиксирует исходный релиз, дайджест манифеста, GitHub run, Wrangler `4.151.3`, версию Cloudflare Worker и deployment ID.

Откат (rollback) никогда не выбирает «предыдущую» версию автоматически. Оператор передаёт тег, дайджест манифеста, UUID версии Worker и подписанный Deployment Release. Workflow перепроверяет обе цепочки подписей и тег версии Cloudflare до переключения; `restore` использует те же явные поля:

```sh
gh workflow run rollback.yml --ref <workflow-tag> \
  -f action=rollback -f release=<target-tag> \
  -f manifest_digest=<sha256> -f version_id=<uuid> \
  -f deployment_release=<immutable-deployment-release>
```

Официальная документация: [Static Assets](https://developers.cloudflare.com/workers/static-assets/), [Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/), [Version URLs](https://developers.cloudflare.com/workers/versions-and-deployments/version-urls/), [Version Metadata](https://developers.cloudflare.com/workers/runtime-apis/bindings/version-metadata/), [API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

## SBOM и отчёты об уязвимостях

`npm run tools:evidence` устанавливает Syft `1.55.0` и Grype `0.121.0` для Linux amd64. Скрипт проверяет SHA-256 официальных release-архивов до распаковки. Версии и контрольные суммы находятся в `tools/install-evidence-tools.sh`, поэтому обновление инструментов является явным изменением репозитория.

После создания content-addressed релиза команда ниже формирует доказательства:

```sh
npm run evidence:generate -- --release .artifacts/releases/<manifest-sha256> --output .artifacts/evidence
```

Результат содержит runtime SBOM в SPDX 2.3 и CycloneDX 1.7, отдельный build SBOM в CycloneDX 1.7 и отдельные отчёты Grype для runtime и build. Runtime-документы перечисляют всю файловую систему релиза: публичные ассеты, исходный код Worker, конфигурацию деплоя и сам манифест; категории остаются различимыми, а каждый SHA-256 сверяется с манифестом. Build SBOM строится из полного `package-lock.json`, включает прямые и транзитивные зависимости и их связи. Все документы привязаны к одному и тому же дайджесту манифеста. В репозитории закреплены официальные JSON Schema SPDX и CycloneDX, и генератор валидирует документы до сканирования.

Отчёт об уязвимостях всегда содержит зафиксированную версию Grype, время сканирования, метаданные использованной базы, найденные и проигнорированные совпадения и точное состояние. `no-known-vulnerabilities` означает выполненное сканирование с нулём совпадений; `unavailable` или `not-scanned` содержит причину и завершает генерацию с ошибкой. Найденные CVE публикуются без искусственного порога серьёзности: это демо показывает проверяемый результат сканирования, а не задаёт продуктовую политику принятия риска.

## Независимая проверка production

Верификатор запускается из доверенного checkout, а не со страницы сайта:

```sh
git checkout v0.5.0
npm ci
npm run tools:signing
npm run verify:release -- --release v0.5.0 --rebuild
```

Команда принимает только явный SemVer-тег, скачивает соответствующий GitHub Release и проверяет Cosign bundles с точным GitHub OIDC issuer, репозиторием, путём workflow и ссылкой на тег. Затем она проверяет подписанный индекс доказательств, SLSA/CycloneDX in-toto subjects, содержимое SPDX/CycloneDX и завершённые отчёты об уязвимостях, воспроизводит манифест и tar из чистого checkout тега и только после этого проверяет production.

Production-слой скачивает каждый URL с `Accept-Encoding: identity`, ограничивает редиректы, размер и таймаут, отклоняет переход на другой origin и сверяет точный размер и SHA-256. HTML-парсер сопоставляет загружаемые браузером ссылки на скрипты и таблицы стилей с манифестом и ожидаемым SHA-384 SRI, не исполняя скачанный код. Он также требует каноническую import map перед entry-модулем, точный SHA-384 каждого JS-файла из манифеста и CSP-хеш самой import map. Полная response CSP хранится как подписанный `security-policy.txt`; Worker применяет её к ответам, а верификатор сравнивает заголовок побайтно. Читаемый и JSON-вывод содержат `pass`, `fail`, `unavailable` или `skipped` для каждого слоя. Низкоуровневая команда `npm run verify -- --manifest ./manifest.json` доступна для локальных HTTP-фикстур, но сама по себе не аутентифицирует манифест.

Код возврата `0` означает, что все обязательные проверки выполнены и пройдены; `1` — ошибка подписи, политики доказательств или production-байтов; `2` — неверный вызов CLI; `3` — обязательный сервис GitHub, Sigstore или production недоступен. Недоступная проверка никогда не засчитывается как успешная.

Workflow по расписанию [Verify production](https://github.com/metalagman/webappsec/actions/workflows/verify-production.yml) использует только явно заданную переменную репозитория `PRODUCTION_RELEASE_TAG`. Read-only job с `contents: read` берёт верификатор и зависимости из точного коммита доверенной ветки `main`; checkout тега находится в отдельном каталоге и читается только как исходные данные для воспроизводимой сборки. Ассеты релиза скачиваются отдельным доверенным шагом, а верификатор запускается без GitHub-токена и сохраняет точный JSON-отчёт как артефакт Actions на 90 дней. При ручном запуске требуется явно указать параметр `tag`.

Только после успешной проверки отдельный publisher job получает `contents: write` и короткоживущий `id-token: write`; учётные данные Cloudflare ему недоступны. Он повторно валидирует все девять слоёв, сохраняет точный JSON и детерминированный читаемый отчёт, связывает их SHA-256 индексом и записью верификации, подписывает каждый файл keyless Cosign и публикует неизменяемый Release `verification-<tag>-<run-id>`. Этот job ничего не разворачивает и не меняет production.

## Подписанный релизный конвейер

`.github/workflows/verify.yml` работает на pull request и `main` только с `contents: read`: устанавливает точную версию Node.js, восстанавливает зафиксированный граф npm-зависимостей, запускает unit- и браузерные проверки и dry-run Wrangler. Этот workflow не получает OIDC-токен, права записи релизов или секреты Cloudflare.

Публикация запускается только по неизменяемому SemVer-тегу через `.github/workflows/release.yml`. Единственный release job получает `contents: write` и короткоживущий `id-token: write`. Он дважды собирает манифест и нормализованный tar, сравнивает байты, создаёт SBOM/CVE-доказательства, SLSA v1 predicate и канонический `evidence-index.json`, затем подписывает манифест, tar и индекс через keyless Cosign. Отдельные in-toto bundles связывают SLSA predicate с манифестом и tar, а runtime/build CycloneDX — с tar. Политика подписи фиксирует issuer `https://token.actions.githubusercontent.com` и идентичность вида `https://github.com/metalagman/webappsec/.github/workflows/release.yml@refs/tags/<tag>`.

Cosign `3.1.3`, Syft `1.55.0` и Grype `0.121.0` скачиваются только по закреплённым URL и принимаются после проверки SHA-256. GitHub Actions вызываются по полным commit SHA. Релизный скрипт отказывается заменять уже существующий GitHub Release, сначала загружает полный набор ассетов в черновик и только затем публикует его. В настройках публичного репозитория должна быть включена **Release immutability**, чтобы с момента публикации GitHub запретил изменение релиза на стороне сервера.

Состав релиза можно локально перепроверить до криптографического слоя:

```sh
npm run evidence:verify -- .artifacts/publish
```

`evidence-index.json` перечисляет SHA-256 и размер канонического манифеста, content-addressed `<manifest-sha256>.tar`, SPDX/CycloneDX SBOM, двух отчётов об уязвимостях и SLSA predicate. Cosign bundles публикуются рядом как authentication envelopes; они не включаются в подписываемый индекс, чтобы избежать самоссылки.
