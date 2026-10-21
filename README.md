# Proof of Deploy

`webappsec.metalagman.dev` — открытая демонстрация проверяемой цепочки поставки веб-сайта: исходный код → CI-сборка → подписанный артефакт → deployment → production-байты.

Сайт объясняет роль SBOM, CVE-сопоставления, SLSA provenance, reproducible build, Sigstore/Cosign, подписанного deployment manifest, внешнего verifier и browser SRI. Исходный код, конфигурация Cloudflare Worker и GitHub Actions публикуются в этом репозитории.

## Локальная проверка

Требуется Node.js 22. Точные версии npm-зависимостей зафиксированы в `package-lock.json`.

```sh
npm ci
npm run check
npm run deploy:validate
```

`npm run deploy:validate` собирает сайт и выполняет локальный `wrangler deploy --dry-run`; сеть и Cloudflare credentials для этого не нужны.

## Cloudflare deployment contract

`wrangler.jsonc` описывает единственный Worker `webappsec`, Static Assets из `dist`, обязательный Worker-first wrapper, публичные Version URLs и Custom Domain `webappsec.metalagman.dev`. Custom Domain создаёт нужные DNS и TLS записи средствами Cloudflare Workers, поэтому Terraform и изменения в `home-lab` не требуются.

Worker отдаёт body, полученный от Static Assets binding, без преобразования. Он добавляет security headers, разделяет cache policy для content-hashed ресурсов и HTML, отклоняет неизвестные Host и перенаправляет разрешённый HTTP URL на HTTPS. На Version URLs добавляется `X-Robots-Tag: noindex, nofollow`. Заголовки `X-Webappsec-Release` и `X-Webappsec-Worker-Version` берутся из Cloudflare Version Metadata; release workflow передаёт digest manifest как version tag.

Production job использует GitHub Environment `production` и два Environment secrets:

- `CLOUDFLARE_API_TOKEN` — custom token, ограниченный нужным account и зоной `metalagman.dev`: **Account / Workers Scripts / Write** и **Zone / Workers Routes / Write**;
- `CLOUDFLARE_ACCOUNT_ID` — идентификатор Cloudflare account.

Токену не нужны DNS Write, Global API Key или доступ к другим зонам. Секреты задаются только в GitHub Environment и никогда не помещаются в репозиторий, release artifact или логи.

Deploy обязан использовать подписанный content-addressed release, повторно проверить его до загрузки и вызвать pinned Wrangler с tag, равным digest manifest. Worker source, общий модуль content-addressing policy и `wrangler.jsonc` входят в manifest как deploy inputs, поэтому их подмена меняет release identity.

Официальная документация: [Static Assets](https://developers.cloudflare.com/workers/static-assets/), [Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/), [Version URLs](https://developers.cloudflare.com/workers/versions-and-deployments/version-urls/), [Version Metadata](https://developers.cloudflare.com/workers/runtime-apis/bindings/version-metadata/), [API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

## SBOM и vulnerability evidence

`npm run tools:evidence` устанавливает Syft 1.55.0 и Grype 0.121.0 для Linux amd64. Скрипт проверяет SHA-256 официальных release-архивов до распаковки. Версии и checksums находятся в `tools/install-evidence-tools.sh`, поэтому обновление инструментов является видимым изменением репозитория.

После создания content-addressed release команда ниже формирует evidence:

```sh
npm run evidence:generate -- --release .artifacts/releases/<manifest-sha256> --output .artifacts/evidence
```

Результат содержит runtime SBOM в SPDX 2.3 и CycloneDX 1.7, отдельный build SBOM в CycloneDX 1.7 и отдельные Grype reports для runtime/build. Runtime documents перечисляют весь release filesystem: публичные assets, Worker runtime source, deployment configuration и сам manifest; категории остаются различимыми, а каждый SHA-256 сверяется с manifest. Build SBOM строится из полного `package-lock.json`, включает прямые и транзитивные зависимости и их связи. Все документы связываются с тем же manifest digest. В репозитории закреплены официальные JSON Schema SPDX и CycloneDX, и генератор валидирует документы до сканирования.

Vulnerability report всегда содержит pinned-версию Grype, время scan, metadata использованной базы, найденные и ignored matches и точное состояние. `no-known-vulnerabilities` означает выполненный scan с нулём совпадений; `unavailable`/`not-scanned` содержит причину и завершает генерацию с ошибкой. Найденные CVE публикуются без выдуманного severity gate: этот demo показывает проверяемый результат сканирования, а не задаёт продуктовую политику принятия риска.

## Независимая проверка production

Verifier запускается из доверенного checkout, а не со страницы сайта:

```sh
git checkout v0.1.1
npm ci
npm run tools:signing
npm run verify:release -- --release v0.1.1 --rebuild
```

Команда принимает только явный SemVer tag, скачивает соответствующий GitHub Release и проверяет Cosign bundles с точным GitHub OIDC issuer, repository, workflow path и tag ref. Затем она проверяет signed evidence index, SLSA/CycloneDX in-toto subjects, SPDX/CycloneDX content и завершённые vulnerability reports, воспроизводит manifest/tar из чистого tag checkout и только после этого проверяет production.

Production-слой скачивает каждый URL с `Accept-Encoding: identity`, ограничивает redirects, размер и timeout, отклоняет переход на другой origin и сравнивает точные size/SHA-256. HTML parser сопоставляет browser-loaded script/stylesheet references с manifest и единственным ожидаемым SHA-384 SRI, не исполняя скачанный код. Human и JSON output содержат `pass`, `fail`, `unavailable` или `skipped` для каждого слоя. Низкоуровневая команда `npm run verify -- --manifest ./manifest.json` доступна для локальных HTTP fixtures, но сама по себе не аутентифицирует manifest.

Exit code `0` означает, что все обязательные проверки выполнены и прошли; `1` — ошибка подписи, evidence policy или production bytes; `2` — неверный вызов CLI; `3` — обязательный GitHub/Sigstore/production service недоступен. Недоступная проверка никогда не становится pass.

Scheduled workflow [Verify production](https://github.com/metalagman/webappsec/actions/workflows/verify-production.yml) использует только явно заданный repository variable `PRODUCTION_RELEASE_TAG`, сохраняет JSON report на 90 дней и не получает write/OIDC/deployment credentials. Verifier и его зависимости берутся из trusted `main`; tag checkout находится в отдельном каталоге и читается только как source data для воспроизводимой сборки. Release assets скачиваются отдельным trusted step, а verifier запускается без GitHub token. Ручной запуск требует явный tag input.

## Signed release pipeline

`.github/workflows/verify.yml` работает на pull request и `main` только с `contents: read`: устанавливает точную версию Node.js, locked npm graph, запускает unit/browser checks и dry-run Wrangler. Этот workflow не получает OIDC token, release write permission или Cloudflare secrets.

Публикация запускается только immutable SemVer tag через `.github/workflows/release.yml`. Единственный release job получает `contents: write` и короткоживущий `id-token: write`. Он дважды собирает manifest и normalized tar, сравнивает байты, создаёт SBOM/CVE evidence, SLSA v1 predicate и канонический `evidence-index.json`, затем подписывает manifest, tar и index через keyless Cosign. Отдельные in-toto bundles связывают SLSA predicate с manifest и tar, а runtime/build CycloneDX — с tar. Signer policy фиксирует issuer `https://token.actions.githubusercontent.com` и identity вида `https://github.com/metalagman/webappsec/.github/workflows/release.yml@refs/tags/<tag>`.

Cosign 3.1.3, Syft 1.55.0 и Grype 0.121.0 скачиваются только по закреплённым URL и принимаются после SHA-256 проверки. GitHub Actions вызываются по полным commit SHA. Release script отказывается заменять уже существующий GitHub Release, сначала загружает полный набор assets в draft и только затем публикует его. В настройках публичного репозитория должна быть включена **Release immutability**, чтобы с момента публикации GitHub запретил изменение release на стороне сервера.

Состав release можно локально перепроверить до криптографического слоя:

```sh
npm run evidence:verify -- .artifacts/publish
```

`evidence-index.json` перечисляет SHA-256 и размер canonical manifest, content-addressed `<manifest-sha256>.tar`, SPDX/CycloneDX SBOM, двух vulnerability reports и SLSA predicate. Cosign bundles публикуются рядом как authentication envelopes; они не включаются в подписываемый index, чтобы избежать самоссылки.
