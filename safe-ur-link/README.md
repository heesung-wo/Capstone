# SafeURLink (v0.6.6 · URL 입력창 기본 편집 기능 복원)

Chrome / Whale MV3 확장 프로그램. 알려진 악성 URL을 접속 전에 차단하고, 휴리스틱으로 위험도를 평가합니다.

## 추가 기능: 시그니처 공유 웹사이트 (웹 검사기)

**기존 확장 프로그램과 같은 `signatures.json` + 동일한 `core/scan.js` 판정 엔진**을 사용해 웹사이트에서 URL을 직접 검사합니다. 원래 ZIP에 포함된 시그니처 JSON은 수정하지 않았습니다.

- **배포 주소**: <https://heesung-wo.github.io/Capstone/> (해당 GitHub 저장소에서 Actions가 정상 배포된 이후)
- **웹사이트 소스**: `public/index.html`, `public/assets/css/site.css`, `public/assets/js/{site,scan-worker}.js`
- **공통 검사 엔진**: `core/common.js`, `core/scan.js`, `core/remote-feed.js`, `shared/render.js` — 확장 프로그램과 웹사이트가 같은 판정 정책을 사용
- **피드**: 웹사이트는 같은 경로의 `./signatures.json`을 읽습니다. 별도의 API 키나 서버가 필요하지 않습니다. 검사할 URL로 직접 HTTP 요청을 보내지 않습니다.
- **대용량 대응**: 웹 워커에서 JSON을 검증·인덱싱하여 화면 응답성을 유지합니다. 업데이트 실패 시 이미 로드한 이전 피드는 메모리에서 유지합니다.
- **데모 상태**: 이 ZIP의 `public/signatures.json`에는 `.test` URL 두 개만 있습니다. 실제 DB가 GitHub Actions로 배포되어야 실제 위협 피드로 검사할 수 있습니다.
- **기존 확장 프로그램과 차이**: 사용자 개인의 허용/차단 목록 및 브라우저별 IndexedDB 내용은 웹사이트와 자동으로 공유되지 않습니다. 동일한 공개 시그니처를 바탕으로 한 **수동 검사**만 수행하며, 웹사이트 자체가 페이지 탐색을 차단하는 기능은 아닙니다.

### 로컬에서 실행

프로젝트의 `safe-ur-link/` 폴더에서 다음 명령을 실행합니다.

```bash
npm run stage:site
python -m http.server 8000 --directory public
```

브라우저에서 `http://localhost:8000/`을 열고 `https://phishing.test/login`, `http://malware.test/demo`로 테스트합니다. `index.html` 파일을 `file://`로 직접 열면 워커·JSON 로딩이 제한될 수 있습니다.

### GitHub Pages 배포

`.github/workflows/update-signatures.yml`은 기존 시그니처 수집 뒤 `npm run stage:site`로 **공통 검사 모듈을 `public/core/`, `public/shared/`에 복사**하고 `public/` 전체를 배포합니다. `scripts/build-feed.mjs`는 더 이상 검사 웹사이트의 `index.html`을 시그니처 안내 페이지로 덮어쓰지 않고, 데이터 출처 고지를 `notices.html`로 생성합니다.

기존 저장소의 Actions 비밀 키, `PUBLISH_*`, 재배포 허가 및 Pages 설정은 **그대로 유지**해야 합니다. 기존 운영용 워크플로의 값을 ZIP의 예시 설정으로 무작정 덮어쓰지 마세요. `public/`, `core/`, `shared/`, `scripts/` 변경도 워크플로 배포 트리거에 반영했습니다.

## v0.6.6 URL 입력창 편집 개선

- **Backspace, Delete, Space, 방향키, Home/End, 일반 타이핑** 등 입력창 기본 편집 동작을 브라우저에 맡깁니다.
- **Ctrl+A / Cmd+A** 는 입력창에 포커스가 있으면 네이티브 전체 선택을 수행하며, 검사 버튼 등에 포커스가 있을 때도 입력창 전체 선택이 가능하게 유지합니다.
- **Ctrl+V / Cmd+V, 마우스 메뉴 붙여넣기** 는 브라우저 기본 붙여넣기를 사용합니다. 비표준 `clipboard.readText()` 처리, 붙여넣기 후 자동 검사 및 `preventDefault()`를 제거했습니다. **검사는 Enter 또는 검사 버튼**으로 실행합니다.
- URL 검사 성공/실패 후 입력창에 포커스를 되돌려 바로 수정할 수 있습니다. 사용하지 않게 된 `clipboardRead` 권한을 제거했습니다.
- **기존 기능 유지:** 선택한 URL 텍스트만 검사하는 우클릭 메뉴, 누적 DB, DNR 실시간 보호, GitHub Actions 워크플로는 변경하지 않았습니다.
- **적용:** 기존 폴더를 덮어쓰고 Chrome/Whale 확장 프로그램 관리 화면에서 새로고침(↻). 확장 프로그램을 삭제하면 로컬 DB에 영향이 있을 수 있으니 기존 설치 경로를 유지하세요. GitHub Actions 재배포는 필요 없습니다.

## 이전 v0.6.5 변경 이력


Chrome / Whale MV3 확장 프로그램. 알려진 악성 URL을 접속 전에 차단하고, 휴리스틱으로 위험도를 평가합니다.

## v0.6.5 우클릭 메뉴 간소화 (이전 기능 유지)

- **우클릭 검사:** `SafeURLink: 선택한 URL 텍스트 검사` 메뉴 하나만 제공합니다. 드래그해 선택한 문자열(`selectionText`)만 전달하며, 하이퍼링크의 실제 주소(`linkUrl`)나 페이지 URL(`pageUrl`)로 대체하지 않습니다.
- **제거:** `SafeURLink: 링크의 실제 주소 검사` 메뉴(`check-link`)를 삭제했습니다. 설치·업데이트·브라우저 시작 시 기존 메뉴를 초기화하고 선택 검사 메뉴만 등록합니다.
- **URL 형식 검증:** 일반 문구를 드래그한 경우 잘못된 URL이라고 안내합니다.
- **직접 검사:** `Ctrl+A` / `Cmd+A` 기능은 유지합니다.
- **그 외 기능:** 누적 시그니처 DB, 시그니처 동기화, 실시간 보호, GitHub Actions 워크플로는 변경하지 않았습니다.

### 기존 설치본 업데이트

1. **기존 `safe-ur-link/` 폴더에 패치 파일을 덮어씁니다.** 확장 프로그램을 삭제하지 마세요. 기존 확장 ID와 로컬 DB를 유지하기 위해 같은 경로에서 업데이트하는 것이 좋습니다.
2. Chrome의 `chrome://extensions` 또는 Whale 확장 프로그램 관리 화면에서 SafeURLink **새로고침(↻)** 을 누릅니다.
3. 일반 웹페이지에서 URL 문자열을 드래그해 우클릭한 다음 `SafeURLink: 선택한 URL 텍스트 검사`를 누릅니다. 결과 탭에 선택한 URL만 표시되는지 확인하세요.
4. 실제 링크 주소 검사 메뉴가 사라졌는지도 확인하세요. 메뉴가 그대로 보이면 확장 프로그램을 새로고침하고 브라우저도 재시작해 보세요.

> GitHub Actions를 다시 배포할 필요는 없습니다. 워크플로의 기존 `PUBLISH_*` / `REDISTRIBUTION_CONFIRMED` 설정은 변경하지 마세요.

## 구조 (API 키가 사용자에게 노출되지 않는 방식)

```text
[GitHub Actions, 하루 1회]                     [GitHub Pages]                  [사용자 브라우저]
 비밀 키(Secrets)로 URLhaus 등 수집  ──▶  signatures.json (키 없음, 공개)  ──▶  확장 프로그램이 다운로드
```

- 외부 위협 정보 API와 비밀 키는 **GitHub Actions 안에서만** 사용됩니다.
- 확장 프로그램은 `core/config.js`의 `SIGNATURE_FEED_URL` 하나만 내려받습니다. **사용자는 키를 입력하지 않습니다.**
- 다운로드한 데이터는 `core/remote-feed.js`가 검증한 뒤 IndexedDB에 **덮어쓰기형 UPSERT**로 누적 저장합니다. 기존 소스 전체를 삭제하지 않습니다.
- GitHub Actions는 `PREVIOUS_FEED_URL`에 있는 직전 `signatures.json`을 다운로드해 새 수집 결과와 병합합니다. 따라서 **새로 설치한 사용자도 과거 누적 이력**을 받을 수 있습니다.
- 기존 피드에 있었지만 최신 수집에서 빠진 URL은 `meta.active=false`로 보존합니다. 수집 실패한 소스는 메타데이터도 변경하지 않습니다.
- **수집량 변경이 반영되려면** 수정된 `scripts/build-feed.mjs`를 GitHub에 반영하고 Actions를 재실행하여 Pages의 `signatures.json`을 새로 배포해야 합니다. 브라우저의 **지금 업데이트** 버튼은 이미 배포된 파일만 내려받습니다.

## 개발자 설정 (한 번만)

저장소 이름이 `Capstone`이고 이 프로젝트가 `safe-ur-link/` 하위 폴더라는 전제입니다.
워크플로 파일은 **저장소 루트** `.github/workflows/update-signatures.yml`에 있어야 GitHub가 인식합니다.

1. **Secrets 등록**: Settings → Secrets and variables → Actions → *Secrets*
   - `ABUSE_CH_AUTH_KEY` : https://auth.abuse.ch/ 에서 발급 (URLhaus, ThreatFox)
   - `PHISHTANK_KEY` : 선택
2. **Variables 등록**: 같은 화면의 *Variables* 탭
   - `PHISHTANK_USER_AGENT` : 식별 가능한 문자열 (예: `phishtank/내아이디`)
3. **Pages 소스 변경**: Settings → Pages → Build and deployment → Source: **GitHub Actions**
4. **이전 배포 피드 설정**: `.github/workflows/update-signatures.yml`의 `PREVIOUS_FEED_URL`을 현재 Pages에 배포한 `signatures.json` 주소와 동일하게 맞춥니다. 기본 예시는 `https://heesung-wo.github.io/Capstone/signatures.json`입니다.
   - 주소가 404면 안전을 위해 빌드가 중단됩니다. **정말 최초 배포일 때만** `ALLOW_FIRST_DEPLOY: 'true'`로 한 번 실행하고, 성공 후 `'false'`로 복원하세요.
   - 이전 피드가 5xx·잘못된 JSON 등의 오류를 반환해도 빌드를 중단하여 기존 누적 데이터를 덮어쓰지 않습니다.
5. **첫 배포/갱신**: Actions 탭 → *Build and deploy signatures* → *Run workflow*
   - `PUBLISH_*`가 모두 `false`이면 `.test` 도메인만 생성합니다. **이전 실제 시그니처가 있는 상태에서 모두 `false`로 바뀌면** 실수로 배포를 지우지 않도록 오류가 발생합니다.
6. 배포 후 `https://<계정>.github.io/Capstone/signatures.json` 이 열리는지 확인하고, 다르면 `core/config.js`와 `manifest.json`의 `host_permissions`를 맞춥니다.
7. **실제 데이터 공개**: 각 소스의 약관에서 공개 재배포가 허용되는지 확인한 뒤, 워크플로의 해당 `PUBLISH_*`와 `REDISTRIBUTION_CONFIRMED`를 `'true'`로 바꿉니다. (`PUBLISH_URLHAUS`, `PUBLISH_THREATFOX`, `PUBLISH_PHISHTANK`, `PUBLISH_PHISHING_DB`)

> `signatures.json`은 누구나 내려받을 수 있는 공개 파일입니다. 키는 들어가지 않지만 수집한 URL 목록은 공개됩니다.

> **PhishTank 404가 계속 발생한다면:** `PHISHTANK_KEY`가 공식 피드 다운로드에 유효한지 확인하고 `PHISHTANK_USER_AGENT` 변수를 `phishtank/사용자아이디`처럼 식별 가능하게 입력하세요. 익명 공개 피드는 일일 다운로드 횟수 제한을 받을 수 있습니다.

> **부분 실패 시 보존 정책(v0.6.2 이후 유지):** 워크플로 기본 `OPTIONAL_SOURCES: 'PhishingDB,PhishTank'`. 선택 소스에서 수집 실패가 발생해도 이전 공개 피드에 있던 해당 소스 기록을 **그대로 유지**하고, 다른 성공한 소스만 갱신합니다. 이전 데이터 자체가 없으면 `unavailable`로 표시합니다. 필수 소스 실패나 전체 소스 실패는 배포하지 않습니다.

> **기존 GitHub Actions 설정 유지:** 이 ZIP에는 공개 설정 예시가 `false`인 `.github/workflows/update-signatures.yml`이 함께 들어 있습니다. GitHub 저장소에서 이미 `PUBLISH_*` / `REDISTRIBUTION_CONFIRMED`를 `true`로 변경해 운영 중이라면, 이 파일을 그대로 덮어써서 다시 `false`로 만들지 마세요. v0.6.4의 우클릭 수정은 수집 스크립트와 GitHub Actions 설정을 변경하지 않습니다. GitHub의 기존 워크플로 활성화 설정을 보존해야 합니다.

## 확장 프로그램 설치 (개발자 모드)

`manifest.json`이 있는 `safe-ur-link` 폴더를 Chrome/Whale 확장 프로그램 관리 페이지에서 로드합니다.
설치하면 자동으로 데이터를 받아오며, 설정 페이지의 **지금 업데이트**로 수동 갱신할 수 있습니다(1분 간격 제한).

## 동작 정책

| 항목 | 값 |
|---|---|
| Actions 수집 주기 | 하루 1회 (KST 12:17경), 수동 실행 가능 |
| 확장 프로그램 확인 주기 | 6시간 (알람은 1시간마다 확인, 실패 시 1시간 후 재시도) |
| 일시적 오류(5xx, 429, 네트워크) | 소스별로 최대 2회 재시도 (5초, 20초 간격) |
| PhishTank 404 | 공식 JSON → 공식 CSV, 키가 있는 경우 공개 JSON → 공개 CSV 순서로 대체 시도. 401/403/429/509는 우회하지 않음 |
| PhishingDB 404/408/500/502/503/504·연결 실패·내용 오류 | 공식 GitHub 저장소의 `phishing-links-ACTIVE.txt` 원본으로 한 번 대체 조회. 403/429는 우회하지 않음 |
| 수집 일부 실패 시 | 필수 소스 실패 또는 모든 소스 실패 → 빌드 중단. 선택 소스 실패 → 이전 피드의 해당 소스 이력 유지 및 다른 성공 소스만 추가 |
| 누적 이력 갱신 | 성공한 소스에 새로 있는 URL은 `active=true`로 갱신하고, 사라진 과거 URL은 `active=false`로 보존. 실패한 소스는 변경하지 않음 |
| 이전 피드 로딩 오류 | 배포 중단(새 배포로 이전 이력이 소실되는 것을 방지). 404는 최초 배포를 명시적으로 허용한 경우에만 통과 |
| 소스별 수집 상한 | **없음**. 현재 선택한 각 공급자 피드의 HTTP(S) URL을 정규화·소스별 중복 제거 후 모두 보존 |
| 전체 시그니처 건수 제한 | 기존 코드의 **300,000건** 검사 제거. 단, GitHub Pages 크기/대역폭, 브라우저 디스크·메모리 제약은 남음 |
| 실시간 보호에만 적용하는 상한 | URLhaus 9,000 / PhishTank 9,000 / PhishingDB 9,000 / ThreatFox 2,700. 중복 URL은 DNR 규칙 하나로 합산 |

## 실시간 보호: 위협 DB는 BLOCK / 사용자 차단 목록은 REDIRECT

Manifest V3의 `chrome.declarativeNetRequest`를 사용합니다. 실시간 보호는 **메인 프레임 이동(`main_frame`)**에 적용되고, 일반 사이트의 네트워크 요청은 별도 실시간 서버 조회 없이 기존처럼 처리됩니다.

| 시그니처/목록 | DNR 동작 | 사용자 화면 |
|---|---|---|
| `지금 업데이트`로 받은 URLhaus / PhishTank / PhishingDB / ThreatFox | `block` (우선순위 10) | Chrome 기본 차단 오류 화면(예: `ERR_BLOCKED_BY_CLIENT`) |
| 사용자가 설정에 입력한 차단 도메인(+하위 도메인) | `redirect` (우선순위 20) | SafeURLink 경고 페이지. `이 URL 접속` 시 해당 탭·URL 세션 허용 |
| 사용자 허용 도메인 | `allow` (우선순위 30) | 정상 접속 |
| 어느 곳에도 일치하지 않는 주소 | 규칙 없음 | 정상 접속(안전성 보증은 아님) |

**자동 BLOCK은 최신 수집 목록에서 확인된 항목만 대상으로 하고, 7일 이상 갱신되지 않은 항목이나 과거 이력(active=false)은 자동 차단하지 않습니다.** 수동 URL 검사는 전체 누적 이력을 검색하고, 과거 이력만 발견되면 현재 악성 여부는 미확정임을 알립니다.

**자동 BLOCK 여부에는 위험 점수 임계값을 사용하지 않습니다.** 다만 **실시간 보호 전용**으로 각 소스의 최대 선정 건수를 제한하므로 DB에 있어도 자동 차단되지 않는 URL이 생길 수 있습니다. 수동 검사에는 전체 DB를 사용하고 위험 점수를 표시합니다.

### 건수 제한 (Chrome 121 이상)

- 동적 DNR **총 30,000개** (안전한 `block`/`allow` 포함). `redirect`는 별도 **최대 5,000개** 제한이 있고, 이 역시 총 30,000개 안에 포함됩니다.
- 시그니처 자동 `block` **최대 29,700개**, 사용자 지정 차단 도메인의 `redirect` **최대 300개**로 제한합니다. 실시간 보호는 `core/dnr.js`의 `REALTIME_SOURCE_LIMITS`를 따라 소스별로 9,000 / 9,000 / 9,000 / 2,700건을 선별합니다. 사용자 `allow` 규칙도 동적 규칙을 소비하므로, 총 한도를 넘길 때는 시그니처 block을 먼저 줄입니다.
- 네 소스의 **전체 수집량에는 상한이 없지만** 소스별 선정 제한, 동일 URL 중복, 필터로 표현할 수 없는 URL, 사용자 허용/차단 우선 처리로 인해 실제 적용 block 규칙은 29,700개보다 적을 수 있습니다. 미반영 URL도 IndexedDB에 남아 수동 검사할 수 있습니다.
- 각 소스 상한을 넘으면 **최근 확인된 출처의 교차 탐지 수 → online → valid(PhishTank) → verified → confidence → 마지막 확인 시각 → 최근 등록 시각** 기준으로 선정합니다. 이는 선정 우선순위일 뿐, 개별 URL의 차단 여부에 위험 점수 임계값을 두는 것이 아닙니다. `PhishTank online-valid` 피드는 유효/온라인/검증된 URL만 제공하므로 필드 값이 모두 같을 수 있습니다.
- DNR 필터의 와일드카드 메타 문자(`*`, `^`, `|`)를 포함하는 URL 등 정확한 조건을 만들 수 없는 항목은 과잉 차단 방지를 위해 규칙으로 만들지 않습니다. 설정 화면에서 *미포함 개수*를 확인할 수 있습니다.
- `/core/dnr.js`에서 `MAX_PROTECTION_RULES=30000`으로 관리하며, Chrome 121 미만의 브라우저에서는 설치되지 않도록 `manifest.json`의 `minimum_chrome_version`을 121로 관리합니다.

### 업데이트 및 검증

1. Chrome/Whale에서 `chrome://extensions` → 개발자 모드 → **압축해제된 확장 프로그램 로드**로 `safe-ur-link/` 폴더를 설치/다시 로드합니다. 기존 버전에서 업그레이드하는 경우에는 **확장 프로그램 새로고침** 후 설정 저장을 눌러 이전 redirect 규칙을 교체합니다.
2. 설정 → **지금 업데이트**를 선택합니다. URL 검사에 쓰이는 동일한 다운로드 시그니처 DB로부터 DNR `block` 규칙을 재생성합니다. 데이터 변경이 없으면 기존 규칙을 유지하며, 설정 저장 시에도 재구성합니다.
3. 수집/배포가 정상이고 시그니처가 충분하면 **DB 자동 차단 최대 29,700개**이며, 사용자 차단은 **최대 300개**입니다. `DNR 적용`, `DB 자동 차단`, `사용자 경고`, `허용`, `한도 초과` 수치를 확인합니다.
4. 위험한 서버에 접속할 필요 없이 확장 프로그램 서비스 워커 DevTools Console에서 다음을 실행해 실시간 차단 조건을 확인할 수 있습니다.

```javascript
const rules = await chrome.declarativeNetRequest.getDynamicRules();
console.table(rules.reduce((m, rule) => { m[rule.action.type] = (m[rule.action.type] || 0) + 1; return m; }, {}));
// 기대 결과: 대부분 block, 사용자가 등록한 차단 도메인은 redirect
```

5. 피드가 **없는 초기 상태 또는 Demo 피드만** 받은 경우, 안전한 시연용 URL인 `https://phishing.test/login`은 **Chrome 자체의 차단 오류**가 나와야 합니다. 실제 위협 피드를 받은 이후에는 시연용 규칙을 자동 추가하지 않습니다. 설정 → 사용자 차단 목록에 `manual-test.test`를 입력하고 `https://manual-test.test/a`를 열면 **SafeURLink 경고 페이지**가 나와야 합니다.
6. 정상 사이트 접속 유지도 점검합니다. 확장 프로그램 자체가 DNR 규칙을 거절한 경우에는 **이전 정상 규칙을 유지**하고 설정 화면에 오류를 표시합니다.

> 단, 시그니처 피드에 등록된 URL에도 오탐이나 오래된 항목이 포함될 수 있습니다. 현재 정책은 사용자의 요청대로 *피드에 있는 항목을 자동 차단*합니다. 이 정책의 장단점 및 미포함 URL은 졸업작품 보고서에 구분해서 기록하는 것이 좋습니다.

> **범위**: DNR `main_frame`에 대한 정확한 URL 차단 및 사용자 지정 도메인 경고입니다. 페이지 내 이미지·스크립트·하위 프레임까지 모든 악성 요청을 차단하는 기능을 의미하지 않습니다. 사이트의 서비스 워커 캐시 등 일부 요청에는 DNR이 적용되지 않을 수 있습니다.

## 수집량 확대 시 알아둘 점

- **누적 이력 보존 ≠ 위험 영구 확정.** 과거 URL은 사라져도 저장하지만, 수동 검사는 이력 사실만 알리고 자동 차단에서는 제외합니다. 악성 이력을 영구 삭제하지 않는 만큼 오탐·개인정보·용량 관리를 위한 별도 관리 정책이 필요합니다.
- **수집량 무제한 ≠ 공급자가 보유한 전체 이력 다운로드.** 이 버전은 원본 API 응답 건수에 인위적인 건수 제한을 적용하지 않지만, 현재 수집 URL 자체에 범위가 있습니다.
  - **URLhaus**: `core/feeds.js`는 인증된 `recent.csv`를 사용합니다. 공식 문서상 최근 30일 등록 데이터 기준이며, 더 넓은 `full` 덤프(활성 또는 90일 내 등록)는 별도 제공됩니다. 더 넓은 덤프 사용은 인증 계정에서 공식 제공되는 실제 다운로드 경로와 형식을 확인하고 수정해야 합니다.
  - **PhishTank**: 공식 `online-valid.json`을 사용합니다. 원래부터 검증되고 온라인인 피싱 URL만 제공하므로, 신고만 되었거나 오프라인인 전체 과거 데이터까지 받을 수는 없습니다.
  - **ThreatFox**: `get_iocs` API는 공식적으로 최근 **최대 7일**만 지원합니다. 오래된 IOC까지 포함하려면 별도 데이터 export를 사용해야 하며, 6개월 이상 지난 IOC는 만료되어 API/Export에서 제외됩니다. 단순히 건수 제한만 없앤다고 과거 전체를 받는 것은 아닙니다.
  - **PhishingDB**: `phishing-links-ACTIVE.txt`에서 공개되는 해당 시점의 목록만 받습니다.
- **누적 배포의 한계**: 이 버전은 이전 `signatures.json` 전체를 매번 다운로드·병합·재공개합니다. 신규 URL만 전송하는 실제 델타 프로토콜은 아닙니다. 장기적으로는 원본 데이터 보관소와 날짜별 변경분/청크 파일로 개선해야 합니다.
- **공개 배포 한계**: GitHub Pages 게시 사이트 최대 1GB / 월 소프트 대역폭 100GB. 방대한 피드의 단일 JSON 생성·파싱·IndexedDB 저장·규칙 정렬은 메모리/시간을 소비합니다. 이 버전은 20만 건 모의 데이터 단위 테스트를 통과했지만, 실제 제공자의 최대 데이터 크기 및 모든 사용자 환경에서의 동작을 보증하지 않습니다. 데이터가 수백 MB 이상이면 파일을 소스별·청크별로 나누고 네트워크 전송도 증분 업데이트하는 후속 개선이 필요합니다.
- **저장 권한**: `manifest.json`에 `unlimitedStorage`를 추가해 확장 프로그램 IndexedDB의 기본 저장 할당량 문제를 완화합니다. 물리적 디스크, 전송량, 실행 메모리는 여전히 유한합니다.
- **재배포 주의**: GitHub Pages에는 전체 URL 시그니처가 공개됩니다. 각 공급자의 데이터 재배포 허가/조건을 반드시 확인하세요. 워크플로의 `PUBLISH_*`와 `REDISTRIBUTION_CONFIRMED`는 이전과 같이 기본 `false`입니다.

## 로컬 개발

```bash
cd safe-ur-link
npm test                 # 단위 테스트 (DNR 규칙 한도·우선순위 포함)
npm run build:feed       # public/signatures.json 생성 (환경변수 없으면 시연 데이터)
```

## 유의 사항

- 외부 DB에 없는 URL을 안전하다고 단정할 수 없습니다. UI 판정 `No Threat Detected`는 "위협 미탐지"를 뜻합니다.
- Phishing.Database의 ACTIVE 피드는 `verified`, 등록 시각, 개별 URL의 정확한 현재 응답 상태를 제공하지 않습니다. `meta.active=true`는 **그날 다운로드 목록에 실렸음**을 나타낼 뿐, 사이트가 실제로 현재 접속 가능한 상태임을 증명하지 않습니다. 모든 URL을 수동 검사 DB에 저장하며, 실시간 보호만 상위 9천 건을 사용합니다(동점이면 URL 문자열 순).
- Phishing.Database는 MIT 라이선스입니다. 공개하면 `signatures.json`(`notices`)과 Pages 첫 화면에 저작권·라이선스 고지가 함께 실립니다.
- OpenPhish 무료 피드는 비상업 용도로 제한되고 재배포 조건이 불명확해 지원하지 않습니다.
- 이전 버전(사용자가 키를 직접 입력)에서 업데이트하면 저장돼 있던 키가 자동 삭제됩니다.
- 실제 외부 서버 인증과 대용량 수집, 브라우저에서의 확장 프로그램 동작은 이 환경에서 검증하지 못했습니다. 현재 69개 테스트는 모의 응답 및 브라우저 IndexedDB 동작을 단순화한 로직 검증이며, 실제 통합 시험을 대체하지 않습니다.

## 파일 구조

```text
Capstone/
├── .github/workflows/update-signatures.yml   # 수집 → Pages 배포 (키는 여기서만 사용)
└── safe-ur-link/
    ├── manifest.json
    ├── package.json                 # 빌드/테스트 전용 (확장 프로그램에는 불필요)
    ├── scripts/build-feed.mjs       # signatures.json 생성
    ├── background/background.js     # 피드 다운로드, 판정, 차단 규칙
    ├── core/
    │   ├── dnr.js                   # 실시간 보호 규칙 생성·순위·상한
    │   ├── config.js                # 피드 주소
    │   ├── remote-feed.js           # 피드 다운로드·검증
    │   ├── history.js               # 서버 누적 병합 및 실패 소스 보존
    │   ├── feeds.js                 # 원본 API 수집기 (Actions 전용)
    │   ├── common.js                # 위험도 계산
    │   └── db.js                    # IndexedDB
    ├── pages/{options,popup,result,warning}/
    ├── assets/{css,icons}/
    ├── shared/render.js
    └── tests/
```

### 이름 통일과 기존 데이터 호환성

Chrome UI(확장 프로그램 이름, 팝업, 설정, 우클릭 메뉴, 경고, 로그 메시지)는 `SafeURLink`로 통일합니다. `safe-ur-link/` 경로와 IndexedDB의 `safe-ur-link` 내부 저장소 이름은 **기존 GitHub Actions 경로 및 설치된 확장 프로그램 데이터 유지**를 위해 변경하지 않습니다. 내부 키/경로는 사용자에게 표시되는 브랜드명이 아닙니다.
