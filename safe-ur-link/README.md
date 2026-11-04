# SafeURLink (v0.5.0 · 시그니처 자동 차단 / 사용자 경고 분리)

Chrome / Whale MV3 확장 프로그램. 알려진 악성 URL을 접속 전에 차단하고, 휴리스틱으로 위험도를 평가합니다.

## 구조 (API 키가 사용자에게 노출되지 않는 방식)

```text
[GitHub Actions, 하루 1회]                     [GitHub Pages]                  [사용자 브라우저]
 비밀 키(Secrets)로 URLhaus 등 수집  ──▶  signatures.json (키 없음, 공개)  ──▶  확장 프로그램이 다운로드
```

- 외부 위협 정보 API와 비밀 키는 **GitHub Actions 안에서만** 사용됩니다.
- 확장 프로그램은 `core/config.js`의 `SIGNATURE_FEED_URL` 하나만 내려받습니다. **사용자는 키를 입력하지 않습니다.**
- 다운로드한 데이터는 `core/remote-feed.js`가 검증한 뒤 IndexedDB에 저장합니다. 실패하면 기존 데이터를 유지합니다.
- **수집량 변경이 반영되려면** 수정된 `scripts/build-feed.mjs`를 GitHub에 반영하고 Actions를 재실행하여 Pages의 `signatures.json`을 새로 배포해야 합니다. 브라우저의 **지금 업데이트** 버튼만 눌러서는 기존 공개 피드의 건수가 줄어들지 않습니다.

## 개발자 설정 (한 번만)

저장소 이름이 `Capstone`이고 이 프로젝트가 `safe-ur-link/` 하위 폴더라는 전제입니다.
워크플로 파일은 **저장소 루트** `.github/workflows/update-signatures.yml`에 있어야 GitHub가 인식합니다.

1. **Secrets 등록**: Settings → Secrets and variables → Actions → *Secrets*
   - `ABUSE_CH_AUTH_KEY` : https://auth.abuse.ch/ 에서 발급 (URLhaus, ThreatFox)
   - `PHISHTANK_KEY` : 선택
2. **Variables 등록**: 같은 화면의 *Variables* 탭
   - `PHISHTANK_USER_AGENT` : 식별 가능한 문자열 (예: `phishtank/내아이디`)
3. **Pages 소스 변경**: Settings → Pages → Build and deployment → Source: **GitHub Actions**
4. **첫 배포**: Actions 탭 → *Build and deploy signatures* → *Run workflow*
   - 기본값에서는 `.test` 도메인 시연 데이터만 배포됩니다.
5. 배포 후 `https://<계정>.github.io/Capstone/signatures.json` 이 열리는지 확인하고, 다르면 `core/config.js`와 `manifest.json`의 `host_permissions`를 맞춥니다.
6. **실제 데이터 공개**: 각 소스의 약관에서 공개 재배포가 허용되는지 확인한 뒤, 워크플로의 해당 `PUBLISH_*`와 `REDISTRIBUTION_CONFIRMED`를 `'true'`로 바꿉니다. (`PUBLISH_URLHAUS`, `PUBLISH_THREATFOX`, `PUBLISH_PHISHTANK`, `PUBLISH_PHISHING_DB`)

> `signatures.json`은 누구나 내려받을 수 있는 공개 파일입니다. 키는 들어가지 않지만 수집한 URL 목록은 공개됩니다.

> **기존 GitHub Actions 설정 유지:** 이 ZIP에는 공개 설정 예시가 `false`인 `.github/workflows/update-signatures.yml`이 함께 들어 있습니다. GitHub 저장소에서 이미 `PUBLISH_*` / `REDISTRIBUTION_CONFIRMED`를 `true`로 변경해 운영 중이라면, 이 파일을 그대로 덮어써서 다시 `false`로 만들지 마세요. 수집 상한은 `scripts/build-feed.mjs`만 변경해도 적용되므로, GitHub의 기존 워크플로 활성화 설정을 보존해야 합니다.

## 확장 프로그램 설치 (개발자 모드)

`manifest.json`이 있는 `safe-ur-link` 폴더를 Chrome/Whale 확장 프로그램 관리 페이지에서 로드합니다.
설치하면 자동으로 데이터를 받아오며, 설정 페이지의 **지금 업데이트**로 수동 갱신할 수 있습니다(1분 간격 제한).

## 동작 정책

| 항목 | 값 |
|---|---|
| Actions 수집 주기 | 하루 1회 (KST 12:17경), 수동 실행 가능 |
| 확장 프로그램 확인 주기 | 6시간 (알람은 1시간마다 확인, 실패 시 1시간 후 재시도) |
| 일시적 오류(5xx, 429, 네트워크) | 소스별로 최대 2회 재시도 (5초, 20초 간격) |
| 수집 일부 실패 시 | 빌드 중단, Pages에는 마지막 정상 배포본 유지. 단 `OPTIONAL_SOURCES`에 적은 소스는 실패해도 나머지로 배포하고 그 소스 데이터는 그날 피드에서 제외 |
| 소스별 공개 상한 | URLhaus 9,000건 / PhishTank 9,000건 / PhishingDB 9,000건 / ThreatFox 2,700건 (`scripts/build-feed.mjs`의 `SOURCE_LIMITS`). 초과 시 활성(online) → 검증됨 → 신뢰도 → 최근 등록 순으로 남김 |
| 전체 용량 안전장치 | 300,000건 (초과 시 빌드 실패) |

## 실시간 보호: 위협 DB는 BLOCK / 사용자 차단 목록은 REDIRECT

Manifest V3의 `chrome.declarativeNetRequest`를 사용합니다. 실시간 보호는 **메인 프레임 이동(`main_frame`)**에 적용되고, 일반 사이트의 네트워크 요청은 별도 실시간 서버 조회 없이 기존처럼 처리됩니다.

| 시그니처/목록 | DNR 동작 | 사용자 화면 |
|---|---|---|
| `지금 업데이트`로 받은 URLhaus / PhishTank / PhishingDB / ThreatFox | `block` (우선순위 10) | Chrome 기본 차단 오류 화면(예: `ERR_BLOCKED_BY_CLIENT`) |
| 사용자가 설정에 입력한 차단 도메인(+하위 도메인) | `redirect` (우선순위 20) | SafeURLink 경고 페이지. `이 URL 접속` 시 해당 탭·URL 세션 허용 |
| 사용자 허용 도메인 | `allow` (우선순위 30) | 정상 접속 |
| 어느 곳에도 일치하지 않는 주소 | 규칙 없음 | 정상 접속(안전성 보증은 아님) |

**자동 BLOCK 여부에는 위험 점수 임계값을 사용하지 않습니다.** 피드에서 받은 URL이라면 해당 URL과 정확히 일치하는 규칙을 만들고, 위험 점수는 팝업/우클릭 수동 검사 결과에 계속 표시합니다.

### 건수 제한 (Chrome 121 이상)

- 동적 DNR **총 30,000개** (안전한 `block`/`allow` 포함). `redirect`는 별도 **최대 5,000개** 제한이 있고, 이 역시 총 30,000개 안에 포함됩니다.
- 시그니처 자동 `block` **최대 29,700개**, 사용자 지정 차단 도메인의 `redirect` **최대 300개**로 제한합니다. 사용자 `allow` 규칙도 동적 규칙을 소비하므로, 300개 차단 도메인을 모두 사용한 상태에서 허용 목록까지 등록하면 **시그니처 block 건수를 그만큼 줄여** 전체 한도 30,000개를 준수합니다.
- 네 소스의 피드 건수 총합이 정확히 29,700건이더라도, 소스 간 동일 URL 중복, URL 필터 표현 불가능, 사용자 지정 허용/차단의 우선 처리가 있으면 실제 적용 block 규칙은 29,700개보다 적을 수 있습니다. 미반영 URL은 IndexedDB에 보존되며 팝업/우클릭에서 수동 검사할 수 있습니다.
- 상한을 넘으면 **교차 탐지 소스 수 → 활성 여부 → 검증 여부 → 최근 등록 시각** 기준으로 선정합니다. 이는 선정 우선순위일 뿐, 개별 URL의 차단 여부에 위험 점수 임계값을 두는 것이 아닙니다.
- DNR 필터의 와일드카드 메타 문자(`*`, `^`, `|`)를 포함하는 URL 등 정확한 조건을 만들 수 없는 항목은 과잉 차단 방지를 위해 규칙으로 만들지 않습니다. 설정 화면에서 *미포함 개수*를 확인할 수 있습니다.
- `/core/dnr.js`에서 `MAX_PROTECTION_RULES=30000`으로 관리하며, Chrome 121 미만의 브라우저에서는 설치되지 않도록 `manifest.json`의 `minimum_chrome_version`을 121로 변경했습니다.

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

## 로컬 개발

```bash
cd safe-ur-link
npm test                 # 단위 테스트 (DNR 규칙 한도·우선순위 포함)
npm run build:feed       # public/signatures.json 생성 (환경변수 없으면 시연 데이터)
```

## 유의 사항

- 외부 DB에 없는 URL을 안전하다고 단정할 수 없습니다. UI 판정 `No Threat Detected`는 "위협 미탐지"를 뜻합니다.
- Phishing.Database 목록은 등록 시각, 검증 여부, 활성 여부를 제공하지 않아 해당 값을 임의로 생성하지 않습니다. 상한(9천 건)을 넘으면 날짜 시드 기반 무작위 표본을 사용합니다.
- Phishing.Database는 MIT 라이선스입니다. 공개하면 `signatures.json`(`notices`)과 Pages 첫 화면에 저작권·라이선스 고지가 함께 실립니다.
- OpenPhish 무료 피드는 비상업 용도로 제한되고 재배포 조건이 불명확해 지원하지 않습니다.
- 이전 버전(사용자가 키를 직접 입력)에서 업데이트하면 저장돼 있던 키가 자동 삭제됩니다.
- 실제 외부 서버 인증과 대용량 수집, 브라우저에서의 확장 프로그램 동작은 이 환경에서 검증하지 못했습니다. 로직은 모의 응답으로 테스트했습니다.

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
    │   ├── feeds.js                 # 원본 API 수집기 (Actions 전용)
    │   ├── common.js                # 위험도 계산
    │   └── db.js                    # IndexedDB
    ├── pages/{options,popup,warning}/
    ├── assets/{css,icons}/
    ├── shared/render.js
    └── tests/
```

### 이름 통일과 기존 데이터 호환성

Chrome UI(확장 프로그램 이름, 팝업, 설정, 우클릭 메뉴, 경고, 로그 메시지)는 `SafeURLink`로 통일합니다. `safe-ur-link/` 경로와 IndexedDB의 `safe-ur-link` 내부 저장소 이름은 **기존 GitHub Actions 경로 및 설치된 확장 프로그램 데이터 유지**를 위해 변경하지 않습니다. 내부 키/경로는 사용자에게 표시되는 브랜드명이 아닙니다.
