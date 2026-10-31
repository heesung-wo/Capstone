# Safe UR Link v0.2.0 — GitHub Actions + GitHub Pages 기반 시그니처 배포

## 핵심 변경

- 사용자는 **API 키 없이 확장 프로그램만 설치**합니다.
- 개발자만 GitHub Actions Secrets에 `ABUSE_CH_AUTH_KEY` 등을 보관합니다.
- GitHub Actions의 `scripts/build-feed.mjs`가 공식 피드를 수집하고 `public/signatures.json`을 생성합니다.
- GitHub Pages가 해당 JSON을 정적 HTTPS 주소로 배포합니다.
- 확장 프로그램의 `background/background.js`는 6시간 간격으로 JSON을 확인하고, IndexedDB를 업데이트합니다.
- 수집/배포/다운로드 실패 시 기존 공개 데이터 또는 기존 로컬 DB를 유지합니다.
- 기존 수동 URL 검사, 현재 탭 검사, 우클릭 검사, 허용/차단 목록, `declarativeNetRequest` 경고 기능을 유지합니다.

## 1. 개발자 설정 (실제 사용 전 필수)

1. GitHub에서 `safe-ur-link` 등의 새 저장소를 생성하고 **이 디렉터리의 파일 전체**를 저장소 최상위에 올립니다. `.github/workflows/update-signatures.yml` 숨김 폴더도 포함해야 합니다.
2. GitHub 저장소의 `Settings → Pages → Build and deployment → Source`를 **GitHub Actions**로 지정합니다.
3. `Actions → Build and deploy signatures → Run workflow`를 실행합니다. 초기 설정은 외부 데이터를 게시하지 않으므로 안전한 `.test` 시연 주소 2건만 배포합니다.
4. 작업이 성공하면 `https://<GITHUB_USERNAME>.github.io/<REPOSITORY>/signatures.json`을 브라우저에서 열어 JSON이 보이는지 확인합니다.
5. **`core/config.js`의 `SIGNATURE_FEED_URL`을 위의 실제 주소로 변경합니다.** 기존 placeholder `YOUR_NAME`를 둔 채로는 동작하지 않습니다.
6. Chrome/Whale 확장 관리에서 `manifest.json`이 있는 이 폴더를 개발자 모드의 '압축 해제된 확장 프로그램 로드'로 설치/새로고침합니다.
7. 확장 프로그램 설정의 **지금 업데이트**를 누르면 초기 시연 DB가 2건 표시됩니다. 테스트 주소 `https://phishing.test/login` 또는 `http://malware.test/demo`를 수동 URL 검사해 보세요.
8. 확인 후 `core/config.js`가 반영된 확장 프로그램만 사용자에게 배포하면 **사용자는 키/Pages URL을 입력할 필요가 없습니다**.

`https://*.github.io/*` 권한만 기본적으로 허용합니다. GitHub Pages에 별도 커스텀 도메인을 연결할 계획이라면 `manifest.json`의 `host_permissions`에 해당 사이트를 추가해야 합니다.

## 2. 개발자의 API 키 등록

GitHub 저장소 → `Settings → Secrets and variables → Actions → New repository secret`

- `ABUSE_CH_AUTH_KEY` : URLhaus/ThreatFox 공통 Auth-Key (필요한 경우)
- `PHISHTANK_KEY` : PhishTank 앱 키 (선택)

PhishTank를 활성화하는 경우 `Settings → Secrets and variables → Actions → Variables`에서
`PHISHTANK_USER_AGENT`에 **`phishtank/본인의_식별자`** 형태를 설정해야 합니다.

**중요: Secrets를 등록했다고 곧바로 피드가 공개되지는 않습니다.** `update-signatures.yml`에는 공개 배포 소스가 기본적으로 전부 `false`입니다.

## 3. 실제 위협 피드 활성화 및 법적 주의

GitHub Pages는 **누구나 다운로드할 수 있는 공개 파일**입니다. 원본 데이터를 재가공하더라도 재배포 조건이 적용될 수 있습니다. 원 제공자의 이용약관, 라이선스, 필요한 승인을 먼저 확인하세요.

- OpenPhish: https://openphish.com/terms.html — 제3자 배포는 명시적인 서면 허가가 없는 한 제한됨. **기본 비활성**.
- URLhaus: https://urlhaus.abuse.ch/api/ — Auth-Key 필수, 공정 사용 원칙. 공개 재배포 가능 여부 별도 확인.
- ThreatFox: https://threatfox.abuse.ch/api/ — Auth-Key 필수, 공정 사용 원칙. 공개 재배포 가능 여부 별도 확인.
- PhishTank: https://phishtank.org/developer_info.php 및 https://phishtank.org/terms.php — 식별 가능한 User-Agent/다운로드 제한 및 데이터 이용약관 확인.

허가된 소스만 `.github/workflows/update-signatures.yml`에서 다음 값을 바꿉니다.

```yaml
PUBLISH_URLHAUS: 'true'       # 해당 소스에 대한 재배포 권한 확인 후
PUBLISH_THREATFOX: 'true'
PUBLISH_PHISHTANK: 'true'
PUBLISH_OPENPHISH: 'false'    # 서면 허가 확인 전까지 false 유지
REDISTRIBUTION_CONFIRMED: 'true'
OPENPHISH_WRITTEN_PERMISSION: 'false'
```

위 값은 **예시**이며, 실제로 확인되지 않은 소스는 `false`로 두세요. `REDISTRIBUTION_CONFIRMED`는 개발자의 확인 선언이지 이용 권한을 자동 부여하는 기능이 아닙니다. OpenPhish는 추가로 `OPENPHISH_WRITTEN_PERMISSION: 'true'`가 필요합니다.

실제 피드는 서버의 cron 설정에 따라 **하루 1회** 조회합니다. 매시간 갱신은 아닙니다. 확장 프로그램은 **6시간마다** 서버의 JSON 파일을 확인합니다. 작업 지연은 가능하며 모든 주기에 새 데이터가 있다는 뜻은 아닙니다.

## 4. 데이터 형식

`public/signatures.json` 예시 (시연용 `.test` 주소만 사용):

```json
{
  "schema": 1,
  "generatedAt": "2026-10-31T00:00:00.000Z",
  "sources": [{ "name": "Demo", "count": 1 }],
  "signatures": [
    { "source": "Demo", "url": "https://phishing.test/login", "meta": { "online": false, "threat": "demo" } }
  ]
}
```

공개 JSON에 **API 키, 개인정보, 업스트림 API 요청 헤더가 포함되지 않도록** `scripts/build-feed.mjs`가 필요한 필드만 추립니다.

## 5. 파일 구조

```text
safe-ur-link/
├─ .github/workflows/update-signatures.yml  # 수집 및 Pages 배포
├─ scripts/
│  ├─ collectors.mjs                          # 외부 API 접근 (Actions 환경 전용)
│  └─ build-feed.mjs                          # 정규화·통합·공개 JSON 생성
├─ public/
│  ├─ signatures.json                         # GitHub Pages 공개 데이터
│  └─ index.html
├─ core/
│  ├─ config.js                               # 개발자가 설정하는 공개 JSON URL
│  ├─ remote-feed.js                          # 브라우저 JSON 다운로드/검증
│  ├─ db.js                                   # IndexedDB 저장
│  └─ common.js                               # URL 정규화·위험 점수
├─ background/background.js                   # 검사/알람/차단 규칙
├─ pages/{popup,options,warning}/            # 확장 프로그램 화면
├─ shared/, assets/, tests/
├─ manifest.json
└─ package.json
```

## 6. 오류 해결 및 제한

- `core/config.js에 GitHub Pages 주소를 설정`: placeholder를 실제 계정/저장소 주소로 변경.
- `HTTP 404`: Pages 배포 완료 여부, Actions 로그, `Settings → Pages` 출처, 주소의 저장소명 확인.
- API 401/403: 개발자의 Actions 로그에서 키/권한을 확인. **사용자의 확장 프로그램에서는 API 키를 입력하지 않습니다**.
- 업스트림 서비스 수집 실패: 스크립트가 오류로 종료하고 새 Pages 배포를 중단하여 마지막 정상 배포가 유지됩니다.
- 확장 JSON 다운로드 실패: IndexedDB에 남아 있는 이전 시그니처를 유지합니다.
- Chrome `declarativeNetRequest`는 비안전 동적 redirect 규칙에 제한이 있어 자동 차단은 **최대 4,800개 규칙**입니다. 전체 시그니처 DB는 수동 URL 검사에 이용할 수 있지만 초과 주소는 자동 차단 대상에서 빠질 수 있습니다.
- GitHub Pages는 공개 데이터 저장소이지 비밀 저장소가 아닙니다. API 키는 전용 Secrets에만 보관합니다.
- 이 버전은 키 없이 작동하도록 코드가 연결되어 있지만 **실제 GitHub Pages 사이트 배포와 실제 API 응답은 이 로컬 테스트 환경에서 수행하지 않았습니다.**

## 7. 개발자 테스트

Node.js 22 이상에서:

```sh
npm test
npm run build:feed   # 기본 .test 시연 JSON 생성
```

`tests`는 샘플 JSON 검사·파서·오류 처리 모의 테스트를 사용합니다. 실제 운영에 배포하기 전에 Chrome/Whale에서 기능별 검증이 필요합니다.
