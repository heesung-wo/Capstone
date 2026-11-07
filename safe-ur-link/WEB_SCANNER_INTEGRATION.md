# SafeURLink 웹 직접 검사 통합 안내 (기존 확장 프로그램 유지)

## 목표

업로드한 `SafeURLink_v0.6.3(1).zip` 소스를 바탕으로 작업했습니다. ZIP 이름과 달리 원본 `manifest.json`과 `package.json` 안의 버전 표기는 `0.6.6`이므로 변경하지 않았습니다.

기존 브라우저 확장 프로그램의 **실시간 보호, IndexedDB 저장, 사용자 허용/차단, 설정 UI, 팝업/우클릭, GitHub Actions 데이터 수집**은 유지합니다. URL 직접 검사 기능의 **판정 엔진과 배포 시그니처만** 웹사이트와 공유합니다. 별도 API 서버 또는 API 키가 포함된 웹 프론트엔드는 사용하지 않습니다.

## 검사 데이터 흐름

```text
[GitHub Actions] 수집 → public/signatures.json (원본, 전체/이력 포함)
                            ├─ 확장 프로그램: 주기적으로 다운로드 → IndexedDB
                            │                     → check() → evaluateUrl()
                            └─ 웹용 배포 인덱스 생성 → web-index.json + web-shards/{0~511}.json
                                                    → 웹 워커: URL 해시로 해당 파일만 조회
                                                    → evaluateUrl()
```

`core/common.js`는 기존 위험 점수/URL 정규화 로직입니다. `core/scan.js`는 기존 `background.check()`에서 **판정 로직만 추출**합니다. `core/web-shards.js`는 빌더와 웹 클라이언트가 동일한 URL 분할 함수를 사용하도록 합니다.

## 변경 파일

- `core/scan.js` (추가): 확장 프로그램·웹사이트 공통 판정 함수
- `core/web-shards.js` (추가): 512분할 고정 해시
- `core/common.js`, `core/dnr.js` (소폭 수정): 7일 이력 기준을 공용 상수로 이동, 값 변경 없음
- `background/background.js` (소폭 수정): 기존 체크 흐름을 유지하며 최종 계산을 `evaluateUrl()`에 위임
- `scripts/build-feed.mjs` (소폭 수정): 웹 첫 화면을 덮어쓰지 않고 저작권 고지를 `notices.html`에 생성
- `scripts/build-web-index.mjs`, `scripts/stage-site.mjs` (추가): 원본 JSON 전체 분할 및 웹에서 쓸 동일한 공통 모듈 복사
- `public/index.html`, `public/assets/css/site.css`, `public/assets/js/site.js`, `public/assets/js/scan-worker.js` (추가): 직접 검사 사이트
- `.github/workflows/update-signatures.yml` (소폭 수정): 수집 이후 웹 분할·배포 단계 추가, 기존 수집 키/허용 스위치 보존
- `package.json` (소폭 수정): `stage:site`, `build:web-index` 스크립트 추가
- `tests/web-*.test.mjs` (추가): 일치, 샤딩, URL 검사 및 웹 워커 테스트

`manifest.json`은 변경하지 않았습니다.

## 로컬 실행

Node.js 20+ 및 Python 3가 설치되어 있다면, `safe-ur-link` 폴더에서:

```bash
npm test
npm run stage:site
npm run build:web-index
python -m http.server 8000 --directory public
```

브라우저에서 `http://localhost:8000/` 접속. 압축 파일의 `public/signatures.json`은 *시연용 2건*입니다. 로컬 테스트: `https://phishing.test/login` (악성) / `https://example.com/` (위협 미탐지).

`public/index.html`을 `file://`로 직접 열면 브라우저 모듈과 워커 제약으로 동작하지 않습니다.

## GitHub Pages에 게시

1. 압축을 풀어 기존 저장소의 `.github/` 및 `safe-ur-link/` 동일 경로에 변경 사항을 반영합니다. **운영 중인 Actions Secrets, Variables, 수집 정책을 보존**하세요. 특히 `PUBLISH_*`/`REDISTRIBUTION_CONFIRMED`가 기존 저장소와 다른 경우 원본을 무작정 덮어쓰지 말고 현재 운영 값을 유지하세요. 이 파일은 사용자가 업로드한 ZIP의 기본 설정을 그대로 보존했습니다.
2. GitHub Settings → Pages의 Source가 `GitHub Actions`인지 확인합니다.
3. Actions → `Build and deploy signatures` → `Run workflow`를 실행합니다.
4. 실행 로그에 `Collect and build public feed` → `Publish shared direct-scan modules` → `Build full-coverage web lookup index` → Pages 배포 순서가 나오는지 확인합니다.
5. 배포 완료 후 `https://heesung-wo.github.io/Capstone/`의 스캐너에서 데이터 건수, 마지막 배포 시각, 검사 결과를 확인합니다. `https://heesung-wo.github.io/Capstone/web-index.json`의 `signatureCount`와 `signatures.json`의 `signatures.length`가 같아야 합니다.
6. 브라우저가 이전 JS/CSS를 캐시한 경우 `Ctrl + Shift + R` 새로고침합니다.

**주의:** 웹사이트의 새로고침 버튼은 *기존에 Pages로 배포된 데이터*를 다시 읽습니다. 원본 수집을 즉시 수행하지 않습니다. 새로운 데이터 수집은 GitHub Actions 워크플로가 수행합니다.

## 일치 기준과 예외

- 같은 `signatures.json` 생성 시각, 동일한 URL, 같은 메타데이터를 입력한 경우 점수 계산, `Malicious`/`Suspicious`/`No Threat Detected` 판정은 **같은 `evaluateUrl()`**을 사용합니다.
- 확장 프로그램은 **개인 허용·차단 목록**이 시그니처보다 우선합니다. 웹사이트에서는 이 개인 목록을 읽을 수 없으므로 적용하지 않습니다.
- 확장 프로그램의 로컬 DB에만 남은 과거 이력은 웹사이트에서 재현할 수 없습니다. 다만 GitHub Actions가 `signatures.json`에 누적 저장한 이력은 `web-shards`에도 **삭제 없이** 담깁니다.
- 시그니처 다운로드 실패나 파일 누락, 인덱스와 샤드 버전 불일치는 **검사 실패**로 안내합니다. `No Threat Detected`로 대체하지 않습니다.
- 시그니처 목록에 없더라도 안전을 보증하지 않습니다. 확장 프로그램의 실시간 DNR에는 별도 최대 적용량이 있지만, 수동 검사는 전체 수집 피드를 기준으로 합니다.
- `signatures.json`과 웹 인덱스는 공개 파일이므로 각 원본 데이터 공급자의 재배포 이용조건을 반드시 확인해야 합니다.

## 문제 해결

- **'데이터 연결 중' 지속:** 개발자 도구(F12) → Console, Network에서 `web-index.json`, `core/scan.js`, `assets/js/scan-worker.js`의 응답을 확인하세요. 모듈 오류는 화면에도 표시됩니다.
- **URL 검사 결과가 없음:** `web-shards/<번호>.json`가 404인지, 생성 시각이 `web-index.json`과 같은지 확인하세요. 오류는 `No Threat Detected`가 아닌 검사 오류로 표시됩니다.
- **시그니처 수가 2개:** 압축 ZIP 내 기본 데모 데이터만 배포된 상태이거나 실제 수집이 수행되지 않은 상태입니다. 기존 수집 Actions 설정과 로그를 확인하세요.
- **확장 프로그램과 판정이 다름:** 먼저 확장 프로그램 설정 페이지에서 마지막 갱신 시각, 개인 허용·차단 목록, 과거 이력 여부를 확인하고 웹사이트의 배포 시각과 대조하세요.
