# Safe UR Link

Chrome / Whale MV3 확장 프로그램. 알려진 악성 URL을 접속 전에 차단하고, 휴리스틱으로 위험도를 평가합니다.

## 구조 (API 키가 사용자에게 노출되지 않는 방식)

```text
[GitHub Actions, 하루 1회]                     [GitHub Pages]                  [사용자 브라우저]
 비밀 키(Secrets)로 URLhaus 등 수집  ──▶  signatures.json (키 없음, 공개)  ──▶  확장 프로그램이 다운로드
```

- 외부 위협 정보 API와 비밀 키는 **GitHub Actions 안에서만** 사용됩니다.
- 확장 프로그램은 `core/config.js`의 `SIGNATURE_FEED_URL` 하나만 내려받습니다. **사용자는 키를 입력하지 않습니다.**
- 다운로드한 데이터는 `core/remote-feed.js`가 검증한 뒤 IndexedDB에 저장합니다. 실패하면 기존 데이터를 유지합니다.

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
6. **실제 데이터 공개**: 각 소스의 약관에서 공개 재배포가 허용되는지 확인한 뒤, 워크플로의 해당 `PUBLISH_*`와 `REDISTRIBUTION_CONFIRMED`를 `'true'`로 바꿉니다. (OpenPhish는 `OPENPHISH_WRITTEN_PERMISSION`도 필요)

> `signatures.json`은 누구나 내려받을 수 있는 공개 파일입니다. 키는 들어가지 않지만 수집한 URL 목록은 공개됩니다.

## 확장 프로그램 설치 (개발자 모드)

`manifest.json`이 있는 `safe-ur-link` 폴더를 Chrome/Whale 확장 프로그램 관리 페이지에서 로드합니다.
설치하면 자동으로 데이터를 받아오며, 설정 페이지의 **지금 업데이트**로 수동 갱신할 수 있습니다(1분 간격 제한).

## 동작 정책

| 항목 | 값 |
|---|---|
| Actions 수집 주기 | 하루 1회 (KST 12:17경), 수동 실행 가능 |
| 확장 프로그램 확인 주기 | 6시간 (알람은 1시간마다 확인, 실패 시 1시간 후 재시도) |
| 수집 일부 실패 시 | 빌드 중단, Pages에는 마지막 정상 배포본 유지 |
| 용량 상한 | 300,000건 (초과 시 빌드 실패) |

## 로컬 개발

```bash
cd safe-ur-link
npm test                 # 단위 테스트
npm run build:feed       # public/signatures.json 생성 (환경변수 없으면 시연 데이터)
```

## 유의 사항

- 외부 DB에 없는 URL을 안전하다고 단정할 수 없습니다. UI 판정 `No Threat Detected`는 "위협 미탐지"를 뜻합니다.
- OpenPhish 무료 피드는 최초 관측 시각을 제공하지 않아 해당 값을 임의로 생성하지 않습니다.
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
