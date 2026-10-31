# Safe UR Link — 공식 피드 API 반영판 (2026-10-31)

Chrome / Whale MV3 확장 프로그램. 파일 구조는 유지하면서 `core/feeds.js`, `background/background.js`, `pages/options/*`, `manifest.json`을 수정했습니다.

## 사용 방법

1. `manifest.json`이 있는 `safe-ur-link` 폴더를 Chrome/Whale 확장 프로그램 관리 페이지에서 개발자 모드로 로드합니다.
2. 확장 프로그램의 설정 페이지를 열고, URLhaus/ThreatFox를 사용하려면 https://auth.abuse.ch/ 에서 무료 발급받은 `abuse.ch Auth-Key`를 입력합니다.
3. PhishTank 키는 선택 사항입니다. 키가 없는 공개 피드는 다운로드 횟수 제한이 엄격합니다. 자동 수집에 반복적으로 사용할 때는 PhishTank 앱 키 등록을 권장합니다.
4. 설정을 저장하고 **지금 업데이트**를 누릅니다. 업데이트 버튼도 최소 갱신 간격을 지키며 저장된 캐시를 재사용합니다.
5. 설정 페이지에서 피드별 수집 성공 여부·건수·다음 확인 시각을 확인합니다.

## 피드별 갱신 정책

| 소스 | 키 | 프로그램의 최소 갱신 간격 | 비고 |
|---|---|---|---|
| URLhaus | abuse.ch Auth-Key 필수 | 1시간 | 데이터 공급자 공식 최소 간격 5분. CSV에는 offline도 포함될 수 있음 |
| PhishTank | 선택 | 키 있으면 1시간, 없으면 24시간 | 공식 DB 갱신 1시간, 무키 다운로드 몇 회/일로 제한 |
| OpenPhish | 불필요 | 6시간 | 공개 feed.txt |
| ThreatFox | abuse.ch Auth-Key 필수 | 6시간 | 최근 7일 IOC, url 유형만 사용 |

확장 프로그램 알람은 **1시간마다 갱신 여부를 확인**하지만 매번 모든 외부 API에 요청하지는 않습니다. 오류가 발생해도 DB 데이터를 삭제하지 않습니다. HTTP 429/509 및 Retry-After에 대한 재시도 대기 처리를 포함합니다.

### 공식 문서

- URLhaus: https://urlhaus.abuse.ch/api/
- ThreatFox: https://threatfox.abuse.ch/api/
- PhishTank 데이터베이스: https://phishtank.org/developer_info.php
- PhishTank 요청 제한: https://phishtank.org/api_info.php
- abuse.ch 키 발급: https://auth.abuse.ch/

## 유의 사항

- **Chrome 확장 프로그램에서는 `User-Agent`를 임의로 지정할 수 없습니다.** PhishTank는 식별 가능한 User-Agent를 요구하므로 공개 데이터 요청이 HTML 차단 페이지, HTTP 403/509 등으로 실패할 수 있습니다. 갱신 주기를 길게 하더라도 성공을 보장할 수 없습니다. 완전한 안정성이 필요하면 서버에서 데이터를 정기 수집해 확장 프로그램에 공급하는 구성을 권장합니다.
- `https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv`에서 키는 요청 URL 경로에 포함됩니다. 확장 프로그램에 포함된 인증 정보는 안전한 서버 비밀이 아닙니다. **실제 서비스에 배포할 때는 키를 서버에만 저장**해야 합니다.
- URLhaus의 `recent.csv`는 온라인 전용 피드가 아닙니다. `meta.online`은 CSV의 `url_status`를 사용하며, `first_seen`은 실제 `dateadded` 값에서 가져옵니다.
- OpenPhish의 무료 텍스트 피드는 개별 URL의 최초 관측 시각을 제공하지 않으므로 해당 값을 임의로 생성하지 않습니다.
- 외부 DB에 없는 URL을 안전하다고 단정할 수 없습니다. 기존 UI 판정 `No Threat Detected`를 유지합니다.
- API 키가 제공되지 않았으므로 실제 외부 서버 인증 성공 및 실시간 대용량 수집은 검증하지 못했습니다. 파일 형식/오류 처리는 모의 응답으로 테스트했습니다.

## 구조

```text
safe-ur-link/
├── manifest.json
├── background/background.js    # 1시간 체크, 캐시, 차단 규칙
├── core/
│   ├── feeds.js               # 공식 API 수집 및 JSON/CSV 파싱
│   ├── common.js              # 위험도 계산
│   └── db.js                  # IndexedDB
├── pages/{options,popup,warning}/
├── assets/{css,icons}/
└── shared/render.js
```
