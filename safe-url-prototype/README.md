# Safe UR Link 통합 프로토타입

Chrome/Whale Manifest V3 확장 프로그램과 Node.js 로컬 서버를 연결한 캡스톤용 테스트 버전입니다. Node.js 18 이상을 사용하세요. 외부 패키지 설치는 필요 없습니다.

## 구성

```text
extension/popup·우클릭 검사 ──POST /scan──> server/server.js ──> PhishTank
                                                 └──> URL 특징 분석
extension/DNR 로컬 규칙 ──접속 전──> warning.html ──일회성 허용──> 원래 URL
```

- 직접 입력, 현재 탭, 링크/선택한 URL 우클릭: PhishTank 개별 URL API와 URL 특징을 함께 검사합니다.
- URLhaus(최대 50점)는 키가 필요하여 아직 호출하지 않습니다. 현재 PhishTank 최대 40점 + URL 분석 최대 10점 = **최대 50점**입니다.
- 검증된 피싱 URL(`verified`와 `valid`가 참)은 점수와 관계없이 `MALICIOUS`입니다. 미등록은 `UNKNOWN`, API 실패는 `UNVERIFIED`입니다. 점수는 검증된 확률이나 안전 보증이 아닌 프로토타입의 근거 가중치입니다.
- 사전에 등록한 `phishing.test`, `malware.test`, 사용자 차단 도메인, 직접 검사에서 확인한 피싱 URL은 DNR 규칙으로 네트워크 연결 전에 경고 페이지로 전환합니다. 사용자 허용 도메인은 우선합니다.
- 경고 페이지의 **이번 한 번만 계속**은 해당 탭·정확한 URL에 임시 허용 규칙을 추가하고 이동한 뒤 제거합니다. 최대 1분 뒤에도 제거합니다.

## 실행

1. 터미널에서 이 폴더로 이동한 뒤 `node server/server.js`를 실행합니다. 서버는 `127.0.0.1:3000`만 수신합니다.
2. Chrome에서 `chrome://extensions` 또는 Whale에서 `whale://extensions`를 열고 **개발자 모드**를 켭니다.
3. **압축해제된 확장 프로그램 로드**에서 이 폴더 안의 `extension` 폴더를 선택합니다. ZIP을 먼저 압축 해제해야 합니다.
4. 확장 팝업에서 `https://www.google.com/`을 입력하고 **검사**를 누릅니다. 결과가 `UNKNOWN`이어도 안전 판정은 아닙니다.
5. 새 탭에 `http://phishing.test/`를 입력해 사전 등록된 규칙의 경고 페이지를 확인합니다. 이 주소는 테스트용 예약 도메인이므로 실제 악성 사이트에 접속할 필요가 없습니다.
6. 팝업의 **차단 추가**에 `example.test`를 입력해 목록을 확인하거나, 웹페이지의 링크를 우클릭해 **Safe UR Link: 링크 검사**를 사용합니다.

서버 연결 확인: `http://127.0.0.1:3000/health`는 `{"ok":true}`를 반환합니다. Node 단위/로컬 HTTP 검증은 `node --test server/scan.test.js`로 실행합니다.

## 확인 시 유의점

- PhishTank 공식 문서는 개별 조회를 POST로 제공하고 앱 키를 선택사항으로 두지만, 키 없이 조회할 때 제한이 큽니다. 식별 가능한 User-Agent를 서버에서 지정했습니다. 이 코드는 HTTPS 엔드포인트를 우선 사용하고 HTTP로 자동 전환하지 않습니다. 네트워크, 서버 정책, 제한(HTTP 509) 문제라면 `UNVERIFIED`와 원인을 표시합니다. 공식 문서의 HTTP 주소만 되는 환경에서는 **검사 URL이 평문으로 전송됨을 이해하고** 서버 실행 전에 환경 변수 `PHISHTANK_USE_DOCUMENTED_HTTP=1`을 직접 지정할 수 있습니다 (PowerShell: `$env:PHISHTANK_USE_DOCUMENTED_HTTP="1"`; bash: `PHISHTANK_USE_DOCUMENTED_HTTP=1 node server/server.js`).
- 외부 API 호출 시 검사한 URL 전체가 PhishTank에 전달됩니다. 로그인 토큰 등이 URL에 있는 실제 개인 주소를 테스트에 쓰지 마세요.
- 실제 PhishTank 연결은 개발 머신에서 확인해야 합니다. 로컬 자동 검증에서는 응답을 대체해 판정/예외 경로를 확인합니다.
- **모든 새 방문 URL을 API 응답까지 기다렸다 차단하지 않습니다.** 실시간 보호는 사전 저장 시그니처에서만 작동합니다. 직접 검사로 검증된 피싱 URL은 이후 방문에 대비해 정확한 URL로 저장합니다.
- 초기 시그니처는 시연용 2개 도메인뿐이며 주기적 DB 갱신, 대량 URL 목록, 프로덕션 서버 인증, 점수 실험 검증은 다음 단계입니다. DNR 규칙은 이 프로토타입에서 최대 1,000개로 제한했습니다.
- 이 버전은 이전 대화의 두 코드 파일을 직접 수정한 결과가 아니라, 같은 기능 설계를 새 폴더에 통합한 실행 가능한 샘플입니다.
