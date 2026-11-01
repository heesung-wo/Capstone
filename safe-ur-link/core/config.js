// 개발자가 확장 프로그램 배포 전에 한 번만 변경할 주소입니다.
// 사용자는 API 키나 URL을 입력할 필요가 없습니다.
// 저장소 이름이 Capstone 이므로 GitHub Pages 주소는 https://<계정>.github.io/Capstone/ 입니다.
export const SIGNATURE_FEED_URL = 'https://heesung-wo.github.io/Capstone/signatures.json';

// 확장 프로그램은 6시간마다 최신 공개 JSON을 확인합니다.
// 실제 원본 API 조회(비밀 키 사용)는 GitHub Actions에서만 수행합니다.
export const REFRESH_INTERVAL_MS = 6 * 60 * 60 * 1000;
