// 개발자가 확장 프로그램 배포 전에 한 번만 변경할 주소입니다.
// 사용자는 API 키나 URL을 입력할 필요가 없습니다.
// GitHub Pages 프로젝트 사이트 예: https://YOUR_NAME.github.io/safe-ur-link/signatures.json
export const SIGNATURE_FEED_URL = 'https://YOUR_NAME.github.io/safe-ur-link/signatures.json';

// 확장 프로그램은 6시간마다 최신 공개 JSON을 확인합니다.
// 실제 원본 API 조회는 별도 GitHub Actions에서 수행합니다.
export const REFRESH_INTERVAL_MS = 6 * 60 * 60 * 1000;
