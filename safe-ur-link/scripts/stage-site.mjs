// GitHub Pages에 확장 프로그램의 공통 판정/피드 검증/렌더 모듈을 복사한다.
// 원본 파일을 수정하지 않으며, 매 배포마다 공통 코드의 최신 버전을 사용한다.
import { copyFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
for (const source of ['core/common.js', 'core/scan.js', 'core/remote-feed.js', 'core/web-shards.js', 'shared/render.js']) {
  const destination = path.join(root, 'public', source);
  await mkdir(path.dirname(destination), { recursive: true });
  await copyFile(path.join(root, source), destination);
}
console.log('웹사이트 공유 모듈 배치 완료');

// index 생성은 웹사이트 정적 자료 배치와 별도 스크립트로 실행한다.
