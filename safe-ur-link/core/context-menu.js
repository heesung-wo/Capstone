// 드래그한 URL 문자열(selectionText)만 검사한다.
// 링크의 실제 목적지(linkUrl)나 현재 페이지 주소(pageUrl)는 사용하지 않는다.
export const SELECTED_URL_MENU_ID = 'check-selection';

export const CONTEXT_MENUS = Object.freeze([
  Object.freeze({
    id: SELECTED_URL_MENU_ID,
    title: 'SafeURLink: 선택한 URL 텍스트 검사',
    contexts: ['selection']
  })
]);

// 선택 문구가 없으면 다른 필드로 대체하지 않는다.
export function targetFromContext(info) {
  if (!info) return null;
  if (info.menuItemId === SELECTED_URL_MENU_ID) {
    const value = typeof info.selectionText === 'string' ? info.selectionText.trim() : '';
    return value ? { url: value, mode: 'selection' } : null;
  }
  return null;
}

// 평범한 선택 문구(예: '로그인' 또는 '여기를 클릭')를 URL처럼 검사하지 않는다.
// 명시적 http(s) URL 또는 점을 포함하는 도메인/IP, localhost만 허용한다.
// 선택 텍스트를 다른 주소로 추측하거나 치환하지 않는다.
export function isSelectedUrl(value) {
  if (typeof value !== 'string') return false;
  const raw = value.trim();
  if (!raw || /\s/.test(raw)) return false;
  const explicitHttp = /^https?:\/\//i.test(raw);
  if (!explicitHttp && /^[a-z][a-z\d+.-]*:/i.test(raw) && !/^[a-z\d.-]+:\d+(?:[/?#]|$)/i.test(raw)) return false;
  try {
    const parsed = new URL(explicitHttp ? raw : `https://${raw}`);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) return false;
    return explicitHttp || parsed.hostname.includes('.') || parsed.hostname === 'localhost' || parsed.hostname.startsWith('[');
  } catch {
    return false;
  }
}

export function resultPageUrl(runtime, selected) {
  const params = new URLSearchParams({ url: selected.url, mode: selected.mode });
  return `${runtime.getURL('pages/result/result.html')}?${params.toString()}`;
}

// MV3 서비스 워커가 재시작돼도 메뉴 중복 생성 없이 선택 URL 검사 메뉴만 등록한다.
export async function registerContextMenu(api) {
  await new Promise((resolve, reject) => {
    api.contextMenus.removeAll(() => {
      const e = api.runtime.lastError;
      if (e) reject(new Error(`우클릭 메뉴 초기화 실패: ${e.message}`));
      else resolve();
    });
  });
  for (const menu of CONTEXT_MENUS) {
    await new Promise((resolve, reject) => {
      api.contextMenus.create({ ...menu, contexts: [...menu.contexts] }, () => {
        const e = api.runtime.lastError;
        if (e) reject(new Error(`우클릭 메뉴 등록 실패 (${menu.id}): ${e.message}`));
        else resolve();
      });
    });
  }
}
