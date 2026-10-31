const LABEL = { Malicious: '악성 URL 확인', Suspicious: '주의가 필요한 URL', 'No Threat Detected': '위협이 탐지되지 않음' };
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
export function resultHTML(r) {
  if (r.error) return `<p class="verdict v-Suspicious">${esc(r.error)}</p>`;
  const cls = 'v-' + r.verdict.split(' ')[0];
  const rs = r.reasons.length ? r.reasons.map(x => `<li><span class="pt">${x.points ? '+' + x.points : '·'}</span><span>${esc(x.text)}</span></li>`).join('')
    : '<li><span class="pt">·</span><span>탐지된 위험 요소가 없습니다</span></li>';
  const note = r.verdict === 'No Threat Detected' ? '<p class="muted">새로 만들어졌거나 아직 위협 정보에 등록되지 않은 악성 URL은 탐지되지 않을 수 있습니다. 안전을 보증하는 결과가 아닙니다.</p>' : '';
  return `<div class="${cls}"><div class="verdict"><b>${r.verdict}</b> <span class="muted">${LABEL[r.verdict]}</span>
    <div class="meter" role="img" aria-label="위험 점수 ${r.score}점"><i style="width:${r.score}%"></i></div>
    <div class="muted">위험 점수 ${r.score}/100${r.externalScore != null ? ` (외부 정보 ${r.externalScore}/60 + 휴리스틱 ${r.heuristicScore}/40)` : ''}</div></div>
    ${r.sources?.length ? `<p class="muted">탐지 출처: ${r.sources.join(', ')}</p>` : ''}
    <ul class="reasons">${rs}</ul>${note}</div>`;
}
export { esc };
