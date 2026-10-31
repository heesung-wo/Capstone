import { resultHTML, esc } from '../../shared/render.js';
const target = new URLSearchParams(location.search).get('u') || '';
document.getElementById('url').textContent = target;
chrome.runtime.sendMessage({ type: 'check', url: target }).then(r => { document.getElementById('info').innerHTML = resultHTML(r); });
document.getElementById('back').onclick = () => history.length > 1 ? history.back() : chrome.runtime.sendMessage({ type: 'goSafe' });
document.getElementById('proceed').onclick = async () => {
  await chrome.runtime.sendMessage({ type: 'allowOnce', url: target });
  location.replace(target);
};
