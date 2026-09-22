const progress = document.getElementById('scrollProgress');
const glow = document.getElementById('cursorGlow');
window.addEventListener('scroll', () => {
  const doc = document.documentElement;
  const available = doc.scrollHeight - doc.clientHeight;
  const pct = available > 0 ? (doc.scrollTop / available) * 100 : 0;
  if (progress) progress.style.width = pct + '%';
});
document.addEventListener('mousemove', e => {
  if (!glow) return;
  glow.style.opacity = '1';
  glow.style.left = e.clientX + 'px';
  glow.style.top = e.clientY + 'px';
});
document.addEventListener('mouseleave', () => { if (glow) glow.style.opacity = '0'; });

const reveal = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if(entry.isIntersecting){
      entry.target.classList.add('in');
      reveal.unobserve(entry.target);
    }
  });
}, { threshold: .12 });
document.querySelectorAll('.reveal,.reveal-scale').forEach(el => reveal.observe(el));

const terminal = document.getElementById('terminalBody');
const sequence = [
  ['cmd','whoami'],
  ['out','SOC analyst / cybersecurity student'],
  ['cmd','stack'],
  ['out','Wazuh\nSysmon\nShuffle SOAR\nVirusTotal\nTheHive'],
  ['cmd','latest-case'],
  ['out','Suspicious File Creation by PowerShell'],
  ['cmd','verdict'],
  ['out','True Positive // Impact: No // Remediation: None required']
];
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function runTerminal(){
  if (!terminal) return;
  terminal.innerHTML = '';
  for(const [type,text] of sequence){
    if(type === 'cmd'){
      const line = document.createElement('div');
      line.className = 'term-line';
      terminal.appendChild(line);
      const prefix = '<span class="term-prompt">soc@lab</span><span>:~$ </span>';
      let typed = '';
      for(const ch of text){
        typed += ch;
        line.innerHTML = prefix + typed + '<span class="term-cursor"></span>';
        await sleep(38);
      }
      line.innerHTML = prefix + typed;
      await sleep(180);
    } else {
      const out = document.createElement('div');
      out.className = 'term-line term-out';
      out.textContent = text;
      terminal.appendChild(out);
      await sleep(380);
    }
  }
  await sleep(1700);
  runTerminal();
}
if (terminal) runTerminal();

const lightbox = document.getElementById('lightbox');
const lightboxImg = document.getElementById('lightboxImg');
const closeBtn = document.getElementById('lightboxClose');
document.querySelectorAll('[data-lightbox]').forEach(img => {
  img.tabIndex = 0;
  img.setAttribute('role', 'button');
  img.setAttribute('aria-label', `${img.alt}. Open full-size image`);
  img.addEventListener('click', () => {
    if (!lightbox || !lightboxImg) return;
    lightboxImg.src = img.src;
    lightbox.classList.add('open');
    lightbox.setAttribute('aria-hidden','false');
    document.body.style.overflow = 'hidden';
    if (closeBtn) closeBtn.focus();
  });
  img.addEventListener('keydown', event => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      img.click();
    }
  });
});
function closeLightbox(){
  if (!lightbox) return;
  lightbox.classList.remove('open');
  lightbox.setAttribute('aria-hidden','true');
  document.body.style.overflow = '';
}
if (closeBtn) closeBtn.addEventListener('click', closeLightbox);
if (lightbox) lightbox.addEventListener('click', e => { if(e.target === lightbox) closeLightbox(); });
document.addEventListener('keydown', e => { if(e.key === 'Escape') closeLightbox(); });
