const progress = document.querySelector('.scroll-progress span');
const updateProgress = () => { const max = document.documentElement.scrollHeight - window.innerHeight; progress.style.width = `${max > 0 ? (window.scrollY / max) * 100 : 0}%`; };
window.addEventListener('scroll', updateProgress, { passive: true }); updateProgress();
const observer = new IntersectionObserver((entries) => { entries.forEach((entry) => { if (entry.isIntersecting) { entry.target.classList.add('is-visible'); observer.unobserve(entry.target); } }); }, { threshold: 0.13 });
document.querySelectorAll('.reveal').forEach((item) => observer.observe(item));
document.querySelectorAll('[data-copy]').forEach((button) => { button.addEventListener('click', async () => { try { await navigator.clipboard.writeText(button.dataset.copy); button.textContent = 'Copied'; setTimeout(() => { button.textContent = 'Copy'; }, 1400); } catch { button.textContent = 'Copy unavailable'; } }); });
