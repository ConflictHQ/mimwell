// Cycle the tagline's rotating term. Reduced-motion users keep the first term.
document$.subscribe(function () {
  var words = document.querySelectorAll('.mw-rotator > span');
  if (words.length < 2 || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  var i = 0;
  clearInterval(window.__mwRotator);
  window.__mwRotator = setInterval(function () {
    var cur = words[i]; i = (i + 1) % words.length; var next = words[i];
    cur.classList.remove('on'); cur.classList.add('out');
    next.classList.remove('out'); next.classList.add('on');
    setTimeout(function () { cur.classList.remove('out'); }, 500);
  }, 2400);
});
