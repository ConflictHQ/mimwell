/* Shared fixture-testable scheduler. No authority, credentials or transport here. */
(function (root) {
  'use strict';
  function gate(request, perMinute, now = Date.now) {
    let calls = [];
    return async (...args) => {
      const time = now(); calls = calls.filter(at => time - at < 60000);
      if (calls.length >= perMinute) throw new Error('Request budget reached; retry in a minute');
      calls.push(time); return request(...args);
    };
  }
  function poll({read, changed, failed, seconds, initial, schedule = setTimeout, cancel = clearTimeout}) {
    let timer, stopped = false, previous = initial === undefined ? undefined : JSON.stringify(initial), delay = seconds * 1000;
    async function tick() {
      try {
        const next = JSON.stringify(await read());
        if (stopped) return;
        if (previous !== undefined && previous !== next) await changed();
        previous = next; delay = seconds * 1000;
      } catch (error) {if (stopped) return; delay = Math.min(delay * 2, Math.max(300000, seconds * 1000)); failed(error);}
      if (!stopped) timer = schedule(tick, delay);
    }
    timer = schedule(tick, initial === undefined ? 0 : delay);
    return () => {stopped = true; cancel(timer);};
  }
  const api = Object.freeze({gate, poll});
  if (typeof module !== 'undefined') module.exports = api;
  else root.BrainAppHelpers = api;
})(globalThis);
