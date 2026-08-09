(function () {
  const JOB_ID = "{{JOB_ID}}";
  const BASE_DOMAIN = "{{BASE_DOMAIN}}";

  function toLocal(url) {
    if (!url) return url;
    try {
      const parsed = new URL(url, window.location.href);
      if (parsed.hostname === BASE_DOMAIN) {
        return "/clone/" + JOB_ID + parsed.pathname + parsed.search;
      }
      return url;
    } catch (e) {
      if (typeof url === "string" && url.startsWith("/") && !url.startsWith("//")) {
        return "/clone/" + JOB_ID + url;
      }
      return url;
    }
  }

  /* --- Intercept <a> clicks that JS may have attached handlers to --- */
  document.addEventListener("click", function (e) {
    const a = e.target.closest && e.target.closest("a[href]");
    if (!a) return;
    const href = a.getAttribute("href");
    const local = toLocal(href);
    if (local !== href) {
      e.preventDefault();
      window.location.href = local;
    }
  }, true);

  /* --- Intercept history.pushState / replaceState (SPA routers) --- */
  const _push = history.pushState.bind(history);
  const _replace = history.replaceState.bind(history);

  history.pushState = function (state, title, url) {
    return _push(state, title, url == null ? url : toLocal(url));
  };
  history.replaceState = function (state, title, url) {
    return _replace(state, title, url == null ? url : toLocal(url));
  };

  /* --- Intercept fetch() to the same domain --- */
  const _fetch = window.fetch ? window.fetch.bind(window) : null;
  if (_fetch) {
    window.fetch = function (input, init) {
      if (typeof input === "string") {
        input = toLocal(input);
      } else if (input && typeof input === "object" && "url" in input) {
        try {
          input = new Request(toLocal(input.url), input);
        } catch (e) { /* leave input as-is if reconstruction fails */ }
      }
      return _fetch(input, init);
    };
  }

  /* --- Intercept XMLHttpRequest --- */
  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    const rest = Array.prototype.slice.call(arguments, 2);
    return _open.apply(this, [method, toLocal(url)].concat(rest));
  };

  /* --- Intercept window.location.assign / replace --- */
  try {
    const _assign = window.location.assign.bind(window.location);
    const _locReplace = window.location.replace.bind(window.location);

    window.location.assign = function (url) {
      return _assign(toLocal(url));
    };
    window.location.replace = function (url) {
      return _locReplace(toLocal(url));
    };
  } catch (e) {
    /* window.location.assign/replace aren't always overridable in every
       browser sandbox — navigation-via-click and pushState/fetch/XHR
       interception above still cover the common cases. */
  }

  console.log("[WebLens] Navigation interceptor active. Job: " + JOB_ID);
})();
