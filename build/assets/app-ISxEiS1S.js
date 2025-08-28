const __vite__mapDeps = (
  i,
  m = __vite__mapDeps,
  d = m.f ||
    (m.f = [
      "assets/browserAll-F8FjJuYr.js",
      "assets/webworkerAll-DhhJBp7F.js",
      "assets/Graphics-nZJdCvau.js",
      "assets/CanvasTextGenerator-DVVSTSyj.js",
      "assets/app-DEV1gfeS.js",
      "assets/app-B3dtaGch.css",
      "assets/ConfirmPassword-CGqZ4eGy.js",
      "assets/InputError-BeX5CBml.js",
      "assets/InputLabel-Cg62RQsb.js",
      "assets/PrimaryButton-CY_yXSaT.js",
      "assets/TextInput-BXwS4CZ-.js",
      "assets/GuestLayout-Cv6dpd1v.js",
      "assets/ApplicationLogo-C7YUkWYE.js",
      "assets/ForgotPassword-D2wYq80S.js",
      "assets/Login-_PHr24uR.js",
      "assets/Checkbox-BaVb8NSd.js",
      "assets/Register-k--fK94k.js",
      "assets/ResetPassword-TXam1puG.js",
      "assets/VerifyEmail-BdCPZrp2.js",
      "assets/CentralAdminLayout-Cbu_i4m7.js",
      "assets/CentralAdminLayout-DYnAoKxo.css",
      "assets/Dashboard-CovVvXVO.js",
      "assets/Edit-C2Gwxhlu.js",
      "assets/AuthenticatedLayout-_KqLO-Hi.js",
      "assets/Modal-C_qxCcmu.js",
      "assets/transition-B2rbusXP.js",
      "assets/DeleteUserForm-CaYkx09F.js",
      "assets/UpdatePasswordForm-B8a4qOZc.js",
      "assets/UpdateProfileInformationForm-B7HaU-sl.js",
      "assets/Deposits-rD0cUBS9.js",
      "assets/AdminLayout-XOYPXGkG.js",
      "assets/ChangePasswordModal-BWoRzeQs.js",
      "assets/AdminLayout-BlhtlAFt.css",
      "assets/TransactionModal-D6eZM7vU.js",
      "assets/Jackpot-CBhrBH6I.js",
      "assets/EditUserModal-Cm7Tw_4Y.js",
      "assets/ResetPasswordModal-BvQoIqGF.js",
      "assets/SangriaFiscal-BiGG_tFP.js",
      "assets/SangriaFiscalProfessional-CPfaWSjD.js",
      "assets/SangriaFiscal_backup-BvKzKN2U.js",
      "assets/Settings-CkZO6HhW.js",
      "assets/Users-CIkGEKaF.js",
      "assets/WeizhenManager-DHEFPIOy.js",
      "assets/Withdrawals-DmZsUA6j.js",
      "assets/Login-Db_DB0y2.js",
      "assets/Register-CgqfjIpJ.js",
      "assets/InGame-BuzDpMYM.js",
      "assets/gameboard-C0YZYNRD.js",
      "assets/gameboard-DlinXd9b.css",
      "assets/AuthModal-C92geU3j.js",
      "assets/HelpModal-CCSZe4Ch.js",
      "assets/Launch-CvycAOTb.js",
      "assets/AgentPanelModal-DQL6vaSx.js",
      "assets/AgentPanelModal-DkfFGnc5.css",
      "assets/Launch-DwIndhFC.css",
      "assets/LobbyUI-BKWQ5jUv.js",
      "assets/Main-CNXtrjPC.js",
      "assets/Unauthorized-B1N0TLZf.js",
      "assets/Create-DUD93sqd.js",
      "assets/Welcome-B6zCJ_m7.js",
    ])
) => i.map((i) => d[i]);
import "./app-DEV1gfeS.js";
function T0(r, e) {
  for (var i = 0; i < e.length; i++) {
    const o = e[i];
    if (typeof o != "string" && !Array.isArray(o)) {
      for (const l in o)
        if (l !== "default" && !(l in r)) {
          const c = Object.getOwnPropertyDescriptor(o, l);
          c &&
            Object.defineProperty(
              r,
              l,
              c.get ? c : { enumerable: !0, get: () => o[l] }
            );
        }
    }
  }
  return Object.freeze(
    Object.defineProperty(r, Symbol.toStringTag, { value: "Module" })
  );
}
const O0 = "modulepreload",
  M0 = function (r) {
    return "/build/" + r;
  },
  Md = {},
  Pe = function (e, i, o) {
    let l = Promise.resolve();
    if (i && i.length > 0) {
      let m = function (p) {
        return Promise.all(
          p.map((g) =>
            Promise.resolve(g).then(
              (v) => ({ status: "fulfilled", value: v }),
              (v) => ({ status: "rejected", reason: v })
            )
          )
        );
      };
      document.getElementsByTagName("link");
      const f = document.querySelector("meta[property=csp-nonce]"),
        d = f?.nonce || f?.getAttribute("nonce");
      l = m(
        i.map((p) => {
          if (((p = M0(p)), p in Md)) return;
          Md[p] = !0;
          const g = p.endsWith(".css"),
            v = g ? '[rel="stylesheet"]' : "";
          if (document.querySelector(`link[href="${p}"]${v}`)) return;
          const x = document.createElement("link");
          if (
            ((x.rel = g ? "stylesheet" : O0),
            g || (x.as = "script"),
            (x.crossOrigin = ""),
            (x.href = p),
            d && x.setAttribute("nonce", d),
            document.head.appendChild(x),
            g)
          )
            return new Promise((w, E) => {
              x.addEventListener("load", w),
                x.addEventListener("error", () =>
                  E(new Error(`Unable to preload CSS for ${p}`))
                );
            });
        })
      );
    }
    function c(f) {
      const d = new Event("vite:preloadError", { cancelable: !0 });
      if (((d.payload = f), window.dispatchEvent(d), !d.defaultPrevented))
        throw f;
    }
    return l.then((f) => {
      for (const d of f || []) d.status === "rejected" && c(d.reason);
      return e().catch(c);
    });
  };
var Id =
  typeof globalThis < "u"
    ? globalThis
    : typeof window < "u"
    ? window
    : typeof global < "u"
    ? global
    : typeof self < "u"
    ? self
    : {};
function Mm(r) {
  return r && r.__esModule && Object.prototype.hasOwnProperty.call(r, "default")
    ? r.default
    : r;
}
function I0(r) {
  if (Object.prototype.hasOwnProperty.call(r, "__esModule")) return r;
  var e = r.default;
  if (typeof e == "function") {
    var i = function o() {
      var l = !1;
      try {
        l = this instanceof o;
      } catch {}
      return l
        ? Reflect.construct(e, arguments, this.constructor)
        : e.apply(this, arguments);
    };
    i.prototype = e.prototype;
  } else i = {};
  return (
    Object.defineProperty(i, "__esModule", { value: !0 }),
    Object.keys(r).forEach(function (o) {
      var l = Object.getOwnPropertyDescriptor(r, o);
      Object.defineProperty(
        i,
        o,
        l.get
          ? l
          : {
              enumerable: !0,
              get: function () {
                return r[o];
              },
            }
      );
    }),
    i
  );
}
var uu = { exports: {} },
  ps = {},
  cu = { exports: {} },
  Ee = {};
/**
 * @license React
 * react.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */ var Ld;
function L0() {
  if (Ld) return Ee;
  Ld = 1;
  var r = Symbol.for("react.element"),
    e = Symbol.for("react.portal"),
    i = Symbol.for("react.fragment"),
    o = Symbol.for("react.strict_mode"),
    l = Symbol.for("react.profiler"),
    c = Symbol.for("react.provider"),
    f = Symbol.for("react.context"),
    d = Symbol.for("react.forward_ref"),
    m = Symbol.for("react.suspense"),
    p = Symbol.for("react.memo"),
    g = Symbol.for("react.lazy"),
    v = Symbol.iterator;
  function x(R) {
    return R === null || typeof R != "object"
      ? null
      : ((R = (v && R[v]) || R["@@iterator"]),
        typeof R == "function" ? R : null);
  }
  var w = {
      isMounted: function () {
        return !1;
      },
      enqueueForceUpdate: function () {},
      enqueueReplaceState: function () {},
      enqueueSetState: function () {},
    },
    E = Object.assign,
    k = {};
  function _(R, B, le) {
    (this.props = R),
      (this.context = B),
      (this.refs = k),
      (this.updater = le || w);
  }
  (_.prototype.isReactComponent = {}),
    (_.prototype.setState = function (R, B) {
      if (typeof R != "object" && typeof R != "function" && R != null)
        throw Error(
          "setState(...): takes an object of state variables to update or a function which returns an object of state variables."
        );
      this.updater.enqueueSetState(this, R, B, "setState");
    }),
    (_.prototype.forceUpdate = function (R) {
      this.updater.enqueueForceUpdate(this, R, "forceUpdate");
    });
  function A() {}
  A.prototype = _.prototype;
  function b(R, B, le) {
    (this.props = R),
      (this.context = B),
      (this.refs = k),
      (this.updater = le || w);
  }
  var N = (b.prototype = new A());
  (N.constructor = b), E(N, _.prototype), (N.isPureReactComponent = !0);
  var U = Array.isArray,
    z = Object.prototype.hasOwnProperty,
    H = { current: null },
    G = { key: !0, ref: !0, __self: !0, __source: !0 };
  function Q(R, B, le) {
    var he,
      W = {},
      re = null,
      Y = null;
    if (B != null)
      for (he in (B.ref !== void 0 && (Y = B.ref),
      B.key !== void 0 && (re = "" + B.key),
      B))
        z.call(B, he) && !G.hasOwnProperty(he) && (W[he] = B[he]);
    var ue = arguments.length - 2;
    if (ue === 1) W.children = le;
    else if (1 < ue) {
      for (var ne = Array(ue), de = 0; de < ue; de++)
        ne[de] = arguments[de + 2];
      W.children = ne;
    }
    if (R && R.defaultProps)
      for (he in ((ue = R.defaultProps), ue))
        W[he] === void 0 && (W[he] = ue[he]);
    return {
      $$typeof: r,
      type: R,
      key: re,
      ref: Y,
      props: W,
      _owner: H.current,
    };
  }
  function me(R, B) {
    return {
      $$typeof: r,
      type: R.type,
      key: B,
      ref: R.ref,
      props: R.props,
      _owner: R._owner,
    };
  }
  function ae(R) {
    return typeof R == "object" && R !== null && R.$$typeof === r;
  }
  function xe(R) {
    var B = { "=": "=0", ":": "=2" };
    return (
      "$" +
      R.replace(/[=:]/g, function (le) {
        return B[le];
      })
    );
  }
  var te = /\/+/g;
  function _e(R, B) {
    return typeof R == "object" && R !== null && R.key != null
      ? xe("" + R.key)
      : B.toString(36);
  }
  function Ae(R, B, le, he, W) {
    var re = typeof R;
    (re === "undefined" || re === "boolean") && (R = null);
    var Y = !1;
    if (R === null) Y = !0;
    else
      switch (re) {
        case "string":
        case "number":
          Y = !0;
          break;
        case "object":
          switch (R.$$typeof) {
            case r:
            case e:
              Y = !0;
          }
      }
    if (Y)
      return (
        (Y = R),
        (W = W(Y)),
        (R = he === "" ? "." + _e(Y, 0) : he),
        U(W)
          ? ((le = ""),
            R != null && (le = R.replace(te, "$&/") + "/"),
            Ae(W, B, le, "", function (de) {
              return de;
            }))
          : W != null &&
            (ae(W) &&
              (W = me(
                W,
                le +
                  (!W.key || (Y && Y.key === W.key)
                    ? ""
                    : ("" + W.key).replace(te, "$&/") + "/") +
                  R
              )),
            B.push(W)),
        1
      );
    if (((Y = 0), (he = he === "" ? "." : he + ":"), U(R)))
      for (var ue = 0; ue < R.length; ue++) {
        re = R[ue];
        var ne = he + _e(re, ue);
        Y += Ae(re, B, le, ne, W);
      }
    else if (((ne = x(R)), typeof ne == "function"))
      for (R = ne.call(R), ue = 0; !(re = R.next()).done; )
        (re = re.value), (ne = he + _e(re, ue++)), (Y += Ae(re, B, le, ne, W));
    else if (re === "object")
      throw (
        ((B = String(R)),
        Error(
          "Objects are not valid as a React child (found: " +
            (B === "[object Object]"
              ? "object with keys {" + Object.keys(R).join(", ") + "}"
              : B) +
            "). If you meant to render a collection of children, use an array instead."
        ))
      );
    return Y;
  }
  function ke(R, B, le) {
    if (R == null) return R;
    var he = [],
      W = 0;
    return (
      Ae(R, he, "", "", function (re) {
        return B.call(le, re, W++);
      }),
      he
    );
  }
  function be(R) {
    if (R._status === -1) {
      var B = R._result;
      (B = B()),
        B.then(
          function (le) {
            (R._status === 0 || R._status === -1) &&
              ((R._status = 1), (R._result = le));
          },
          function (le) {
            (R._status === 0 || R._status === -1) &&
              ((R._status = 2), (R._result = le));
          }
        ),
        R._status === -1 && ((R._status = 0), (R._result = B));
    }
    if (R._status === 1) return R._result.default;
    throw R._result;
  }
  var Se = { current: null },
    D = { transition: null },
    J = {
      ReactCurrentDispatcher: Se,
      ReactCurrentBatchConfig: D,
      ReactCurrentOwner: H,
    };
  function X() {
    throw Error("act(...) is not supported in production builds of React.");
  }
  return (
    (Ee.Children = {
      map: ke,
      forEach: function (R, B, le) {
        ke(
          R,
          function () {
            B.apply(this, arguments);
          },
          le
        );
      },
      count: function (R) {
        var B = 0;
        return (
          ke(R, function () {
            B++;
          }),
          B
        );
      },
      toArray: function (R) {
        return (
          ke(R, function (B) {
            return B;
          }) || []
        );
      },
      only: function (R) {
        if (!ae(R))
          throw Error(
            "React.Children.only expected to receive a single React element child."
          );
        return R;
      },
    }),
    (Ee.Component = _),
    (Ee.Fragment = i),
    (Ee.Profiler = l),
    (Ee.PureComponent = b),
    (Ee.StrictMode = o),
    (Ee.Suspense = m),
    (Ee.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED = J),
    (Ee.act = X),
    (Ee.cloneElement = function (R, B, le) {
      if (R == null)
        throw Error(
          "React.cloneElement(...): The argument must be a React element, but you passed " +
            R +
            "."
        );
      var he = E({}, R.props),
        W = R.key,
        re = R.ref,
        Y = R._owner;
      if (B != null) {
        if (
          (B.ref !== void 0 && ((re = B.ref), (Y = H.current)),
          B.key !== void 0 && (W = "" + B.key),
          R.type && R.type.defaultProps)
        )
          var ue = R.type.defaultProps;
        for (ne in B)
          z.call(B, ne) &&
            !G.hasOwnProperty(ne) &&
            (he[ne] = B[ne] === void 0 && ue !== void 0 ? ue[ne] : B[ne]);
      }
      var ne = arguments.length - 2;
      if (ne === 1) he.children = le;
      else if (1 < ne) {
        ue = Array(ne);
        for (var de = 0; de < ne; de++) ue[de] = arguments[de + 2];
        he.children = ue;
      }
      return {
        $$typeof: r,
        type: R.type,
        key: W,
        ref: re,
        props: he,
        _owner: Y,
      };
    }),
    (Ee.createContext = function (R) {
      return (
        (R = {
          $$typeof: f,
          _currentValue: R,
          _currentValue2: R,
          _threadCount: 0,
          Provider: null,
          Consumer: null,
          _defaultValue: null,
          _globalName: null,
        }),
        (R.Provider = { $$typeof: c, _context: R }),
        (R.Consumer = R)
      );
    }),
    (Ee.createElement = Q),
    (Ee.createFactory = function (R) {
      var B = Q.bind(null, R);
      return (B.type = R), B;
    }),
    (Ee.createRef = function () {
      return { current: null };
    }),
    (Ee.forwardRef = function (R) {
      return { $$typeof: d, render: R };
    }),
    (Ee.isValidElement = ae),
    (Ee.lazy = function (R) {
      return { $$typeof: g, _payload: { _status: -1, _result: R }, _init: be };
    }),
    (Ee.memo = function (R, B) {
      return { $$typeof: p, type: R, compare: B === void 0 ? null : B };
    }),
    (Ee.startTransition = function (R) {
      var B = D.transition;
      D.transition = {};
      try {
        R();
      } finally {
        D.transition = B;
      }
    }),
    (Ee.unstable_act = X),
    (Ee.useCallback = function (R, B) {
      return Se.current.useCallback(R, B);
    }),
    (Ee.useContext = function (R) {
      return Se.current.useContext(R);
    }),
    (Ee.useDebugValue = function () {}),
    (Ee.useDeferredValue = function (R) {
      return Se.current.useDeferredValue(R);
    }),
    (Ee.useEffect = function (R, B) {
      return Se.current.useEffect(R, B);
    }),
    (Ee.useId = function () {
      return Se.current.useId();
    }),
    (Ee.useImperativeHandle = function (R, B, le) {
      return Se.current.useImperativeHandle(R, B, le);
    }),
    (Ee.useInsertionEffect = function (R, B) {
      return Se.current.useInsertionEffect(R, B);
    }),
    (Ee.useLayoutEffect = function (R, B) {
      return Se.current.useLayoutEffect(R, B);
    }),
    (Ee.useMemo = function (R, B) {
      return Se.current.useMemo(R, B);
    }),
    (Ee.useReducer = function (R, B, le) {
      return Se.current.useReducer(R, B, le);
    }),
    (Ee.useRef = function (R) {
      return Se.current.useRef(R);
    }),
    (Ee.useState = function (R) {
      return Se.current.useState(R);
    }),
    (Ee.useSyncExternalStore = function (R, B, le) {
      return Se.current.useSyncExternalStore(R, B, le);
    }),
    (Ee.useTransition = function () {
      return Se.current.useTransition();
    }),
    (Ee.version = "18.3.1"),
    Ee
  );
}
var Fd;
function Wc() {
  return Fd || ((Fd = 1), (cu.exports = L0())), cu.exports;
}
/**
 * @license React
 * react-jsx-runtime.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */ var Nd;
function F0() {
  if (Nd) return ps;
  Nd = 1;
  var r = Wc(),
    e = Symbol.for("react.element"),
    i = Symbol.for("react.fragment"),
    o = Object.prototype.hasOwnProperty,
    l = r.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner,
    c = { key: !0, ref: !0, __self: !0, __source: !0 };
  function f(d, m, p) {
    var g,
      v = {},
      x = null,
      w = null;
    p !== void 0 && (x = "" + p),
      m.key !== void 0 && (x = "" + m.key),
      m.ref !== void 0 && (w = m.ref);
    for (g in m) o.call(m, g) && !c.hasOwnProperty(g) && (v[g] = m[g]);
    if (d && d.defaultProps)
      for (g in ((m = d.defaultProps), m)) v[g] === void 0 && (v[g] = m[g]);
    return {
      $$typeof: e,
      type: d,
      key: x,
      ref: w,
      props: v,
      _owner: l.current,
    };
  }
  return (ps.Fragment = i), (ps.jsx = f), (ps.jsxs = f), ps;
}
var Dd;
function N0() {
  return Dd || ((Dd = 1), (uu.exports = F0())), uu.exports;
}
var D0 = N0();
function Im(r, e) {
  return function () {
    return r.apply(e, arguments);
  };
}
const { toString: B0 } = Object.prototype,
  { getPrototypeOf: Xc } = Object,
  { iterator: va, toStringTag: Lm } = Symbol,
  _a = ((r) => (e) => {
    const i = B0.call(e);
    return r[i] || (r[i] = i.slice(8, -1).toLowerCase());
  })(Object.create(null)),
  ur = (r) => ((r = r.toLowerCase()), (e) => _a(e) === r),
  wa = (r) => (e) => typeof e === r,
  { isArray: Ci } = Array,
  ks = wa("undefined");
function Os(r) {
  return (
    r !== null &&
    !ks(r) &&
    r.constructor !== null &&
    !ks(r.constructor) &&
    Lt(r.constructor.isBuffer) &&
    r.constructor.isBuffer(r)
  );
}
const Fm = ur("ArrayBuffer");
function U0(r) {
  let e;
  return (
    typeof ArrayBuffer < "u" && ArrayBuffer.isView
      ? (e = ArrayBuffer.isView(r))
      : (e = r && r.buffer && Fm(r.buffer)),
    e
  );
}
const j0 = wa("string"),
  Lt = wa("function"),
  Nm = wa("number"),
  Ms = (r) => r !== null && typeof r == "object",
  $0 = (r) => r === !0 || r === !1,
  ra = (r) => {
    if (_a(r) !== "object") return !1;
    const e = Xc(r);
    return (
      (e === null ||
        e === Object.prototype ||
        Object.getPrototypeOf(e) === null) &&
      !(Lm in r) &&
      !(va in r)
    );
  },
  z0 = (r) => {
    if (!Ms(r) || Os(r)) return !1;
    try {
      return (
        Object.keys(r).length === 0 &&
        Object.getPrototypeOf(r) === Object.prototype
      );
    } catch {
      return !1;
    }
  },
  H0 = ur("Date"),
  q0 = ur("File"),
  V0 = ur("Blob"),
  G0 = ur("FileList"),
  W0 = (r) => Ms(r) && Lt(r.pipe),
  X0 = (r) => {
    let e;
    return (
      r &&
      ((typeof FormData == "function" && r instanceof FormData) ||
        (Lt(r.append) &&
          ((e = _a(r)) === "formdata" ||
            (e === "object" &&
              Lt(r.toString) &&
              r.toString() === "[object FormData]"))))
    );
  },
  Y0 = ur("URLSearchParams"),
  [Q0, K0, J0, Z0] = ["ReadableStream", "Request", "Response", "Headers"].map(
    ur
  ),
  e_ = (r) =>
    r.trim ? r.trim() : r.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, "");
function Is(r, e, { allOwnKeys: i = !1 } = {}) {
  if (r === null || typeof r > "u") return;
  let o, l;
  if ((typeof r != "object" && (r = [r]), Ci(r)))
    for (o = 0, l = r.length; o < l; o++) e.call(null, r[o], o, r);
  else {
    if (Os(r)) return;
    const c = i ? Object.getOwnPropertyNames(r) : Object.keys(r),
      f = c.length;
    let d;
    for (o = 0; o < f; o++) (d = c[o]), e.call(null, r[d], d, r);
  }
}
function Dm(r, e) {
  if (Os(r)) return null;
  e = e.toLowerCase();
  const i = Object.keys(r);
  let o = i.length,
    l;
  for (; o-- > 0; ) if (((l = i[o]), e === l.toLowerCase())) return l;
  return null;
}
const jn =
    typeof globalThis < "u"
      ? globalThis
      : typeof self < "u"
      ? self
      : typeof window < "u"
      ? window
      : global,
  Bm = (r) => !ks(r) && r !== jn;
function Ec() {
  const { caseless: r } = (Bm(this) && this) || {},
    e = {},
    i = (o, l) => {
      const c = (r && Dm(e, l)) || l;
      ra(e[c]) && ra(o)
        ? (e[c] = Ec(e[c], o))
        : ra(o)
        ? (e[c] = Ec({}, o))
        : Ci(o)
        ? (e[c] = o.slice())
        : (e[c] = o);
    };
  for (let o = 0, l = arguments.length; o < l; o++)
    arguments[o] && Is(arguments[o], i);
  return e;
}
const t_ = (r, e, i, { allOwnKeys: o } = {}) => (
    Is(
      e,
      (l, c) => {
        i && Lt(l) ? (r[c] = Im(l, i)) : (r[c] = l);
      },
      { allOwnKeys: o }
    ),
    r
  ),
  r_ = (r) => (r.charCodeAt(0) === 65279 && (r = r.slice(1)), r),
  n_ = (r, e, i, o) => {
    (r.prototype = Object.create(e.prototype, o)),
      (r.prototype.constructor = r),
      Object.defineProperty(r, "super", { value: e.prototype }),
      i && Object.assign(r.prototype, i);
  },
  i_ = (r, e, i, o) => {
    let l, c, f;
    const d = {};
    if (((e = e || {}), r == null)) return e;
    do {
      for (l = Object.getOwnPropertyNames(r), c = l.length; c-- > 0; )
        (f = l[c]), (!o || o(f, r, e)) && !d[f] && ((e[f] = r[f]), (d[f] = !0));
      r = i !== !1 && Xc(r);
    } while (r && (!i || i(r, e)) && r !== Object.prototype);
    return e;
  },
  s_ = (r, e, i) => {
    (r = String(r)),
      (i === void 0 || i > r.length) && (i = r.length),
      (i -= e.length);
    const o = r.indexOf(e, i);
    return o !== -1 && o === i;
  },
  o_ = (r) => {
    if (!r) return null;
    if (Ci(r)) return r;
    let e = r.length;
    if (!Nm(e)) return null;
    const i = new Array(e);
    for (; e-- > 0; ) i[e] = r[e];
    return i;
  },
  a_ = (
    (r) => (e) =>
      r && e instanceof r
  )(typeof Uint8Array < "u" && Xc(Uint8Array)),
  l_ = (r, e) => {
    const o = (r && r[va]).call(r);
    let l;
    for (; (l = o.next()) && !l.done; ) {
      const c = l.value;
      e.call(r, c[0], c[1]);
    }
  },
  u_ = (r, e) => {
    let i;
    const o = [];
    for (; (i = r.exec(e)) !== null; ) o.push(i);
    return o;
  },
  c_ = ur("HTMLFormElement"),
  f_ = (r) =>
    r.toLowerCase().replace(/[-_\s]([a-z\d])(\w*)/g, function (i, o, l) {
      return o.toUpperCase() + l;
    }),
  Bd = (
    ({ hasOwnProperty: r }) =>
    (e, i) =>
      r.call(e, i)
  )(Object.prototype),
  h_ = ur("RegExp"),
  Um = (r, e) => {
    const i = Object.getOwnPropertyDescriptors(r),
      o = {};
    Is(i, (l, c) => {
      let f;
      (f = e(l, c, r)) !== !1 && (o[c] = f || l);
    }),
      Object.defineProperties(r, o);
  },
  d_ = (r) => {
    Um(r, (e, i) => {
      if (Lt(r) && ["arguments", "caller", "callee"].indexOf(i) !== -1)
        return !1;
      const o = r[i];
      if (Lt(o)) {
        if (((e.enumerable = !1), "writable" in e)) {
          e.writable = !1;
          return;
        }
        e.set ||
          (e.set = () => {
            throw Error("Can not rewrite read-only method '" + i + "'");
          });
      }
    });
  },
  p_ = (r, e) => {
    const i = {},
      o = (l) => {
        l.forEach((c) => {
          i[c] = !0;
        });
      };
    return Ci(r) ? o(r) : o(String(r).split(e)), i;
  },
  m_ = () => {},
  y_ = (r, e) => (r != null && Number.isFinite((r = +r)) ? r : e);
function g_(r) {
  return !!(r && Lt(r.append) && r[Lm] === "FormData" && r[va]);
}
const v_ = (r) => {
    const e = new Array(10),
      i = (o, l) => {
        if (Ms(o)) {
          if (e.indexOf(o) >= 0) return;
          if (Os(o)) return o;
          if (!("toJSON" in o)) {
            e[l] = o;
            const c = Ci(o) ? [] : {};
            return (
              Is(o, (f, d) => {
                const m = i(f, l + 1);
                !ks(m) && (c[d] = m);
              }),
              (e[l] = void 0),
              c
            );
          }
        }
        return o;
      };
    return i(r, 0);
  },
  __ = ur("AsyncFunction"),
  w_ = (r) => r && (Ms(r) || Lt(r)) && Lt(r.then) && Lt(r.catch),
  jm = ((r, e) =>
    r
      ? setImmediate
      : e
      ? ((i, o) => (
          jn.addEventListener(
            "message",
            ({ source: l, data: c }) => {
              l === jn && c === i && o.length && o.shift()();
            },
            !1
          ),
          (l) => {
            o.push(l), jn.postMessage(i, "*");
          }
        ))(`axios@${Math.random()}`, [])
      : (i) => setTimeout(i))(
    typeof setImmediate == "function",
    Lt(jn.postMessage)
  ),
  x_ =
    typeof queueMicrotask < "u"
      ? queueMicrotask.bind(jn)
      : (typeof process < "u" && process.nextTick) || jm,
  S_ = (r) => r != null && Lt(r[va]),
  F = {
    isArray: Ci,
    isArrayBuffer: Fm,
    isBuffer: Os,
    isFormData: X0,
    isArrayBufferView: U0,
    isString: j0,
    isNumber: Nm,
    isBoolean: $0,
    isObject: Ms,
    isPlainObject: ra,
    isEmptyObject: z0,
    isReadableStream: Q0,
    isRequest: K0,
    isResponse: J0,
    isHeaders: Z0,
    isUndefined: ks,
    isDate: H0,
    isFile: q0,
    isBlob: V0,
    isRegExp: h_,
    isFunction: Lt,
    isStream: W0,
    isURLSearchParams: Y0,
    isTypedArray: a_,
    isFileList: G0,
    forEach: Is,
    merge: Ec,
    extend: t_,
    trim: e_,
    stripBOM: r_,
    inherits: n_,
    toFlatObject: i_,
    kindOf: _a,
    kindOfTest: ur,
    endsWith: s_,
    toArray: o_,
    forEachEntry: l_,
    matchAll: u_,
    isHTMLForm: c_,
    hasOwnProperty: Bd,
    hasOwnProp: Bd,
    reduceDescriptors: Um,
    freezeMethods: d_,
    toObjectSet: p_,
    toCamelCase: f_,
    noop: m_,
    toFiniteNumber: y_,
    findKey: Dm,
    global: jn,
    isContextDefined: Bm,
    isSpecCompliantForm: g_,
    toJSONObject: v_,
    isAsyncFn: __,
    isThenable: w_,
    setImmediate: jm,
    asap: x_,
    isIterable: S_,
  };
function we(r, e, i, o, l) {
  Error.call(this),
    Error.captureStackTrace
      ? Error.captureStackTrace(this, this.constructor)
      : (this.stack = new Error().stack),
    (this.message = r),
    (this.name = "AxiosError"),
    e && (this.code = e),
    i && (this.config = i),
    o && (this.request = o),
    l && ((this.response = l), (this.status = l.status ? l.status : null));
}
F.inherits(we, Error, {
  toJSON: function () {
    return {
      message: this.message,
      name: this.name,
      description: this.description,
      number: this.number,
      fileName: this.fileName,
      lineNumber: this.lineNumber,
      columnNumber: this.columnNumber,
      stack: this.stack,
      config: F.toJSONObject(this.config),
      code: this.code,
      status: this.status,
    };
  },
});
const $m = we.prototype,
  zm = {};
[
  "ERR_BAD_OPTION_VALUE",
  "ERR_BAD_OPTION",
  "ECONNABORTED",
  "ETIMEDOUT",
  "ERR_NETWORK",
  "ERR_FR_TOO_MANY_REDIRECTS",
  "ERR_DEPRECATED",
  "ERR_BAD_RESPONSE",
  "ERR_BAD_REQUEST",
  "ERR_CANCELED",
  "ERR_NOT_SUPPORT",
  "ERR_INVALID_URL",
].forEach((r) => {
  zm[r] = { value: r };
});
Object.defineProperties(we, zm);
Object.defineProperty($m, "isAxiosError", { value: !0 });
we.from = (r, e, i, o, l, c) => {
  const f = Object.create($m);
  return (
    F.toFlatObject(
      r,
      f,
      function (m) {
        return m !== Error.prototype;
      },
      (d) => d !== "isAxiosError"
    ),
    we.call(f, r.message, e, i, o, l),
    (f.cause = r),
    (f.name = r.name),
    c && Object.assign(f, c),
    f
  );
};
const E_ = null;
function Pc(r) {
  return F.isPlainObject(r) || F.isArray(r);
}
function Hm(r) {
  return F.endsWith(r, "[]") ? r.slice(0, -2) : r;
}
function Ud(r, e, i) {
  return r
    ? r
        .concat(e)
        .map(function (l, c) {
          return (l = Hm(l)), !i && c ? "[" + l + "]" : l;
        })
        .join(i ? "." : "")
    : e;
}
function P_(r) {
  return F.isArray(r) && !r.some(Pc);
}
const A_ = F.toFlatObject(F, {}, null, function (e) {
  return /^is[A-Z]/.test(e);
});
function xa(r, e, i) {
  if (!F.isObject(r)) throw new TypeError("target must be an object");
  (e = e || new FormData()),
    (i = F.toFlatObject(
      i,
      { metaTokens: !0, dots: !1, indexes: !1 },
      !1,
      function (k, _) {
        return !F.isUndefined(_[k]);
      }
    ));
  const o = i.metaTokens,
    l = i.visitor || g,
    c = i.dots,
    f = i.indexes,
    m = (i.Blob || (typeof Blob < "u" && Blob)) && F.isSpecCompliantForm(e);
  if (!F.isFunction(l)) throw new TypeError("visitor must be a function");
  function p(E) {
    if (E === null) return "";
    if (F.isDate(E)) return E.toISOString();
    if (F.isBoolean(E)) return E.toString();
    if (!m && F.isBlob(E))
      throw new we("Blob is not supported. Use a Buffer instead.");
    return F.isArrayBuffer(E) || F.isTypedArray(E)
      ? m && typeof Blob == "function"
        ? new Blob([E])
        : Buffer.from(E)
      : E;
  }
  function g(E, k, _) {
    let A = E;
    if (E && !_ && typeof E == "object") {
      if (F.endsWith(k, "{}"))
        (k = o ? k : k.slice(0, -2)), (E = JSON.stringify(E));
      else if (
        (F.isArray(E) && P_(E)) ||
        ((F.isFileList(E) || F.endsWith(k, "[]")) && (A = F.toArray(E)))
      )
        return (
          (k = Hm(k)),
          A.forEach(function (N, U) {
            !(F.isUndefined(N) || N === null) &&
              e.append(
                f === !0 ? Ud([k], U, c) : f === null ? k : k + "[]",
                p(N)
              );
          }),
          !1
        );
    }
    return Pc(E) ? !0 : (e.append(Ud(_, k, c), p(E)), !1);
  }
  const v = [],
    x = Object.assign(A_, {
      defaultVisitor: g,
      convertValue: p,
      isVisitable: Pc,
    });
  function w(E, k) {
    if (!F.isUndefined(E)) {
      if (v.indexOf(E) !== -1)
        throw Error("Circular reference detected in " + k.join("."));
      v.push(E),
        F.forEach(E, function (A, b) {
          (!(F.isUndefined(A) || A === null) &&
            l.call(e, A, F.isString(b) ? b.trim() : b, k, x)) === !0 &&
            w(A, k ? k.concat(b) : [b]);
        }),
        v.pop();
    }
  }
  if (!F.isObject(r)) throw new TypeError("data must be an object");
  return w(r), e;
}
function jd(r) {
  const e = {
    "!": "%21",
    "'": "%27",
    "(": "%28",
    ")": "%29",
    "~": "%7E",
    "%20": "+",
    "%00": "\0",
  };
  return encodeURIComponent(r).replace(/[!'()~]|%20|%00/g, function (o) {
    return e[o];
  });
}
function Yc(r, e) {
  (this._pairs = []), r && xa(r, this, e);
}
const qm = Yc.prototype;
qm.append = function (e, i) {
  this._pairs.push([e, i]);
};
qm.toString = function (e) {
  const i = e
    ? function (o) {
        return e.call(this, o, jd);
      }
    : jd;
  return this._pairs
    .map(function (l) {
      return i(l[0]) + "=" + i(l[1]);
    }, "")
    .join("&");
};
function C_(r) {
  return encodeURIComponent(r)
    .replace(/%3A/gi, ":")
    .replace(/%24/g, "$")
    .replace(/%2C/gi, ",")
    .replace(/%20/g, "+")
    .replace(/%5B/gi, "[")
    .replace(/%5D/gi, "]");
}
function Vm(r, e, i) {
  if (!e) return r;
  const o = (i && i.encode) || C_;
  F.isFunction(i) && (i = { serialize: i });
  const l = i && i.serialize;
  let c;
  if (
    (l
      ? (c = l(e, i))
      : (c = F.isURLSearchParams(e) ? e.toString() : new Yc(e, i).toString(o)),
    c)
  ) {
    const f = r.indexOf("#");
    f !== -1 && (r = r.slice(0, f)),
      (r += (r.indexOf("?") === -1 ? "?" : "&") + c);
  }
  return r;
}
class $d {
  constructor() {
    this.handlers = [];
  }
  use(e, i, o) {
    return (
      this.handlers.push({
        fulfilled: e,
        rejected: i,
        synchronous: o ? o.synchronous : !1,
        runWhen: o ? o.runWhen : null,
      }),
      this.handlers.length - 1
    );
  }
  eject(e) {
    this.handlers[e] && (this.handlers[e] = null);
  }
  clear() {
    this.handlers && (this.handlers = []);
  }
  forEach(e) {
    F.forEach(this.handlers, function (o) {
      o !== null && e(o);
    });
  }
}
const Gm = {
    silentJSONParsing: !0,
    forcedJSONParsing: !0,
    clarifyTimeoutError: !1,
  },
  k_ = typeof URLSearchParams < "u" ? URLSearchParams : Yc,
  R_ = typeof FormData < "u" ? FormData : null,
  b_ = typeof Blob < "u" ? Blob : null,
  T_ = {
    isBrowser: !0,
    classes: { URLSearchParams: k_, FormData: R_, Blob: b_ },
    protocols: ["http", "https", "file", "blob", "url", "data"],
  },
  Qc = typeof window < "u" && typeof document < "u",
  Ac = (typeof navigator == "object" && navigator) || void 0,
  O_ =
    Qc &&
    (!Ac || ["ReactNative", "NativeScript", "NS"].indexOf(Ac.product) < 0),
  M_ =
    typeof WorkerGlobalScope < "u" &&
    self instanceof WorkerGlobalScope &&
    typeof self.importScripts == "function",
  I_ = (Qc && window.location.href) || "http://localhost",
  L_ = Object.freeze(
    Object.defineProperty(
      {
        __proto__: null,
        hasBrowserEnv: Qc,
        hasStandardBrowserEnv: O_,
        hasStandardBrowserWebWorkerEnv: M_,
        navigator: Ac,
        origin: I_,
      },
      Symbol.toStringTag,
      { value: "Module" }
    )
  ),
  vt = { ...L_, ...T_ };
function F_(r, e) {
  return xa(r, new vt.classes.URLSearchParams(), {
    visitor: function (i, o, l, c) {
      return vt.isNode && F.isBuffer(i)
        ? (this.append(o, i.toString("base64")), !1)
        : c.defaultVisitor.apply(this, arguments);
    },
    ...e,
  });
}
function N_(r) {
  return F.matchAll(/\w+|\[(\w*)]/g, r).map((e) =>
    e[0] === "[]" ? "" : e[1] || e[0]
  );
}
function D_(r) {
  const e = {},
    i = Object.keys(r);
  let o;
  const l = i.length;
  let c;
  for (o = 0; o < l; o++) (c = i[o]), (e[c] = r[c]);
  return e;
}
function Wm(r) {
  function e(i, o, l, c) {
    let f = i[c++];
    if (f === "__proto__") return !0;
    const d = Number.isFinite(+f),
      m = c >= i.length;
    return (
      (f = !f && F.isArray(l) ? l.length : f),
      m
        ? (F.hasOwnProp(l, f) ? (l[f] = [l[f], o]) : (l[f] = o), !d)
        : ((!l[f] || !F.isObject(l[f])) && (l[f] = []),
          e(i, o, l[f], c) && F.isArray(l[f]) && (l[f] = D_(l[f])),
          !d)
    );
  }
  if (F.isFormData(r) && F.isFunction(r.entries)) {
    const i = {};
    return (
      F.forEachEntry(r, (o, l) => {
        e(N_(o), l, i, 0);
      }),
      i
    );
  }
  return null;
}
function B_(r, e, i) {
  if (F.isString(r))
    try {
      return (e || JSON.parse)(r), F.trim(r);
    } catch (o) {
      if (o.name !== "SyntaxError") throw o;
    }
  return (i || JSON.stringify)(r);
}
const Ls = {
  transitional: Gm,
  adapter: ["xhr", "http", "fetch"],
  transformRequest: [
    function (e, i) {
      const o = i.getContentType() || "",
        l = o.indexOf("application/json") > -1,
        c = F.isObject(e);
      if ((c && F.isHTMLForm(e) && (e = new FormData(e)), F.isFormData(e)))
        return l ? JSON.stringify(Wm(e)) : e;
      if (
        F.isArrayBuffer(e) ||
        F.isBuffer(e) ||
        F.isStream(e) ||
        F.isFile(e) ||
        F.isBlob(e) ||
        F.isReadableStream(e)
      )
        return e;
      if (F.isArrayBufferView(e)) return e.buffer;
      if (F.isURLSearchParams(e))
        return (
          i.setContentType(
            "application/x-www-form-urlencoded;charset=utf-8",
            !1
          ),
          e.toString()
        );
      let d;
      if (c) {
        if (o.indexOf("application/x-www-form-urlencoded") > -1)
          return F_(e, this.formSerializer).toString();
        if ((d = F.isFileList(e)) || o.indexOf("multipart/form-data") > -1) {
          const m = this.env && this.env.FormData;
          return xa(
            d ? { "files[]": e } : e,
            m && new m(),
            this.formSerializer
          );
        }
      }
      return c || l ? (i.setContentType("application/json", !1), B_(e)) : e;
    },
  ],
  transformResponse: [
    function (e) {
      const i = this.transitional || Ls.transitional,
        o = i && i.forcedJSONParsing,
        l = this.responseType === "json";
      if (F.isResponse(e) || F.isReadableStream(e)) return e;
      if (e && F.isString(e) && ((o && !this.responseType) || l)) {
        const f = !(i && i.silentJSONParsing) && l;
        try {
          return JSON.parse(e);
        } catch (d) {
          if (f)
            throw d.name === "SyntaxError"
              ? we.from(d, we.ERR_BAD_RESPONSE, this, null, this.response)
              : d;
        }
      }
      return e;
    },
  ],
  timeout: 0,
  xsrfCookieName: "XSRF-TOKEN",
  xsrfHeaderName: "X-XSRF-TOKEN",
  maxContentLength: -1,
  maxBodyLength: -1,
  env: { FormData: vt.classes.FormData, Blob: vt.classes.Blob },
  validateStatus: function (e) {
    return e >= 200 && e < 300;
  },
  headers: {
    common: {
      Accept: "application/json, text/plain, */*",
      "Content-Type": void 0,
    },
  },
};
F.forEach(["delete", "get", "head", "post", "put", "patch"], (r) => {
  Ls.headers[r] = {};
});
const U_ = F.toObjectSet([
    "age",
    "authorization",
    "content-length",
    "content-type",
    "etag",
    "expires",
    "from",
    "host",
    "if-modified-since",
    "if-unmodified-since",
    "last-modified",
    "location",
    "max-forwards",
    "proxy-authorization",
    "referer",
    "retry-after",
    "user-agent",
  ]),
  j_ = (r) => {
    const e = {};
    let i, o, l;
    return (
      r &&
        r
          .split(
            `
`
          )
          .forEach(function (f) {
            (l = f.indexOf(":")),
              (i = f.substring(0, l).trim().toLowerCase()),
              (o = f.substring(l + 1).trim()),
              !(!i || (e[i] && U_[i])) &&
                (i === "set-cookie"
                  ? e[i]
                    ? e[i].push(o)
                    : (e[i] = [o])
                  : (e[i] = e[i] ? e[i] + ", " + o : o));
          }),
      e
    );
  },
  zd = Symbol("internals");
function ms(r) {
  return r && String(r).trim().toLowerCase();
}
function na(r) {
  return r === !1 || r == null ? r : F.isArray(r) ? r.map(na) : String(r);
}
function $_(r) {
  const e = Object.create(null),
    i = /([^\s,;=]+)\s*(?:=\s*([^,;]+))?/g;
  let o;
  for (; (o = i.exec(r)); ) e[o[1]] = o[2];
  return e;
}
const z_ = (r) => /^[-_a-zA-Z0-9^`|~,!#$%&'*+.]+$/.test(r.trim());
function fu(r, e, i, o, l) {
  if (F.isFunction(o)) return o.call(this, e, i);
  if ((l && (e = i), !!F.isString(e))) {
    if (F.isString(o)) return e.indexOf(o) !== -1;
    if (F.isRegExp(o)) return o.test(e);
  }
}
function H_(r) {
  return r
    .trim()
    .toLowerCase()
    .replace(/([a-z\d])(\w*)/g, (e, i, o) => i.toUpperCase() + o);
}
function q_(r, e) {
  const i = F.toCamelCase(" " + e);
  ["get", "set", "has"].forEach((o) => {
    Object.defineProperty(r, o + i, {
      value: function (l, c, f) {
        return this[o].call(this, e, l, c, f);
      },
      configurable: !0,
    });
  });
}
let Ft = class {
  constructor(e) {
    e && this.set(e);
  }
  set(e, i, o) {
    const l = this;
    function c(d, m, p) {
      const g = ms(m);
      if (!g) throw new Error("header name must be a non-empty string");
      const v = F.findKey(l, g);
      (!v || l[v] === void 0 || p === !0 || (p === void 0 && l[v] !== !1)) &&
        (l[v || m] = na(d));
    }
    const f = (d, m) => F.forEach(d, (p, g) => c(p, g, m));
    if (F.isPlainObject(e) || e instanceof this.constructor) f(e, i);
    else if (F.isString(e) && (e = e.trim()) && !z_(e)) f(j_(e), i);
    else if (F.isObject(e) && F.isIterable(e)) {
      let d = {},
        m,
        p;
      for (const g of e) {
        if (!F.isArray(g))
          throw TypeError("Object iterator must return a key-value pair");
        d[(p = g[0])] = (m = d[p])
          ? F.isArray(m)
            ? [...m, g[1]]
            : [m, g[1]]
          : g[1];
      }
      f(d, i);
    } else e != null && c(i, e, o);
    return this;
  }
  get(e, i) {
    if (((e = ms(e)), e)) {
      const o = F.findKey(this, e);
      if (o) {
        const l = this[o];
        if (!i) return l;
        if (i === !0) return $_(l);
        if (F.isFunction(i)) return i.call(this, l, o);
        if (F.isRegExp(i)) return i.exec(l);
        throw new TypeError("parser must be boolean|regexp|function");
      }
    }
  }
  has(e, i) {
    if (((e = ms(e)), e)) {
      const o = F.findKey(this, e);
      return !!(o && this[o] !== void 0 && (!i || fu(this, this[o], o, i)));
    }
    return !1;
  }
  delete(e, i) {
    const o = this;
    let l = !1;
    function c(f) {
      if (((f = ms(f)), f)) {
        const d = F.findKey(o, f);
        d && (!i || fu(o, o[d], d, i)) && (delete o[d], (l = !0));
      }
    }
    return F.isArray(e) ? e.forEach(c) : c(e), l;
  }
  clear(e) {
    const i = Object.keys(this);
    let o = i.length,
      l = !1;
    for (; o--; ) {
      const c = i[o];
      (!e || fu(this, this[c], c, e, !0)) && (delete this[c], (l = !0));
    }
    return l;
  }
  normalize(e) {
    const i = this,
      o = {};
    return (
      F.forEach(this, (l, c) => {
        const f = F.findKey(o, c);
        if (f) {
          (i[f] = na(l)), delete i[c];
          return;
        }
        const d = e ? H_(c) : String(c).trim();
        d !== c && delete i[c], (i[d] = na(l)), (o[d] = !0);
      }),
      this
    );
  }
  concat(...e) {
    return this.constructor.concat(this, ...e);
  }
  toJSON(e) {
    const i = Object.create(null);
    return (
      F.forEach(this, (o, l) => {
        o != null && o !== !1 && (i[l] = e && F.isArray(o) ? o.join(", ") : o);
      }),
      i
    );
  }
  [Symbol.iterator]() {
    return Object.entries(this.toJSON())[Symbol.iterator]();
  }
  toString() {
    return Object.entries(this.toJSON()).map(([e, i]) => e + ": " + i).join(`
`);
  }
  getSetCookie() {
    return this.get("set-cookie") || [];
  }
  get [Symbol.toStringTag]() {
    return "AxiosHeaders";
  }
  static from(e) {
    return e instanceof this ? e : new this(e);
  }
  static concat(e, ...i) {
    const o = new this(e);
    return i.forEach((l) => o.set(l)), o;
  }
  static accessor(e) {
    const o = (this[zd] = this[zd] = { accessors: {} }).accessors,
      l = this.prototype;
    function c(f) {
      const d = ms(f);
      o[d] || (q_(l, f), (o[d] = !0));
    }
    return F.isArray(e) ? e.forEach(c) : c(e), this;
  }
};
Ft.accessor([
  "Content-Type",
  "Content-Length",
  "Accept",
  "Accept-Encoding",
  "User-Agent",
  "Authorization",
]);
F.reduceDescriptors(Ft.prototype, ({ value: r }, e) => {
  let i = e[0].toUpperCase() + e.slice(1);
  return {
    get: () => r,
    set(o) {
      this[i] = o;
    },
  };
});
F.freezeMethods(Ft);
function hu(r, e) {
  const i = this || Ls,
    o = e || i,
    l = Ft.from(o.headers);
  let c = o.data;
  return (
    F.forEach(r, function (d) {
      c = d.call(i, c, l.normalize(), e ? e.status : void 0);
    }),
    l.normalize(),
    c
  );
}
function Xm(r) {
  return !!(r && r.__CANCEL__);
}
function ki(r, e, i) {
  we.call(this, r ?? "canceled", we.ERR_CANCELED, e, i),
    (this.name = "CanceledError");
}
F.inherits(ki, we, { __CANCEL__: !0 });
function Ym(r, e, i) {
  const o = i.config.validateStatus;
  !i.status || !o || o(i.status)
    ? r(i)
    : e(
        new we(
          "Request failed with status code " + i.status,
          [we.ERR_BAD_REQUEST, we.ERR_BAD_RESPONSE][
            Math.floor(i.status / 100) - 4
          ],
          i.config,
          i.request,
          i
        )
      );
}
function V_(r) {
  const e = /^([-+\w]{1,25})(:?\/\/|:)/.exec(r);
  return (e && e[1]) || "";
}
function G_(r, e) {
  r = r || 10;
  const i = new Array(r),
    o = new Array(r);
  let l = 0,
    c = 0,
    f;
  return (
    (e = e !== void 0 ? e : 1e3),
    function (m) {
      const p = Date.now(),
        g = o[c];
      f || (f = p), (i[l] = m), (o[l] = p);
      let v = c,
        x = 0;
      for (; v !== l; ) (x += i[v++]), (v = v % r);
      if (((l = (l + 1) % r), l === c && (c = (c + 1) % r), p - f < e)) return;
      const w = g && p - g;
      return w ? Math.round((x * 1e3) / w) : void 0;
    }
  );
}
function W_(r, e) {
  let i = 0,
    o = 1e3 / e,
    l,
    c;
  const f = (p, g = Date.now()) => {
    (i = g), (l = null), c && (clearTimeout(c), (c = null)), r(...p);
  };
  return [
    (...p) => {
      const g = Date.now(),
        v = g - i;
      v >= o
        ? f(p, g)
        : ((l = p),
          c ||
            (c = setTimeout(() => {
              (c = null), f(l);
            }, o - v)));
    },
    () => l && f(l),
  ];
}
const ua = (r, e, i = 3) => {
    let o = 0;
    const l = G_(50, 250);
    return W_((c) => {
      const f = c.loaded,
        d = c.lengthComputable ? c.total : void 0,
        m = f - o,
        p = l(m),
        g = f <= d;
      o = f;
      const v = {
        loaded: f,
        total: d,
        progress: d ? f / d : void 0,
        bytes: m,
        rate: p || void 0,
        estimated: p && d && g ? (d - f) / p : void 0,
        event: c,
        lengthComputable: d != null,
        [e ? "download" : "upload"]: !0,
      };
      r(v);
    }, i);
  },
  Hd = (r, e) => {
    const i = r != null;
    return [(o) => e[0]({ lengthComputable: i, total: r, loaded: o }), e[1]];
  },
  qd =
    (r) =>
    (...e) =>
      F.asap(() => r(...e)),
  X_ = vt.hasStandardBrowserEnv
    ? ((r, e) => (i) => (
        (i = new URL(i, vt.origin)),
        r.protocol === i.protocol &&
          r.host === i.host &&
          (e || r.port === i.port)
      ))(
        new URL(vt.origin),
        vt.navigator && /(msie|trident)/i.test(vt.navigator.userAgent)
      )
    : () => !0,
  Y_ = vt.hasStandardBrowserEnv
    ? {
        write(r, e, i, o, l, c) {
          const f = [r + "=" + encodeURIComponent(e)];
          F.isNumber(i) && f.push("expires=" + new Date(i).toGMTString()),
            F.isString(o) && f.push("path=" + o),
            F.isString(l) && f.push("domain=" + l),
            c === !0 && f.push("secure"),
            (document.cookie = f.join("; "));
        },
        read(r) {
          const e = document.cookie.match(
            new RegExp("(^|;\\s*)(" + r + ")=([^;]*)")
          );
          return e ? decodeURIComponent(e[3]) : null;
        },
        remove(r) {
          this.write(r, "", Date.now() - 864e5);
        },
      }
    : {
        write() {},
        read() {
          return null;
        },
        remove() {},
      };
function Q_(r) {
  return /^([a-z][a-z\d+\-.]*:)?\/\//i.test(r);
}
function K_(r, e) {
  return e ? r.replace(/\/?\/$/, "") + "/" + e.replace(/^\/+/, "") : r;
}
function Qm(r, e, i) {
  let o = !Q_(e);
  return r && (o || i == !1) ? K_(r, e) : e;
}
const Vd = (r) => (r instanceof Ft ? { ...r } : r);
function Hn(r, e) {
  e = e || {};
  const i = {};
  function o(p, g, v, x) {
    return F.isPlainObject(p) && F.isPlainObject(g)
      ? F.merge.call({ caseless: x }, p, g)
      : F.isPlainObject(g)
      ? F.merge({}, g)
      : F.isArray(g)
      ? g.slice()
      : g;
  }
  function l(p, g, v, x) {
    if (F.isUndefined(g)) {
      if (!F.isUndefined(p)) return o(void 0, p, v, x);
    } else return o(p, g, v, x);
  }
  function c(p, g) {
    if (!F.isUndefined(g)) return o(void 0, g);
  }
  function f(p, g) {
    if (F.isUndefined(g)) {
      if (!F.isUndefined(p)) return o(void 0, p);
    } else return o(void 0, g);
  }
  function d(p, g, v) {
    if (v in e) return o(p, g);
    if (v in r) return o(void 0, p);
  }
  const m = {
    url: c,
    method: c,
    data: c,
    baseURL: f,
    transformRequest: f,
    transformResponse: f,
    paramsSerializer: f,
    timeout: f,
    timeoutMessage: f,
    withCredentials: f,
    withXSRFToken: f,
    adapter: f,
    responseType: f,
    xsrfCookieName: f,
    xsrfHeaderName: f,
    onUploadProgress: f,
    onDownloadProgress: f,
    decompress: f,
    maxContentLength: f,
    maxBodyLength: f,
    beforeRedirect: f,
    transport: f,
    httpAgent: f,
    httpsAgent: f,
    cancelToken: f,
    socketPath: f,
    responseEncoding: f,
    validateStatus: d,
    headers: (p, g, v) => l(Vd(p), Vd(g), v, !0),
  };
  return (
    F.forEach(Object.keys({ ...r, ...e }), function (g) {
      const v = m[g] || l,
        x = v(r[g], e[g], g);
      (F.isUndefined(x) && v !== d) || (i[g] = x);
    }),
    i
  );
}
const Km = (r) => {
    const e = Hn({}, r);
    let {
      data: i,
      withXSRFToken: o,
      xsrfHeaderName: l,
      xsrfCookieName: c,
      headers: f,
      auth: d,
    } = e;
    (e.headers = f = Ft.from(f)),
      (e.url = Vm(
        Qm(e.baseURL, e.url, e.allowAbsoluteUrls),
        r.params,
        r.paramsSerializer
      )),
      d &&
        f.set(
          "Authorization",
          "Basic " +
            btoa(
              (d.username || "") +
                ":" +
                (d.password ? unescape(encodeURIComponent(d.password)) : "")
            )
        );
    let m;
    if (F.isFormData(i)) {
      if (vt.hasStandardBrowserEnv || vt.hasStandardBrowserWebWorkerEnv)
        f.setContentType(void 0);
      else if ((m = f.getContentType()) !== !1) {
        const [p, ...g] = m
          ? m
              .split(";")
              .map((v) => v.trim())
              .filter(Boolean)
          : [];
        f.setContentType([p || "multipart/form-data", ...g].join("; "));
      }
    }
    if (
      vt.hasStandardBrowserEnv &&
      (o && F.isFunction(o) && (o = o(e)), o || (o !== !1 && X_(e.url)))
    ) {
      const p = l && c && Y_.read(c);
      p && f.set(l, p);
    }
    return e;
  },
  J_ = typeof XMLHttpRequest < "u",
  Z_ =
    J_ &&
    function (r) {
      return new Promise(function (i, o) {
        const l = Km(r);
        let c = l.data;
        const f = Ft.from(l.headers).normalize();
        let { responseType: d, onUploadProgress: m, onDownloadProgress: p } = l,
          g,
          v,
          x,
          w,
          E;
        function k() {
          w && w(),
            E && E(),
            l.cancelToken && l.cancelToken.unsubscribe(g),
            l.signal && l.signal.removeEventListener("abort", g);
        }
        let _ = new XMLHttpRequest();
        _.open(l.method.toUpperCase(), l.url, !0), (_.timeout = l.timeout);
        function A() {
          if (!_) return;
          const N = Ft.from(
              "getAllResponseHeaders" in _ && _.getAllResponseHeaders()
            ),
            z = {
              data:
                !d || d === "text" || d === "json"
                  ? _.responseText
                  : _.response,
              status: _.status,
              statusText: _.statusText,
              headers: N,
              config: r,
              request: _,
            };
          Ym(
            function (G) {
              i(G), k();
            },
            function (G) {
              o(G), k();
            },
            z
          ),
            (_ = null);
        }
        "onloadend" in _
          ? (_.onloadend = A)
          : (_.onreadystatechange = function () {
              !_ ||
                _.readyState !== 4 ||
                (_.status === 0 &&
                  !(_.responseURL && _.responseURL.indexOf("file:") === 0)) ||
                setTimeout(A);
            }),
          (_.onabort = function () {
            _ &&
              (o(new we("Request aborted", we.ECONNABORTED, r, _)), (_ = null));
          }),
          (_.onerror = function () {
            o(new we("Network Error", we.ERR_NETWORK, r, _)), (_ = null);
          }),
          (_.ontimeout = function () {
            let U = l.timeout
              ? "timeout of " + l.timeout + "ms exceeded"
              : "timeout exceeded";
            const z = l.transitional || Gm;
            l.timeoutErrorMessage && (U = l.timeoutErrorMessage),
              o(
                new we(
                  U,
                  z.clarifyTimeoutError ? we.ETIMEDOUT : we.ECONNABORTED,
                  r,
                  _
                )
              ),
              (_ = null);
          }),
          c === void 0 && f.setContentType(null),
          "setRequestHeader" in _ &&
            F.forEach(f.toJSON(), function (U, z) {
              _.setRequestHeader(z, U);
            }),
          F.isUndefined(l.withCredentials) ||
            (_.withCredentials = !!l.withCredentials),
          d && d !== "json" && (_.responseType = l.responseType),
          p && (([x, E] = ua(p, !0)), _.addEventListener("progress", x)),
          m &&
            _.upload &&
            (([v, w] = ua(m)),
            _.upload.addEventListener("progress", v),
            _.upload.addEventListener("loadend", w)),
          (l.cancelToken || l.signal) &&
            ((g = (N) => {
              _ &&
                (o(!N || N.type ? new ki(null, r, _) : N),
                _.abort(),
                (_ = null));
            }),
            l.cancelToken && l.cancelToken.subscribe(g),
            l.signal &&
              (l.signal.aborted ? g() : l.signal.addEventListener("abort", g)));
        const b = V_(l.url);
        if (b && vt.protocols.indexOf(b) === -1) {
          o(new we("Unsupported protocol " + b + ":", we.ERR_BAD_REQUEST, r));
          return;
        }
        _.send(c || null);
      });
    },
  ew = (r, e) => {
    const { length: i } = (r = r ? r.filter(Boolean) : []);
    if (e || i) {
      let o = new AbortController(),
        l;
      const c = function (p) {
        if (!l) {
          (l = !0), d();
          const g = p instanceof Error ? p : this.reason;
          o.abort(
            g instanceof we ? g : new ki(g instanceof Error ? g.message : g)
          );
        }
      };
      let f =
        e &&
        setTimeout(() => {
          (f = null), c(new we(`timeout ${e} of ms exceeded`, we.ETIMEDOUT));
        }, e);
      const d = () => {
        r &&
          (f && clearTimeout(f),
          (f = null),
          r.forEach((p) => {
            p.unsubscribe
              ? p.unsubscribe(c)
              : p.removeEventListener("abort", c);
          }),
          (r = null));
      };
      r.forEach((p) => p.addEventListener("abort", c));
      const { signal: m } = o;
      return (m.unsubscribe = () => F.asap(d)), m;
    }
  },
  tw = function* (r, e) {
    let i = r.byteLength;
    if (i < e) {
      yield r;
      return;
    }
    let o = 0,
      l;
    for (; o < i; ) (l = o + e), yield r.slice(o, l), (o = l);
  },
  rw = async function* (r, e) {
    for await (const i of nw(r)) yield* tw(i, e);
  },
  nw = async function* (r) {
    if (r[Symbol.asyncIterator]) {
      yield* r;
      return;
    }
    const e = r.getReader();
    try {
      for (;;) {
        const { done: i, value: o } = await e.read();
        if (i) break;
        yield o;
      }
    } finally {
      await e.cancel();
    }
  },
  Gd = (r, e, i, o) => {
    const l = rw(r, e);
    let c = 0,
      f,
      d = (m) => {
        f || ((f = !0), o && o(m));
      };
    return new ReadableStream(
      {
        async pull(m) {
          try {
            const { done: p, value: g } = await l.next();
            if (p) {
              d(), m.close();
              return;
            }
            let v = g.byteLength;
            if (i) {
              let x = (c += v);
              i(x);
            }
            m.enqueue(new Uint8Array(g));
          } catch (p) {
            throw (d(p), p);
          }
        },
        cancel(m) {
          return d(m), l.return();
        },
      },
      { highWaterMark: 2 }
    );
  },
  Sa =
    typeof fetch == "function" &&
    typeof Request == "function" &&
    typeof Response == "function",
  Jm = Sa && typeof ReadableStream == "function",
  iw =
    Sa &&
    (typeof TextEncoder == "function"
      ? (
          (r) => (e) =>
            r.encode(e)
        )(new TextEncoder())
      : async (r) => new Uint8Array(await new Response(r).arrayBuffer())),
  Zm = (r, ...e) => {
    try {
      return !!r(...e);
    } catch {
      return !1;
    }
  },
  sw =
    Jm &&
    Zm(() => {
      let r = !1;
      const e = new Request(vt.origin, {
        body: new ReadableStream(),
        method: "POST",
        get duplex() {
          return (r = !0), "half";
        },
      }).headers.has("Content-Type");
      return r && !e;
    }),
  Wd = 64 * 1024,
  Cc = Jm && Zm(() => F.isReadableStream(new Response("").body)),
  ca = { stream: Cc && ((r) => r.body) };
Sa &&
  ((r) => {
    ["text", "arrayBuffer", "blob", "formData", "stream"].forEach((e) => {
      !ca[e] &&
        (ca[e] = F.isFunction(r[e])
          ? (i) => i[e]()
          : (i, o) => {
              throw new we(
                `Response type '${e}' is not supported`,
                we.ERR_NOT_SUPPORT,
                o
              );
            });
    });
  })(new Response());
const ow = async (r) => {
    if (r == null) return 0;
    if (F.isBlob(r)) return r.size;
    if (F.isSpecCompliantForm(r))
      return (
        await new Request(vt.origin, { method: "POST", body: r }).arrayBuffer()
      ).byteLength;
    if (F.isArrayBufferView(r) || F.isArrayBuffer(r)) return r.byteLength;
    if ((F.isURLSearchParams(r) && (r = r + ""), F.isString(r)))
      return (await iw(r)).byteLength;
  },
  aw = async (r, e) => {
    const i = F.toFiniteNumber(r.getContentLength());
    return i ?? ow(e);
  },
  lw =
    Sa &&
    (async (r) => {
      let {
        url: e,
        method: i,
        data: o,
        signal: l,
        cancelToken: c,
        timeout: f,
        onDownloadProgress: d,
        onUploadProgress: m,
        responseType: p,
        headers: g,
        withCredentials: v = "same-origin",
        fetchOptions: x,
      } = Km(r);
      p = p ? (p + "").toLowerCase() : "text";
      let w = ew([l, c && c.toAbortSignal()], f),
        E;
      const k =
        w &&
        w.unsubscribe &&
        (() => {
          w.unsubscribe();
        });
      let _;
      try {
        if (
          m &&
          sw &&
          i !== "get" &&
          i !== "head" &&
          (_ = await aw(g, o)) !== 0
        ) {
          let z = new Request(e, { method: "POST", body: o, duplex: "half" }),
            H;
          if (
            (F.isFormData(o) &&
              (H = z.headers.get("content-type")) &&
              g.setContentType(H),
            z.body)
          ) {
            const [G, Q] = Hd(_, ua(qd(m)));
            o = Gd(z.body, Wd, G, Q);
          }
        }
        F.isString(v) || (v = v ? "include" : "omit");
        const A = "credentials" in Request.prototype;
        E = new Request(e, {
          ...x,
          signal: w,
          method: i.toUpperCase(),
          headers: g.normalize().toJSON(),
          body: o,
          duplex: "half",
          credentials: A ? v : void 0,
        });
        let b = await fetch(E, x);
        const N = Cc && (p === "stream" || p === "response");
        if (Cc && (d || (N && k))) {
          const z = {};
          ["status", "statusText", "headers"].forEach((me) => {
            z[me] = b[me];
          });
          const H = F.toFiniteNumber(b.headers.get("content-length")),
            [G, Q] = (d && Hd(H, ua(qd(d), !0))) || [];
          b = new Response(
            Gd(b.body, Wd, G, () => {
              Q && Q(), k && k();
            }),
            z
          );
        }
        p = p || "text";
        let U = await ca[F.findKey(ca, p) || "text"](b, r);
        return (
          !N && k && k(),
          await new Promise((z, H) => {
            Ym(z, H, {
              data: U,
              headers: Ft.from(b.headers),
              status: b.status,
              statusText: b.statusText,
              config: r,
              request: E,
            });
          })
        );
      } catch (A) {
        throw (
          (k && k(),
          A && A.name === "TypeError" && /Load failed|fetch/i.test(A.message)
            ? Object.assign(new we("Network Error", we.ERR_NETWORK, r, E), {
                cause: A.cause || A,
              })
            : we.from(A, A && A.code, r, E))
        );
      }
    }),
  kc = { http: E_, xhr: Z_, fetch: lw };
F.forEach(kc, (r, e) => {
  if (r) {
    try {
      Object.defineProperty(r, "name", { value: e });
    } catch {}
    Object.defineProperty(r, "adapterName", { value: e });
  }
});
const Xd = (r) => `- ${r}`,
  uw = (r) => F.isFunction(r) || r === null || r === !1,
  ey = {
    getAdapter: (r) => {
      r = F.isArray(r) ? r : [r];
      const { length: e } = r;
      let i, o;
      const l = {};
      for (let c = 0; c < e; c++) {
        i = r[c];
        let f;
        if (
          ((o = i),
          !uw(i) && ((o = kc[(f = String(i)).toLowerCase()]), o === void 0))
        )
          throw new we(`Unknown adapter '${f}'`);
        if (o) break;
        l[f || "#" + c] = o;
      }
      if (!o) {
        const c = Object.entries(l).map(
          ([d, m]) =>
            `adapter ${d} ` +
            (m === !1
              ? "is not supported by the environment"
              : "is not available in the build")
        );
        let f = e
          ? c.length > 1
            ? `since :
` +
              c.map(Xd).join(`
`)
            : " " + Xd(c[0])
          : "as no adapter specified";
        throw new we(
          "There is no suitable adapter to dispatch the request " + f,
          "ERR_NOT_SUPPORT"
        );
      }
      return o;
    },
    adapters: kc,
  };
function du(r) {
  if (
    (r.cancelToken && r.cancelToken.throwIfRequested(),
    r.signal && r.signal.aborted)
  )
    throw new ki(null, r);
}
function Yd(r) {
  return (
    du(r),
    (r.headers = Ft.from(r.headers)),
    (r.data = hu.call(r, r.transformRequest)),
    ["post", "put", "patch"].indexOf(r.method) !== -1 &&
      r.headers.setContentType("application/x-www-form-urlencoded", !1),
    ey
      .getAdapter(r.adapter || Ls.adapter)(r)
      .then(
        function (o) {
          return (
            du(r),
            (o.data = hu.call(r, r.transformResponse, o)),
            (o.headers = Ft.from(o.headers)),
            o
          );
        },
        function (o) {
          return (
            Xm(o) ||
              (du(r),
              o &&
                o.response &&
                ((o.response.data = hu.call(
                  r,
                  r.transformResponse,
                  o.response
                )),
                (o.response.headers = Ft.from(o.response.headers)))),
            Promise.reject(o)
          );
        }
      )
  );
}
const ty = "1.11.0",
  Ea = {};
["object", "boolean", "number", "function", "string", "symbol"].forEach(
  (r, e) => {
    Ea[r] = function (o) {
      return typeof o === r || "a" + (e < 1 ? "n " : " ") + r;
    };
  }
);
const Qd = {};
Ea.transitional = function (e, i, o) {
  function l(c, f) {
    return (
      "[Axios v" +
      ty +
      "] Transitional option '" +
      c +
      "'" +
      f +
      (o ? ". " + o : "")
    );
  }
  return (c, f, d) => {
    if (e === !1)
      throw new we(
        l(f, " has been removed" + (i ? " in " + i : "")),
        we.ERR_DEPRECATED
      );
    return (
      i &&
        !Qd[f] &&
        ((Qd[f] = !0),
        console.warn(
          l(
            f,
            " has been deprecated since v" +
              i +
              " and will be removed in the near future"
          )
        )),
      e ? e(c, f, d) : !0
    );
  };
};
Ea.spelling = function (e) {
  return (i, o) => (console.warn(`${o} is likely a misspelling of ${e}`), !0);
};
function cw(r, e, i) {
  if (typeof r != "object")
    throw new we("options must be an object", we.ERR_BAD_OPTION_VALUE);
  const o = Object.keys(r);
  let l = o.length;
  for (; l-- > 0; ) {
    const c = o[l],
      f = e[c];
    if (f) {
      const d = r[c],
        m = d === void 0 || f(d, c, r);
      if (m !== !0)
        throw new we("option " + c + " must be " + m, we.ERR_BAD_OPTION_VALUE);
      continue;
    }
    if (i !== !0) throw new we("Unknown option " + c, we.ERR_BAD_OPTION);
  }
}
const ia = { assertOptions: cw, validators: Ea },
  xr = ia.validators;
let zn = class {
  constructor(e) {
    (this.defaults = e || {}),
      (this.interceptors = { request: new $d(), response: new $d() });
  }
  async request(e, i) {
    try {
      return await this._request(e, i);
    } catch (o) {
      if (o instanceof Error) {
        let l = {};
        Error.captureStackTrace
          ? Error.captureStackTrace(l)
          : (l = new Error());
        const c = l.stack ? l.stack.replace(/^.+\n/, "") : "";
        try {
          o.stack
            ? c &&
              !String(o.stack).endsWith(c.replace(/^.+\n.+\n/, "")) &&
              (o.stack +=
                `
` + c)
            : (o.stack = c);
        } catch {}
      }
      throw o;
    }
  }
  _request(e, i) {
    typeof e == "string" ? ((i = i || {}), (i.url = e)) : (i = e || {}),
      (i = Hn(this.defaults, i));
    const { transitional: o, paramsSerializer: l, headers: c } = i;
    o !== void 0 &&
      ia.assertOptions(
        o,
        {
          silentJSONParsing: xr.transitional(xr.boolean),
          forcedJSONParsing: xr.transitional(xr.boolean),
          clarifyTimeoutError: xr.transitional(xr.boolean),
        },
        !1
      ),
      l != null &&
        (F.isFunction(l)
          ? (i.paramsSerializer = { serialize: l })
          : ia.assertOptions(
              l,
              { encode: xr.function, serialize: xr.function },
              !0
            )),
      i.allowAbsoluteUrls !== void 0 ||
        (this.defaults.allowAbsoluteUrls !== void 0
          ? (i.allowAbsoluteUrls = this.defaults.allowAbsoluteUrls)
          : (i.allowAbsoluteUrls = !0)),
      ia.assertOptions(
        i,
        {
          baseUrl: xr.spelling("baseURL"),
          withXsrfToken: xr.spelling("withXSRFToken"),
        },
        !0
      ),
      (i.method = (i.method || this.defaults.method || "get").toLowerCase());
    let f = c && F.merge(c.common, c[i.method]);
    c &&
      F.forEach(
        ["delete", "get", "head", "post", "put", "patch", "common"],
        (E) => {
          delete c[E];
        }
      ),
      (i.headers = Ft.concat(f, c));
    const d = [];
    let m = !0;
    this.interceptors.request.forEach(function (k) {
      (typeof k.runWhen == "function" && k.runWhen(i) === !1) ||
        ((m = m && k.synchronous), d.unshift(k.fulfilled, k.rejected));
    });
    const p = [];
    this.interceptors.response.forEach(function (k) {
      p.push(k.fulfilled, k.rejected);
    });
    let g,
      v = 0,
      x;
    if (!m) {
      const E = [Yd.bind(this), void 0];
      for (
        E.unshift(...d), E.push(...p), x = E.length, g = Promise.resolve(i);
        v < x;

      )
        g = g.then(E[v++], E[v++]);
      return g;
    }
    x = d.length;
    let w = i;
    for (v = 0; v < x; ) {
      const E = d[v++],
        k = d[v++];
      try {
        w = E(w);
      } catch (_) {
        k.call(this, _);
        break;
      }
    }
    try {
      g = Yd.call(this, w);
    } catch (E) {
      return Promise.reject(E);
    }
    for (v = 0, x = p.length; v < x; ) g = g.then(p[v++], p[v++]);
    return g;
  }
  getUri(e) {
    e = Hn(this.defaults, e);
    const i = Qm(e.baseURL, e.url, e.allowAbsoluteUrls);
    return Vm(i, e.params, e.paramsSerializer);
  }
};
F.forEach(["delete", "get", "head", "options"], function (e) {
  zn.prototype[e] = function (i, o) {
    return this.request(
      Hn(o || {}, { method: e, url: i, data: (o || {}).data })
    );
  };
});
F.forEach(["post", "put", "patch"], function (e) {
  function i(o) {
    return function (c, f, d) {
      return this.request(
        Hn(d || {}, {
          method: e,
          headers: o ? { "Content-Type": "multipart/form-data" } : {},
          url: c,
          data: f,
        })
      );
    };
  }
  (zn.prototype[e] = i()), (zn.prototype[e + "Form"] = i(!0));
});
let fw = class ry {
  constructor(e) {
    if (typeof e != "function")
      throw new TypeError("executor must be a function.");
    let i;
    this.promise = new Promise(function (c) {
      i = c;
    });
    const o = this;
    this.promise.then((l) => {
      if (!o._listeners) return;
      let c = o._listeners.length;
      for (; c-- > 0; ) o._listeners[c](l);
      o._listeners = null;
    }),
      (this.promise.then = (l) => {
        let c;
        const f = new Promise((d) => {
          o.subscribe(d), (c = d);
        }).then(l);
        return (
          (f.cancel = function () {
            o.unsubscribe(c);
          }),
          f
        );
      }),
      e(function (c, f, d) {
        o.reason || ((o.reason = new ki(c, f, d)), i(o.reason));
      });
  }
  throwIfRequested() {
    if (this.reason) throw this.reason;
  }
  subscribe(e) {
    if (this.reason) {
      e(this.reason);
      return;
    }
    this._listeners ? this._listeners.push(e) : (this._listeners = [e]);
  }
  unsubscribe(e) {
    if (!this._listeners) return;
    const i = this._listeners.indexOf(e);
    i !== -1 && this._listeners.splice(i, 1);
  }
  toAbortSignal() {
    const e = new AbortController(),
      i = (o) => {
        e.abort(o);
      };
    return (
      this.subscribe(i),
      (e.signal.unsubscribe = () => this.unsubscribe(i)),
      e.signal
    );
  }
  static source() {
    let e;
    return {
      token: new ry(function (l) {
        e = l;
      }),
      cancel: e,
    };
  }
};
function hw(r) {
  return function (i) {
    return r.apply(null, i);
  };
}
function dw(r) {
  return F.isObject(r) && r.isAxiosError === !0;
}
const Rc = {
  Continue: 100,
  SwitchingProtocols: 101,
  Processing: 102,
  EarlyHints: 103,
  Ok: 200,
  Created: 201,
  Accepted: 202,
  NonAuthoritativeInformation: 203,
  NoContent: 204,
  ResetContent: 205,
  PartialContent: 206,
  MultiStatus: 207,
  AlreadyReported: 208,
  ImUsed: 226,
  MultipleChoices: 300,
  MovedPermanently: 301,
  Found: 302,
  SeeOther: 303,
  NotModified: 304,
  UseProxy: 305,
  Unused: 306,
  TemporaryRedirect: 307,
  PermanentRedirect: 308,
  BadRequest: 400,
  Unauthorized: 401,
  PaymentRequired: 402,
  Forbidden: 403,
  NotFound: 404,
  MethodNotAllowed: 405,
  NotAcceptable: 406,
  ProxyAuthenticationRequired: 407,
  RequestTimeout: 408,
  Conflict: 409,
  Gone: 410,
  LengthRequired: 411,
  PreconditionFailed: 412,
  PayloadTooLarge: 413,
  UriTooLong: 414,
  UnsupportedMediaType: 415,
  RangeNotSatisfiable: 416,
  ExpectationFailed: 417,
  ImATeapot: 418,
  MisdirectedRequest: 421,
  UnprocessableEntity: 422,
  Locked: 423,
  FailedDependency: 424,
  TooEarly: 425,
  UpgradeRequired: 426,
  PreconditionRequired: 428,
  TooManyRequests: 429,
  RequestHeaderFieldsTooLarge: 431,
  UnavailableForLegalReasons: 451,
  InternalServerError: 500,
  NotImplemented: 501,
  BadGateway: 502,
  ServiceUnavailable: 503,
  GatewayTimeout: 504,
  HttpVersionNotSupported: 505,
  VariantAlsoNegotiates: 506,
  InsufficientStorage: 507,
  LoopDetected: 508,
  NotExtended: 510,
  NetworkAuthenticationRequired: 511,
};
Object.entries(Rc).forEach(([r, e]) => {
  Rc[e] = r;
});
function ny(r) {
  const e = new zn(r),
    i = Im(zn.prototype.request, e);
  return (
    F.extend(i, zn.prototype, e, { allOwnKeys: !0 }),
    F.extend(i, e, null, { allOwnKeys: !0 }),
    (i.create = function (l) {
      return ny(Hn(r, l));
    }),
    i
  );
}
const $e = ny(Ls);
$e.Axios = zn;
$e.CanceledError = ki;
$e.CancelToken = fw;
$e.isCancel = Xm;
$e.VERSION = ty;
$e.toFormData = xa;
$e.AxiosError = we;
$e.Cancel = $e.CanceledError;
$e.all = function (e) {
  return Promise.all(e);
};
$e.spread = hw;
$e.isAxiosError = dw;
$e.mergeConfig = Hn;
$e.AxiosHeaders = Ft;
$e.formToJSON = (r) => Wm(F.isHTMLForm(r) ? new FormData(r) : r);
$e.getAdapter = ey.getAdapter;
$e.HttpStatusCode = Rc;
$e.default = $e;
const {
  Axios: VS,
  AxiosError: GS,
  CanceledError: WS,
  isCancel: XS,
  CancelToken: YS,
  VERSION: QS,
  all: KS,
  Cancel: JS,
  isAxiosError: ZS,
  spread: eE,
  toFormData: tE,
  AxiosHeaders: rE,
  HttpStatusCode: nE,
  formToJSON: iE,
  getAdapter: sE,
  mergeConfig: oE,
} = $e;
$e.interceptors.request.use(
  (r) => {
    const e = ["local.private:8000", "127.0.0.1:8000"];
    return (
      (typeof r.url == "string" && e.some((i) => r.url.includes(i))) ||
        (typeof r.baseURL == "string" &&
          e.some((i) => r.baseURL.includes(i))) ||
        (typeof r.url == "string" &&
          (r.url = r.url.replace(/http:\/+/gi, "https://")),
        typeof r.baseURL == "string" &&
          (r.baseURL = r.baseURL.replace(/http:\/+/gi, "https://"))),
      r
    );
  },
  (r) => Promise.reject(r)
);
var pu, Kd;
function Ri() {
  return Kd || ((Kd = 1), (pu = TypeError)), pu;
}
const pw = {},
  mw = Object.freeze(
    Object.defineProperty(
      { __proto__: null, default: pw },
      Symbol.toStringTag,
      { value: "Module" }
    )
  ),
  yw = I0(mw);
var mu, Jd;
function Pa() {
  if (Jd) return mu;
  Jd = 1;
  var r = typeof Map == "function" && Map.prototype,
    e =
      Object.getOwnPropertyDescriptor && r
        ? Object.getOwnPropertyDescriptor(Map.prototype, "size")
        : null,
    i = r && e && typeof e.get == "function" ? e.get : null,
    o = r && Map.prototype.forEach,
    l = typeof Set == "function" && Set.prototype,
    c =
      Object.getOwnPropertyDescriptor && l
        ? Object.getOwnPropertyDescriptor(Set.prototype, "size")
        : null,
    f = l && c && typeof c.get == "function" ? c.get : null,
    d = l && Set.prototype.forEach,
    m = typeof WeakMap == "function" && WeakMap.prototype,
    p = m ? WeakMap.prototype.has : null,
    g = typeof WeakSet == "function" && WeakSet.prototype,
    v = g ? WeakSet.prototype.has : null,
    x = typeof WeakRef == "function" && WeakRef.prototype,
    w = x ? WeakRef.prototype.deref : null,
    E = Boolean.prototype.valueOf,
    k = Object.prototype.toString,
    _ = Function.prototype.toString,
    A = String.prototype.match,
    b = String.prototype.slice,
    N = String.prototype.replace,
    U = String.prototype.toUpperCase,
    z = String.prototype.toLowerCase,
    H = RegExp.prototype.test,
    G = Array.prototype.concat,
    Q = Array.prototype.join,
    me = Array.prototype.slice,
    ae = Math.floor,
    xe = typeof BigInt == "function" ? BigInt.prototype.valueOf : null,
    te = Object.getOwnPropertySymbols,
    _e =
      typeof Symbol == "function" && typeof Symbol.iterator == "symbol"
        ? Symbol.prototype.toString
        : null,
    Ae = typeof Symbol == "function" && typeof Symbol.iterator == "object",
    ke =
      typeof Symbol == "function" &&
      Symbol.toStringTag &&
      (typeof Symbol.toStringTag === Ae || !0)
        ? Symbol.toStringTag
        : null,
    be = Object.prototype.propertyIsEnumerable,
    Se =
      (typeof Reflect == "function"
        ? Reflect.getPrototypeOf
        : Object.getPrototypeOf) ||
      ([].__proto__ === Array.prototype
        ? function (M) {
            return M.__proto__;
          }
        : null);
  function D(M, L) {
    if (
      M === 1 / 0 ||
      M === -1 / 0 ||
      M !== M ||
      (M && M > -1e3 && M < 1e3) ||
      H.call(/e/, L)
    )
      return L;
    var Ce = /[0-9](?=(?:[0-9]{3})+(?![0-9]))/g;
    if (typeof M == "number") {
      var Me = M < 0 ? -ae(-M) : ae(M);
      if (Me !== M) {
        var Le = String(Me),
          ge = b.call(L, Le.length + 1);
        return (
          N.call(Le, Ce, "$&_") +
          "." +
          N.call(N.call(ge, /([0-9]{3})/g, "$&_"), /_$/, "")
        );
      }
    }
    return N.call(L, Ce, "$&_");
  }
  var J = yw,
    X = J.custom,
    R = Ye(X) ? X : null,
    B = { __proto__: null, double: '"', single: "'" },
    le = { __proto__: null, double: /(["\\])/g, single: /(['\\])/g };
  mu = function M(L, Ce, Me, Le) {
    var ge = Ce || {};
    if (rt(ge, "quoteStyle") && !rt(B, ge.quoteStyle))
      throw new TypeError('option "quoteStyle" must be "single" or "double"');
    if (
      rt(ge, "maxStringLength") &&
      (typeof ge.maxStringLength == "number"
        ? ge.maxStringLength < 0 && ge.maxStringLength !== 1 / 0
        : ge.maxStringLength !== null)
    )
      throw new TypeError(
        'option "maxStringLength", if provided, must be a positive integer, Infinity, or `null`'
      );
    var xt = rt(ge, "customInspect") ? ge.customInspect : !0;
    if (typeof xt != "boolean" && xt !== "symbol")
      throw new TypeError(
        "option \"customInspect\", if provided, must be `true`, `false`, or `'symbol'`"
      );
    if (
      rt(ge, "indent") &&
      ge.indent !== null &&
      ge.indent !== "	" &&
      !(parseInt(ge.indent, 10) === ge.indent && ge.indent > 0)
    )
      throw new TypeError(
        'option "indent" must be "\\t", an integer > 0, or `null`'
      );
    if (rt(ge, "numericSeparator") && typeof ge.numericSeparator != "boolean")
      throw new TypeError(
        'option "numericSeparator", if provided, must be `true` or `false`'
      );
    var pr = ge.numericSeparator;
    if (typeof L > "u") return "undefined";
    if (L === null) return "null";
    if (typeof L == "boolean") return L ? "true" : "false";
    if (typeof L == "string") return qn(L, ge);
    if (typeof L == "number") {
      if (L === 0) return 1 / 0 / L > 0 ? "0" : "-0";
      var ht = String(L);
      return pr ? D(L, ht) : ht;
    }
    if (typeof L == "bigint") {
      var Kt = String(L) + "n";
      return pr ? D(L, Kt) : Kt;
    }
    var Xn = typeof ge.depth > "u" ? 5 : ge.depth;
    if (
      (typeof Me > "u" && (Me = 0), Me >= Xn && Xn > 0 && typeof L == "object")
    )
      return Y(L) ? "[Array]" : "[Object]";
    var Rr = Bs(ge, Me);
    if (typeof Le > "u") Le = [];
    else if (kt(Le, L) >= 0) return "[Circular]";
    function St(br, Sn, zs) {
      if ((Sn && ((Le = me.call(Le)), Le.push(Sn)), zs)) {
        var Li = { depth: ge.depth };
        return (
          rt(ge, "quoteStyle") && (Li.quoteStyle = ge.quoteStyle),
          M(br, Li, Me + 1, Le)
        );
      }
      return M(br, ge, Me + 1, Le);
    }
    if (typeof L == "function" && !ne(L)) {
      var bi = hr(L),
        Wr = Wn(L, St);
      return (
        "[Function" +
        (bi ? ": " + bi : " (anonymous)") +
        "]" +
        (Wr.length > 0 ? " { " + Q.call(Wr, ", ") + " }" : "")
      );
    }
    if (Ye(L)) {
      var Yn = Ae
        ? N.call(String(L), /^(Symbol\(.*\))_[^)]*$/, "$1")
        : _e.call(L);
      return typeof L == "object" && !Ae ? Vr(Yn) : Yn;
    }
    if (Ds(L)) {
      for (
        var Jt = "<" + z.call(String(L.nodeName)),
          Ti = L.attributes || [],
          mr = 0;
        mr < Ti.length;
        mr++
      )
        Jt += " " + Ti[mr].name + "=" + he(W(Ti[mr].value), "double", ge);
      return (
        (Jt += ">"),
        L.childNodes && L.childNodes.length && (Jt += "..."),
        (Jt += "</" + z.call(String(L.nodeName)) + ">"),
        Jt
      );
    }
    if (Y(L)) {
      if (L.length === 0) return "[]";
      var Xr = Wn(L, St);
      return Rr && !Ra(Xr)
        ? "[" + Gn(Xr, Rr) + "]"
        : "[ " + Q.call(Xr, ", ") + " ]";
    }
    if (de(L)) {
      var Yr = Wn(L, St);
      return !("cause" in Error.prototype) &&
        "cause" in L &&
        !be.call(L, "cause")
        ? "{ [" +
            String(L) +
            "] " +
            Q.call(G.call("[cause]: " + St(L.cause), Yr), ", ") +
            " }"
        : Yr.length === 0
        ? "[" + String(L) + "]"
        : "{ [" + String(L) + "] " + Q.call(Yr, ", ") + " }";
    }
    if (typeof L == "object" && xt) {
      if (R && typeof L[R] == "function" && J) return J(L, { depth: Xn - Me });
      if (xt !== "symbol" && typeof L.inspect == "function") return L.inspect();
    }
    if (nt(L)) {
      var Qn = [];
      return (
        o &&
          o.call(L, function (br, Sn) {
            Qn.push(St(Sn, L, !0) + " => " + St(br, L));
          }),
        Gr("Map", i.call(L), Qn, Rr)
      );
    }
    if (Cr(L)) {
      var Us = [];
      return (
        d &&
          d.call(L, function (br) {
            Us.push(St(br, L));
          }),
        Gr("Set", f.call(L), Us, Rr)
      );
    }
    if (dr(L)) return kr("WeakMap");
    if (Ns(L)) return kr("WeakSet");
    if (Ar(L)) return kr("WeakRef");
    if (Ie(L)) return Vr(St(Number(L)));
    if (_t(L)) return Vr(St(xe.call(L)));
    if (Ue(L)) return Vr(E.call(L));
    if (ve(L)) return Vr(St(String(L)));
    if (typeof window < "u" && L === window) return "{ [object Window] }";
    if (
      (typeof globalThis < "u" && L === globalThis) ||
      (typeof Id < "u" && L === Id)
    )
      return "{ [object globalThis] }";
    if (!ue(L) && !ne(L)) {
      var Oi = Wn(L, St),
        js = Se
          ? Se(L) === Object.prototype
          : L instanceof Object || L.constructor === Object,
        Zt = L instanceof Object ? "" : "null prototype",
        Mi =
          !js && ke && Object(L) === L && ke in L
            ? b.call(wt(L), 8, -1)
            : Zt
            ? "Object"
            : "",
        $s =
          js || typeof L.constructor != "function"
            ? ""
            : L.constructor.name
            ? L.constructor.name + " "
            : "",
        Ii =
          $s +
          (Mi || Zt
            ? "[" + Q.call(G.call([], Mi || [], Zt || []), ": ") + "] "
            : "");
      return Oi.length === 0
        ? Ii + "{}"
        : Rr
        ? Ii + "{" + Gn(Oi, Rr) + "}"
        : Ii + "{ " + Q.call(Oi, ", ") + " }";
    }
    return String(L);
  };
  function he(M, L, Ce) {
    var Me = Ce.quoteStyle || L,
      Le = B[Me];
    return Le + M + Le;
  }
  function W(M) {
    return N.call(String(M), /"/g, "&quot;");
  }
  function re(M) {
    return !ke || !(typeof M == "object" && (ke in M || typeof M[ke] < "u"));
  }
  function Y(M) {
    return wt(M) === "[object Array]" && re(M);
  }
  function ue(M) {
    return wt(M) === "[object Date]" && re(M);
  }
  function ne(M) {
    return wt(M) === "[object RegExp]" && re(M);
  }
  function de(M) {
    return wt(M) === "[object Error]" && re(M);
  }
  function ve(M) {
    return wt(M) === "[object String]" && re(M);
  }
  function Ie(M) {
    return wt(M) === "[object Number]" && re(M);
  }
  function Ue(M) {
    return wt(M) === "[object Boolean]" && re(M);
  }
  function Ye(M) {
    if (Ae) return M && typeof M == "object" && M instanceof Symbol;
    if (typeof M == "symbol") return !0;
    if (!M || typeof M != "object" || !_e) return !1;
    try {
      return _e.call(M), !0;
    } catch {}
    return !1;
  }
  function _t(M) {
    if (!M || typeof M != "object" || !xe) return !1;
    try {
      return xe.call(M), !0;
    } catch {}
    return !1;
  }
  var Ke =
    Object.prototype.hasOwnProperty ||
    function (M) {
      return M in this;
    };
  function rt(M, L) {
    return Ke.call(M, L);
  }
  function wt(M) {
    return k.call(M);
  }
  function hr(M) {
    if (M.name) return M.name;
    var L = A.call(_.call(M), /^function\s*([\w$]+)/);
    return L ? L[1] : null;
  }
  function kt(M, L) {
    if (M.indexOf) return M.indexOf(L);
    for (var Ce = 0, Me = M.length; Ce < Me; Ce++) if (M[Ce] === L) return Ce;
    return -1;
  }
  function nt(M) {
    if (!i || !M || typeof M != "object") return !1;
    try {
      i.call(M);
      try {
        f.call(M);
      } catch {
        return !0;
      }
      return M instanceof Map;
    } catch {}
    return !1;
  }
  function dr(M) {
    if (!p || !M || typeof M != "object") return !1;
    try {
      p.call(M, p);
      try {
        v.call(M, v);
      } catch {
        return !0;
      }
      return M instanceof WeakMap;
    } catch {}
    return !1;
  }
  function Ar(M) {
    if (!w || !M || typeof M != "object") return !1;
    try {
      return w.call(M), !0;
    } catch {}
    return !1;
  }
  function Cr(M) {
    if (!f || !M || typeof M != "object") return !1;
    try {
      f.call(M);
      try {
        i.call(M);
      } catch {
        return !0;
      }
      return M instanceof Set;
    } catch {}
    return !1;
  }
  function Ns(M) {
    if (!v || !M || typeof M != "object") return !1;
    try {
      v.call(M, v);
      try {
        p.call(M, p);
      } catch {
        return !0;
      }
      return M instanceof WeakSet;
    } catch {}
    return !1;
  }
  function Ds(M) {
    return !M || typeof M != "object"
      ? !1
      : typeof HTMLElement < "u" && M instanceof HTMLElement
      ? !0
      : typeof M.nodeName == "string" && typeof M.getAttribute == "function";
  }
  function qn(M, L) {
    if (M.length > L.maxStringLength) {
      var Ce = M.length - L.maxStringLength,
        Me = "... " + Ce + " more character" + (Ce > 1 ? "s" : "");
      return qn(b.call(M, 0, L.maxStringLength), L) + Me;
    }
    var Le = le[L.quoteStyle || "single"];
    Le.lastIndex = 0;
    var ge = N.call(N.call(M, Le, "\\$1"), /[\x00-\x1f]/g, Vn);
    return he(ge, "single", L);
  }
  function Vn(M) {
    var L = M.charCodeAt(0),
      Ce = { 8: "b", 9: "t", 10: "n", 12: "f", 13: "r" }[L];
    return Ce
      ? "\\" + Ce
      : "\\x" + (L < 16 ? "0" : "") + U.call(L.toString(16));
  }
  function Vr(M) {
    return "Object(" + M + ")";
  }
  function kr(M) {
    return M + " { ? }";
  }
  function Gr(M, L, Ce, Me) {
    var Le = Me ? Gn(Ce, Me) : Q.call(Ce, ", ");
    return M + " (" + L + ") {" + Le + "}";
  }
  function Ra(M) {
    for (var L = 0; L < M.length; L++)
      if (
        kt(
          M[L],
          `
`
        ) >= 0
      )
        return !1;
    return !0;
  }
  function Bs(M, L) {
    var Ce;
    if (M.indent === "	") Ce = "	";
    else if (typeof M.indent == "number" && M.indent > 0)
      Ce = Q.call(Array(M.indent + 1), " ");
    else return null;
    return { base: Ce, prev: Q.call(Array(L + 1), Ce) };
  }
  function Gn(M, L) {
    if (M.length === 0) return "";
    var Ce =
      `
` +
      L.prev +
      L.base;
    return (
      Ce +
      Q.call(M, "," + Ce) +
      `
` +
      L.prev
    );
  }
  function Wn(M, L) {
    var Ce = Y(M),
      Me = [];
    if (Ce) {
      Me.length = M.length;
      for (var Le = 0; Le < M.length; Le++)
        Me[Le] = rt(M, Le) ? L(M[Le], M) : "";
    }
    var ge = typeof te == "function" ? te(M) : [],
      xt;
    if (Ae) {
      xt = {};
      for (var pr = 0; pr < ge.length; pr++) xt["$" + ge[pr]] = ge[pr];
    }
    for (var ht in M)
      rt(M, ht) &&
        ((Ce && String(Number(ht)) === ht && ht < M.length) ||
          (Ae && xt["$" + ht] instanceof Symbol) ||
          (H.call(/[^\w$]/, ht)
            ? Me.push(L(ht, M) + ": " + L(M[ht], M))
            : Me.push(ht + ": " + L(M[ht], M))));
    if (typeof te == "function")
      for (var Kt = 0; Kt < ge.length; Kt++)
        be.call(M, ge[Kt]) &&
          Me.push("[" + L(ge[Kt]) + "]: " + L(M[ge[Kt]], M));
    return Me;
  }
  return mu;
}
var yu, Zd;
function gw() {
  if (Zd) return yu;
  Zd = 1;
  var r = Pa(),
    e = Ri(),
    i = function (d, m, p) {
      for (var g = d, v; (v = g.next) != null; g = v)
        if (v.key === m)
          return (g.next = v.next), p || ((v.next = d.next), (d.next = v)), v;
    },
    o = function (d, m) {
      if (d) {
        var p = i(d, m);
        return p && p.value;
      }
    },
    l = function (d, m, p) {
      var g = i(d, m);
      g ? (g.value = p) : (d.next = { key: m, next: d.next, value: p });
    },
    c = function (d, m) {
      return d ? !!i(d, m) : !1;
    },
    f = function (d, m) {
      if (d) return i(d, m, !0);
    };
  return (
    (yu = function () {
      var m,
        p = {
          assert: function (g) {
            if (!p.has(g)) throw new e("Side channel does not contain " + r(g));
          },
          delete: function (g) {
            var v = m && m.next,
              x = f(m, g);
            return x && v && v === x && (m = void 0), !!x;
          },
          get: function (g) {
            return o(m, g);
          },
          has: function (g) {
            return c(m, g);
          },
          set: function (g, v) {
            m || (m = { next: void 0 }), l(m, g, v);
          },
        };
      return p;
    }),
    yu
  );
}
var gu, ep;
function iy() {
  return ep || ((ep = 1), (gu = Object)), gu;
}
var vu, tp;
function vw() {
  return tp || ((tp = 1), (vu = Error)), vu;
}
var _u, rp;
function _w() {
  return rp || ((rp = 1), (_u = EvalError)), _u;
}
var wu, np;
function ww() {
  return np || ((np = 1), (wu = RangeError)), wu;
}
var xu, ip;
function xw() {
  return ip || ((ip = 1), (xu = ReferenceError)), xu;
}
var Su, sp;
function Sw() {
  return sp || ((sp = 1), (Su = SyntaxError)), Su;
}
var Eu, op;
function Ew() {
  return op || ((op = 1), (Eu = URIError)), Eu;
}
var Pu, ap;
function Pw() {
  return ap || ((ap = 1), (Pu = Math.abs)), Pu;
}
var Au, lp;
function Aw() {
  return lp || ((lp = 1), (Au = Math.floor)), Au;
}
var Cu, up;
function Cw() {
  return up || ((up = 1), (Cu = Math.max)), Cu;
}
var ku, cp;
function kw() {
  return cp || ((cp = 1), (ku = Math.min)), ku;
}
var Ru, fp;
function Rw() {
  return fp || ((fp = 1), (Ru = Math.pow)), Ru;
}
var bu, hp;
function bw() {
  return hp || ((hp = 1), (bu = Math.round)), bu;
}
var Tu, dp;
function Tw() {
  return (
    dp ||
      ((dp = 1),
      (Tu =
        Number.isNaN ||
        function (e) {
          return e !== e;
        })),
    Tu
  );
}
var Ou, pp;
function Ow() {
  if (pp) return Ou;
  pp = 1;
  var r = Tw();
  return (
    (Ou = function (i) {
      return r(i) || i === 0 ? i : i < 0 ? -1 : 1;
    }),
    Ou
  );
}
var Mu, mp;
function Mw() {
  return mp || ((mp = 1), (Mu = Object.getOwnPropertyDescriptor)), Mu;
}
var Iu, yp;
function sy() {
  if (yp) return Iu;
  yp = 1;
  var r = Mw();
  if (r)
    try {
      r([], "length");
    } catch {
      r = null;
    }
  return (Iu = r), Iu;
}
var Lu, gp;
function Iw() {
  if (gp) return Lu;
  gp = 1;
  var r = Object.defineProperty || !1;
  if (r)
    try {
      r({}, "a", { value: 1 });
    } catch {
      r = !1;
    }
  return (Lu = r), Lu;
}
var Fu, vp;
function Lw() {
  return (
    vp ||
      ((vp = 1),
      (Fu = function () {
        if (
          typeof Symbol != "function" ||
          typeof Object.getOwnPropertySymbols != "function"
        )
          return !1;
        if (typeof Symbol.iterator == "symbol") return !0;
        var e = {},
          i = Symbol("test"),
          o = Object(i);
        if (
          typeof i == "string" ||
          Object.prototype.toString.call(i) !== "[object Symbol]" ||
          Object.prototype.toString.call(o) !== "[object Symbol]"
        )
          return !1;
        var l = 42;
        e[i] = l;
        for (var c in e) return !1;
        if (
          (typeof Object.keys == "function" && Object.keys(e).length !== 0) ||
          (typeof Object.getOwnPropertyNames == "function" &&
            Object.getOwnPropertyNames(e).length !== 0)
        )
          return !1;
        var f = Object.getOwnPropertySymbols(e);
        if (
          f.length !== 1 ||
          f[0] !== i ||
          !Object.prototype.propertyIsEnumerable.call(e, i)
        )
          return !1;
        if (typeof Object.getOwnPropertyDescriptor == "function") {
          var d = Object.getOwnPropertyDescriptor(e, i);
          if (d.value !== l || d.enumerable !== !0) return !1;
        }
        return !0;
      })),
    Fu
  );
}
var Nu, _p;
function Fw() {
  if (_p) return Nu;
  _p = 1;
  var r = typeof Symbol < "u" && Symbol,
    e = Lw();
  return (
    (Nu = function () {
      return typeof r != "function" ||
        typeof Symbol != "function" ||
        typeof r("foo") != "symbol" ||
        typeof Symbol("bar") != "symbol"
        ? !1
        : e();
    }),
    Nu
  );
}
var Du, wp;
function oy() {
  return (
    wp ||
      ((wp = 1),
      (Du = (typeof Reflect < "u" && Reflect.getPrototypeOf) || null)),
    Du
  );
}
var Bu, xp;
function ay() {
  if (xp) return Bu;
  xp = 1;
  var r = iy();
  return (Bu = r.getPrototypeOf || null), Bu;
}
var Uu, Sp;
function Nw() {
  if (Sp) return Uu;
  Sp = 1;
  var r = "Function.prototype.bind called on incompatible ",
    e = Object.prototype.toString,
    i = Math.max,
    o = "[object Function]",
    l = function (m, p) {
      for (var g = [], v = 0; v < m.length; v += 1) g[v] = m[v];
      for (var x = 0; x < p.length; x += 1) g[x + m.length] = p[x];
      return g;
    },
    c = function (m, p) {
      for (var g = [], v = p, x = 0; v < m.length; v += 1, x += 1) g[x] = m[v];
      return g;
    },
    f = function (d, m) {
      for (var p = "", g = 0; g < d.length; g += 1)
        (p += d[g]), g + 1 < d.length && (p += m);
      return p;
    };
  return (
    (Uu = function (m) {
      var p = this;
      if (typeof p != "function" || e.apply(p) !== o)
        throw new TypeError(r + p);
      for (
        var g = c(arguments, 1),
          v,
          x = function () {
            if (this instanceof v) {
              var A = p.apply(this, l(g, arguments));
              return Object(A) === A ? A : this;
            }
            return p.apply(m, l(g, arguments));
          },
          w = i(0, p.length - g.length),
          E = [],
          k = 0;
        k < w;
        k++
      )
        E[k] = "$" + k;
      if (
        ((v = Function(
          "binder",
          "return function (" +
            f(E, ",") +
            "){ return binder.apply(this,arguments); }"
        )(x)),
        p.prototype)
      ) {
        var _ = function () {};
        (_.prototype = p.prototype),
          (v.prototype = new _()),
          (_.prototype = null);
      }
      return v;
    }),
    Uu
  );
}
var ju, Ep;
function Aa() {
  if (Ep) return ju;
  Ep = 1;
  var r = Nw();
  return (ju = Function.prototype.bind || r), ju;
}
var $u, Pp;
function Kc() {
  return Pp || ((Pp = 1), ($u = Function.prototype.call)), $u;
}
var zu, Ap;
function ly() {
  return Ap || ((Ap = 1), (zu = Function.prototype.apply)), zu;
}
var Hu, Cp;
function Dw() {
  return (
    Cp || ((Cp = 1), (Hu = typeof Reflect < "u" && Reflect && Reflect.apply)),
    Hu
  );
}
var qu, kp;
function Bw() {
  if (kp) return qu;
  kp = 1;
  var r = Aa(),
    e = ly(),
    i = Kc(),
    o = Dw();
  return (qu = o || r.call(i, e)), qu;
}
var Vu, Rp;
function uy() {
  if (Rp) return Vu;
  Rp = 1;
  var r = Aa(),
    e = Ri(),
    i = Kc(),
    o = Bw();
  return (
    (Vu = function (c) {
      if (c.length < 1 || typeof c[0] != "function")
        throw new e("a function is required");
      return o(r, i, c);
    }),
    Vu
  );
}
var Gu, bp;
function Uw() {
  if (bp) return Gu;
  bp = 1;
  var r = uy(),
    e = sy(),
    i;
  try {
    i = [].__proto__ === Array.prototype;
  } catch (f) {
    if (
      !f ||
      typeof f != "object" ||
      !("code" in f) ||
      f.code !== "ERR_PROTO_ACCESS"
    )
      throw f;
  }
  var o = !!i && e && e(Object.prototype, "__proto__"),
    l = Object,
    c = l.getPrototypeOf;
  return (
    (Gu =
      o && typeof o.get == "function"
        ? r([o.get])
        : typeof c == "function"
        ? function (d) {
            return c(d == null ? d : l(d));
          }
        : !1),
    Gu
  );
}
var Wu, Tp;
function jw() {
  if (Tp) return Wu;
  Tp = 1;
  var r = oy(),
    e = ay(),
    i = Uw();
  return (
    (Wu = r
      ? function (l) {
          return r(l);
        }
      : e
      ? function (l) {
          if (!l || (typeof l != "object" && typeof l != "function"))
            throw new TypeError("getProto: not an object");
          return e(l);
        }
      : i
      ? function (l) {
          return i(l);
        }
      : null),
    Wu
  );
}
var Xu, Op;
function $w() {
  if (Op) return Xu;
  Op = 1;
  var r = Function.prototype.call,
    e = Object.prototype.hasOwnProperty,
    i = Aa();
  return (Xu = i.call(r, e)), Xu;
}
var Yu, Mp;
function Jc() {
  if (Mp) return Yu;
  Mp = 1;
  var r,
    e = iy(),
    i = vw(),
    o = _w(),
    l = ww(),
    c = xw(),
    f = Sw(),
    d = Ri(),
    m = Ew(),
    p = Pw(),
    g = Aw(),
    v = Cw(),
    x = kw(),
    w = Rw(),
    E = bw(),
    k = Ow(),
    _ = Function,
    A = function (ne) {
      try {
        return _('"use strict"; return (' + ne + ").constructor;")();
      } catch {}
    },
    b = sy(),
    N = Iw(),
    U = function () {
      throw new d();
    },
    z = b
      ? (function () {
          try {
            return arguments.callee, U;
          } catch {
            try {
              return b(arguments, "callee").get;
            } catch {
              return U;
            }
          }
        })()
      : U,
    H = Fw()(),
    G = jw(),
    Q = ay(),
    me = oy(),
    ae = ly(),
    xe = Kc(),
    te = {},
    _e = typeof Uint8Array > "u" || !G ? r : G(Uint8Array),
    Ae = {
      __proto__: null,
      "%AggregateError%": typeof AggregateError > "u" ? r : AggregateError,
      "%Array%": Array,
      "%ArrayBuffer%": typeof ArrayBuffer > "u" ? r : ArrayBuffer,
      "%ArrayIteratorPrototype%": H && G ? G([][Symbol.iterator]()) : r,
      "%AsyncFromSyncIteratorPrototype%": r,
      "%AsyncFunction%": te,
      "%AsyncGenerator%": te,
      "%AsyncGeneratorFunction%": te,
      "%AsyncIteratorPrototype%": te,
      "%Atomics%": typeof Atomics > "u" ? r : Atomics,
      "%BigInt%": typeof BigInt > "u" ? r : BigInt,
      "%BigInt64Array%": typeof BigInt64Array > "u" ? r : BigInt64Array,
      "%BigUint64Array%": typeof BigUint64Array > "u" ? r : BigUint64Array,
      "%Boolean%": Boolean,
      "%DataView%": typeof DataView > "u" ? r : DataView,
      "%Date%": Date,
      "%decodeURI%": decodeURI,
      "%decodeURIComponent%": decodeURIComponent,
      "%encodeURI%": encodeURI,
      "%encodeURIComponent%": encodeURIComponent,
      "%Error%": i,
      "%eval%": eval,
      "%EvalError%": o,
      "%Float16Array%": typeof Float16Array > "u" ? r : Float16Array,
      "%Float32Array%": typeof Float32Array > "u" ? r : Float32Array,
      "%Float64Array%": typeof Float64Array > "u" ? r : Float64Array,
      "%FinalizationRegistry%":
        typeof FinalizationRegistry > "u" ? r : FinalizationRegistry,
      "%Function%": _,
      "%GeneratorFunction%": te,
      "%Int8Array%": typeof Int8Array > "u" ? r : Int8Array,
      "%Int16Array%": typeof Int16Array > "u" ? r : Int16Array,
      "%Int32Array%": typeof Int32Array > "u" ? r : Int32Array,
      "%isFinite%": isFinite,
      "%isNaN%": isNaN,
      "%IteratorPrototype%": H && G ? G(G([][Symbol.iterator]())) : r,
      "%JSON%": typeof JSON == "object" ? JSON : r,
      "%Map%": typeof Map > "u" ? r : Map,
      "%MapIteratorPrototype%":
        typeof Map > "u" || !H || !G ? r : G(new Map()[Symbol.iterator]()),
      "%Math%": Math,
      "%Number%": Number,
      "%Object%": e,
      "%Object.getOwnPropertyDescriptor%": b,
      "%parseFloat%": parseFloat,
      "%parseInt%": parseInt,
      "%Promise%": typeof Promise > "u" ? r : Promise,
      "%Proxy%": typeof Proxy > "u" ? r : Proxy,
      "%RangeError%": l,
      "%ReferenceError%": c,
      "%Reflect%": typeof Reflect > "u" ? r : Reflect,
      "%RegExp%": RegExp,
      "%Set%": typeof Set > "u" ? r : Set,
      "%SetIteratorPrototype%":
        typeof Set > "u" || !H || !G ? r : G(new Set()[Symbol.iterator]()),
      "%SharedArrayBuffer%":
        typeof SharedArrayBuffer > "u" ? r : SharedArrayBuffer,
      "%String%": String,
      "%StringIteratorPrototype%": H && G ? G(""[Symbol.iterator]()) : r,
      "%Symbol%": H ? Symbol : r,
      "%SyntaxError%": f,
      "%ThrowTypeError%": z,
      "%TypedArray%": _e,
      "%TypeError%": d,
      "%Uint8Array%": typeof Uint8Array > "u" ? r : Uint8Array,
      "%Uint8ClampedArray%":
        typeof Uint8ClampedArray > "u" ? r : Uint8ClampedArray,
      "%Uint16Array%": typeof Uint16Array > "u" ? r : Uint16Array,
      "%Uint32Array%": typeof Uint32Array > "u" ? r : Uint32Array,
      "%URIError%": m,
      "%WeakMap%": typeof WeakMap > "u" ? r : WeakMap,
      "%WeakRef%": typeof WeakRef > "u" ? r : WeakRef,
      "%WeakSet%": typeof WeakSet > "u" ? r : WeakSet,
      "%Function.prototype.call%": xe,
      "%Function.prototype.apply%": ae,
      "%Object.defineProperty%": N,
      "%Object.getPrototypeOf%": Q,
      "%Math.abs%": p,
      "%Math.floor%": g,
      "%Math.max%": v,
      "%Math.min%": x,
      "%Math.pow%": w,
      "%Math.round%": E,
      "%Math.sign%": k,
      "%Reflect.getPrototypeOf%": me,
    };
  if (G)
    try {
      null.error;
    } catch (ne) {
      var ke = G(G(ne));
      Ae["%Error.prototype%"] = ke;
    }
  var be = function ne(de) {
      var ve;
      if (de === "%AsyncFunction%") ve = A("async function () {}");
      else if (de === "%GeneratorFunction%") ve = A("function* () {}");
      else if (de === "%AsyncGeneratorFunction%")
        ve = A("async function* () {}");
      else if (de === "%AsyncGenerator%") {
        var Ie = ne("%AsyncGeneratorFunction%");
        Ie && (ve = Ie.prototype);
      } else if (de === "%AsyncIteratorPrototype%") {
        var Ue = ne("%AsyncGenerator%");
        Ue && G && (ve = G(Ue.prototype));
      }
      return (Ae[de] = ve), ve;
    },
    Se = {
      __proto__: null,
      "%ArrayBufferPrototype%": ["ArrayBuffer", "prototype"],
      "%ArrayPrototype%": ["Array", "prototype"],
      "%ArrayProto_entries%": ["Array", "prototype", "entries"],
      "%ArrayProto_forEach%": ["Array", "prototype", "forEach"],
      "%ArrayProto_keys%": ["Array", "prototype", "keys"],
      "%ArrayProto_values%": ["Array", "prototype", "values"],
      "%AsyncFunctionPrototype%": ["AsyncFunction", "prototype"],
      "%AsyncGenerator%": ["AsyncGeneratorFunction", "prototype"],
      "%AsyncGeneratorPrototype%": [
        "AsyncGeneratorFunction",
        "prototype",
        "prototype",
      ],
      "%BooleanPrototype%": ["Boolean", "prototype"],
      "%DataViewPrototype%": ["DataView", "prototype"],
      "%DatePrototype%": ["Date", "prototype"],
      "%ErrorPrototype%": ["Error", "prototype"],
      "%EvalErrorPrototype%": ["EvalError", "prototype"],
      "%Float32ArrayPrototype%": ["Float32Array", "prototype"],
      "%Float64ArrayPrototype%": ["Float64Array", "prototype"],
      "%FunctionPrototype%": ["Function", "prototype"],
      "%Generator%": ["GeneratorFunction", "prototype"],
      "%GeneratorPrototype%": ["GeneratorFunction", "prototype", "prototype"],
      "%Int8ArrayPrototype%": ["Int8Array", "prototype"],
      "%Int16ArrayPrototype%": ["Int16Array", "prototype"],
      "%Int32ArrayPrototype%": ["Int32Array", "prototype"],
      "%JSONParse%": ["JSON", "parse"],
      "%JSONStringify%": ["JSON", "stringify"],
      "%MapPrototype%": ["Map", "prototype"],
      "%NumberPrototype%": ["Number", "prototype"],
      "%ObjectPrototype%": ["Object", "prototype"],
      "%ObjProto_toString%": ["Object", "prototype", "toString"],
      "%ObjProto_valueOf%": ["Object", "prototype", "valueOf"],
      "%PromisePrototype%": ["Promise", "prototype"],
      "%PromiseProto_then%": ["Promise", "prototype", "then"],
      "%Promise_all%": ["Promise", "all"],
      "%Promise_reject%": ["Promise", "reject"],
      "%Promise_resolve%": ["Promise", "resolve"],
      "%RangeErrorPrototype%": ["RangeError", "prototype"],
      "%ReferenceErrorPrototype%": ["ReferenceError", "prototype"],
      "%RegExpPrototype%": ["RegExp", "prototype"],
      "%SetPrototype%": ["Set", "prototype"],
      "%SharedArrayBufferPrototype%": ["SharedArrayBuffer", "prototype"],
      "%StringPrototype%": ["String", "prototype"],
      "%SymbolPrototype%": ["Symbol", "prototype"],
      "%SyntaxErrorPrototype%": ["SyntaxError", "prototype"],
      "%TypedArrayPrototype%": ["TypedArray", "prototype"],
      "%TypeErrorPrototype%": ["TypeError", "prototype"],
      "%Uint8ArrayPrototype%": ["Uint8Array", "prototype"],
      "%Uint8ClampedArrayPrototype%": ["Uint8ClampedArray", "prototype"],
      "%Uint16ArrayPrototype%": ["Uint16Array", "prototype"],
      "%Uint32ArrayPrototype%": ["Uint32Array", "prototype"],
      "%URIErrorPrototype%": ["URIError", "prototype"],
      "%WeakMapPrototype%": ["WeakMap", "prototype"],
      "%WeakSetPrototype%": ["WeakSet", "prototype"],
    },
    D = Aa(),
    J = $w(),
    X = D.call(xe, Array.prototype.concat),
    R = D.call(ae, Array.prototype.splice),
    B = D.call(xe, String.prototype.replace),
    le = D.call(xe, String.prototype.slice),
    he = D.call(xe, RegExp.prototype.exec),
    W =
      /[^%.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|%$))/g,
    re = /\\(\\)?/g,
    Y = function (de) {
      var ve = le(de, 0, 1),
        Ie = le(de, -1);
      if (ve === "%" && Ie !== "%")
        throw new f("invalid intrinsic syntax, expected closing `%`");
      if (Ie === "%" && ve !== "%")
        throw new f("invalid intrinsic syntax, expected opening `%`");
      var Ue = [];
      return (
        B(de, W, function (Ye, _t, Ke, rt) {
          Ue[Ue.length] = Ke ? B(rt, re, "$1") : _t || Ye;
        }),
        Ue
      );
    },
    ue = function (de, ve) {
      var Ie = de,
        Ue;
      if ((J(Se, Ie) && ((Ue = Se[Ie]), (Ie = "%" + Ue[0] + "%")), J(Ae, Ie))) {
        var Ye = Ae[Ie];
        if ((Ye === te && (Ye = be(Ie)), typeof Ye > "u" && !ve))
          throw new d(
            "intrinsic " +
              de +
              " exists, but is not available. Please file an issue!"
          );
        return { alias: Ue, name: Ie, value: Ye };
      }
      throw new f("intrinsic " + de + " does not exist!");
    };
  return (
    (Yu = function (de, ve) {
      if (typeof de != "string" || de.length === 0)
        throw new d("intrinsic name must be a non-empty string");
      if (arguments.length > 1 && typeof ve != "boolean")
        throw new d('"allowMissing" argument must be a boolean');
      if (he(/^%?[^%]*%?$/, de) === null)
        throw new f(
          "`%` may not be present anywhere but at the beginning and end of the intrinsic name"
        );
      var Ie = Y(de),
        Ue = Ie.length > 0 ? Ie[0] : "",
        Ye = ue("%" + Ue + "%", ve),
        _t = Ye.name,
        Ke = Ye.value,
        rt = !1,
        wt = Ye.alias;
      wt && ((Ue = wt[0]), R(Ie, X([0, 1], wt)));
      for (var hr = 1, kt = !0; hr < Ie.length; hr += 1) {
        var nt = Ie[hr],
          dr = le(nt, 0, 1),
          Ar = le(nt, -1);
        if (
          (dr === '"' ||
            dr === "'" ||
            dr === "`" ||
            Ar === '"' ||
            Ar === "'" ||
            Ar === "`") &&
          dr !== Ar
        )
          throw new f("property names with quotes must have matching quotes");
        if (
          ((nt === "constructor" || !kt) && (rt = !0),
          (Ue += "." + nt),
          (_t = "%" + Ue + "%"),
          J(Ae, _t))
        )
          Ke = Ae[_t];
        else if (Ke != null) {
          if (!(nt in Ke)) {
            if (!ve)
              throw new d(
                "base intrinsic for " +
                  de +
                  " exists, but the property is not available."
              );
            return;
          }
          if (b && hr + 1 >= Ie.length) {
            var Cr = b(Ke, nt);
            (kt = !!Cr),
              kt && "get" in Cr && !("originalValue" in Cr.get)
                ? (Ke = Cr.get)
                : (Ke = Ke[nt]);
          } else (kt = J(Ke, nt)), (Ke = Ke[nt]);
          kt && !rt && (Ae[_t] = Ke);
        }
      }
      return Ke;
    }),
    Yu
  );
}
var Qu, Ip;
function cy() {
  if (Ip) return Qu;
  Ip = 1;
  var r = Jc(),
    e = uy(),
    i = e([r("%String.prototype.indexOf%")]);
  return (
    (Qu = function (l, c) {
      var f = r(l, !!c);
      return typeof f == "function" && i(l, ".prototype.") > -1 ? e([f]) : f;
    }),
    Qu
  );
}
var Ku, Lp;
function fy() {
  if (Lp) return Ku;
  Lp = 1;
  var r = Jc(),
    e = cy(),
    i = Pa(),
    o = Ri(),
    l = r("%Map%", !0),
    c = e("Map.prototype.get", !0),
    f = e("Map.prototype.set", !0),
    d = e("Map.prototype.has", !0),
    m = e("Map.prototype.delete", !0),
    p = e("Map.prototype.size", !0);
  return (
    (Ku =
      !!l &&
      function () {
        var v,
          x = {
            assert: function (w) {
              if (!x.has(w))
                throw new o("Side channel does not contain " + i(w));
            },
            delete: function (w) {
              if (v) {
                var E = m(v, w);
                return p(v) === 0 && (v = void 0), E;
              }
              return !1;
            },
            get: function (w) {
              if (v) return c(v, w);
            },
            has: function (w) {
              return v ? d(v, w) : !1;
            },
            set: function (w, E) {
              v || (v = new l()), f(v, w, E);
            },
          };
        return x;
      }),
    Ku
  );
}
var Ju, Fp;
function zw() {
  if (Fp) return Ju;
  Fp = 1;
  var r = Jc(),
    e = cy(),
    i = Pa(),
    o = fy(),
    l = Ri(),
    c = r("%WeakMap%", !0),
    f = e("WeakMap.prototype.get", !0),
    d = e("WeakMap.prototype.set", !0),
    m = e("WeakMap.prototype.has", !0),
    p = e("WeakMap.prototype.delete", !0);
  return (
    (Ju = c
      ? function () {
          var v,
            x,
            w = {
              assert: function (E) {
                if (!w.has(E))
                  throw new l("Side channel does not contain " + i(E));
              },
              delete: function (E) {
                if (
                  c &&
                  E &&
                  (typeof E == "object" || typeof E == "function")
                ) {
                  if (v) return p(v, E);
                } else if (o && x) return x.delete(E);
                return !1;
              },
              get: function (E) {
                return c &&
                  E &&
                  (typeof E == "object" || typeof E == "function") &&
                  v
                  ? f(v, E)
                  : x && x.get(E);
              },
              has: function (E) {
                return c &&
                  E &&
                  (typeof E == "object" || typeof E == "function") &&
                  v
                  ? m(v, E)
                  : !!x && x.has(E);
              },
              set: function (E, k) {
                c && E && (typeof E == "object" || typeof E == "function")
                  ? (v || (v = new c()), d(v, E, k))
                  : o && (x || (x = o()), x.set(E, k));
              },
            };
          return w;
        }
      : o),
    Ju
  );
}
var Zu, Np;
function Hw() {
  if (Np) return Zu;
  Np = 1;
  var r = Ri(),
    e = Pa(),
    i = gw(),
    o = fy(),
    l = zw(),
    c = l || o || i;
  return (
    (Zu = function () {
      var d,
        m = {
          assert: function (p) {
            if (!m.has(p)) throw new r("Side channel does not contain " + e(p));
          },
          delete: function (p) {
            return !!d && d.delete(p);
          },
          get: function (p) {
            return d && d.get(p);
          },
          has: function (p) {
            return !!d && d.has(p);
          },
          set: function (p, g) {
            d || (d = c()), d.set(p, g);
          },
        };
      return m;
    }),
    Zu
  );
}
var ec, Dp;
function Zc() {
  if (Dp) return ec;
  Dp = 1;
  var r = String.prototype.replace,
    e = /%20/g,
    i = { RFC1738: "RFC1738", RFC3986: "RFC3986" };
  return (
    (ec = {
      default: i.RFC3986,
      formatters: {
        RFC1738: function (o) {
          return r.call(o, e, "+");
        },
        RFC3986: function (o) {
          return String(o);
        },
      },
      RFC1738: i.RFC1738,
      RFC3986: i.RFC3986,
    }),
    ec
  );
}
var tc, Bp;
function hy() {
  if (Bp) return tc;
  Bp = 1;
  var r = Zc(),
    e = Object.prototype.hasOwnProperty,
    i = Array.isArray,
    o = (function () {
      for (var _ = [], A = 0; A < 256; ++A)
        _.push("%" + ((A < 16 ? "0" : "") + A.toString(16)).toUpperCase());
      return _;
    })(),
    l = function (A) {
      for (; A.length > 1; ) {
        var b = A.pop(),
          N = b.obj[b.prop];
        if (i(N)) {
          for (var U = [], z = 0; z < N.length; ++z)
            typeof N[z] < "u" && U.push(N[z]);
          b.obj[b.prop] = U;
        }
      }
    },
    c = function (A, b) {
      for (
        var N = b && b.plainObjects ? { __proto__: null } : {}, U = 0;
        U < A.length;
        ++U
      )
        typeof A[U] < "u" && (N[U] = A[U]);
      return N;
    },
    f = function _(A, b, N) {
      if (!b) return A;
      if (typeof b != "object" && typeof b != "function") {
        if (i(A)) A.push(b);
        else if (A && typeof A == "object")
          ((N && (N.plainObjects || N.allowPrototypes)) ||
            !e.call(Object.prototype, b)) &&
            (A[b] = !0);
        else return [A, b];
        return A;
      }
      if (!A || typeof A != "object") return [A].concat(b);
      var U = A;
      return (
        i(A) && !i(b) && (U = c(A, N)),
        i(A) && i(b)
          ? (b.forEach(function (z, H) {
              if (e.call(A, H)) {
                var G = A[H];
                G && typeof G == "object" && z && typeof z == "object"
                  ? (A[H] = _(G, z, N))
                  : A.push(z);
              } else A[H] = z;
            }),
            A)
          : Object.keys(b).reduce(function (z, H) {
              var G = b[H];
              return e.call(z, H) ? (z[H] = _(z[H], G, N)) : (z[H] = G), z;
            }, U)
      );
    },
    d = function (A, b) {
      return Object.keys(b).reduce(function (N, U) {
        return (N[U] = b[U]), N;
      }, A);
    },
    m = function (_, A, b) {
      var N = _.replace(/\+/g, " ");
      if (b === "iso-8859-1") return N.replace(/%[0-9a-f]{2}/gi, unescape);
      try {
        return decodeURIComponent(N);
      } catch {
        return N;
      }
    },
    p = 1024,
    g = function (A, b, N, U, z) {
      if (A.length === 0) return A;
      var H = A;
      if (
        (typeof A == "symbol"
          ? (H = Symbol.prototype.toString.call(A))
          : typeof A != "string" && (H = String(A)),
        N === "iso-8859-1")
      )
        return escape(H).replace(/%u[0-9a-f]{4}/gi, function (_e) {
          return "%26%23" + parseInt(_e.slice(2), 16) + "%3B";
        });
      for (var G = "", Q = 0; Q < H.length; Q += p) {
        for (
          var me = H.length >= p ? H.slice(Q, Q + p) : H, ae = [], xe = 0;
          xe < me.length;
          ++xe
        ) {
          var te = me.charCodeAt(xe);
          if (
            te === 45 ||
            te === 46 ||
            te === 95 ||
            te === 126 ||
            (te >= 48 && te <= 57) ||
            (te >= 65 && te <= 90) ||
            (te >= 97 && te <= 122) ||
            (z === r.RFC1738 && (te === 40 || te === 41))
          ) {
            ae[ae.length] = me.charAt(xe);
            continue;
          }
          if (te < 128) {
            ae[ae.length] = o[te];
            continue;
          }
          if (te < 2048) {
            ae[ae.length] = o[192 | (te >> 6)] + o[128 | (te & 63)];
            continue;
          }
          if (te < 55296 || te >= 57344) {
            ae[ae.length] =
              o[224 | (te >> 12)] +
              o[128 | ((te >> 6) & 63)] +
              o[128 | (te & 63)];
            continue;
          }
          (xe += 1),
            (te = 65536 + (((te & 1023) << 10) | (me.charCodeAt(xe) & 1023))),
            (ae[ae.length] =
              o[240 | (te >> 18)] +
              o[128 | ((te >> 12) & 63)] +
              o[128 | ((te >> 6) & 63)] +
              o[128 | (te & 63)]);
        }
        G += ae.join("");
      }
      return G;
    },
    v = function (A) {
      for (
        var b = [{ obj: { o: A }, prop: "o" }], N = [], U = 0;
        U < b.length;
        ++U
      )
        for (
          var z = b[U], H = z.obj[z.prop], G = Object.keys(H), Q = 0;
          Q < G.length;
          ++Q
        ) {
          var me = G[Q],
            ae = H[me];
          typeof ae == "object" &&
            ae !== null &&
            N.indexOf(ae) === -1 &&
            (b.push({ obj: H, prop: me }), N.push(ae));
        }
      return l(b), A;
    },
    x = function (A) {
      return Object.prototype.toString.call(A) === "[object RegExp]";
    },
    w = function (A) {
      return !A || typeof A != "object"
        ? !1
        : !!(
            A.constructor &&
            A.constructor.isBuffer &&
            A.constructor.isBuffer(A)
          );
    },
    E = function (A, b) {
      return [].concat(A, b);
    },
    k = function (A, b) {
      if (i(A)) {
        for (var N = [], U = 0; U < A.length; U += 1) N.push(b(A[U]));
        return N;
      }
      return b(A);
    };
  return (
    (tc = {
      arrayToObject: c,
      assign: d,
      combine: E,
      compact: v,
      decode: m,
      encode: g,
      isBuffer: w,
      isRegExp: x,
      maybeMap: k,
      merge: f,
    }),
    tc
  );
}
var rc, Up;
function qw() {
  if (Up) return rc;
  Up = 1;
  var r = Hw(),
    e = hy(),
    i = Zc(),
    o = Object.prototype.hasOwnProperty,
    l = {
      brackets: function (_) {
        return _ + "[]";
      },
      comma: "comma",
      indices: function (_, A) {
        return _ + "[" + A + "]";
      },
      repeat: function (_) {
        return _;
      },
    },
    c = Array.isArray,
    f = Array.prototype.push,
    d = function (k, _) {
      f.apply(k, c(_) ? _ : [_]);
    },
    m = Date.prototype.toISOString,
    p = i.default,
    g = {
      addQueryPrefix: !1,
      allowDots: !1,
      allowEmptyArrays: !1,
      arrayFormat: "indices",
      charset: "utf-8",
      charsetSentinel: !1,
      commaRoundTrip: !1,
      delimiter: "&",
      encode: !0,
      encodeDotInKeys: !1,
      encoder: e.encode,
      encodeValuesOnly: !1,
      filter: void 0,
      format: p,
      formatter: i.formatters[p],
      indices: !1,
      serializeDate: function (_) {
        return m.call(_);
      },
      skipNulls: !1,
      strictNullHandling: !1,
    },
    v = function (_) {
      return (
        typeof _ == "string" ||
        typeof _ == "number" ||
        typeof _ == "boolean" ||
        typeof _ == "symbol" ||
        typeof _ == "bigint"
      );
    },
    x = {},
    w = function k(
      _,
      A,
      b,
      N,
      U,
      z,
      H,
      G,
      Q,
      me,
      ae,
      xe,
      te,
      _e,
      Ae,
      ke,
      be,
      Se
    ) {
      for (
        var D = _, J = Se, X = 0, R = !1;
        (J = J.get(x)) !== void 0 && !R;

      ) {
        var B = J.get(_);
        if (((X += 1), typeof B < "u")) {
          if (B === X) throw new RangeError("Cyclic object value");
          R = !0;
        }
        typeof J.get(x) > "u" && (X = 0);
      }
      if (
        (typeof me == "function"
          ? (D = me(A, D))
          : D instanceof Date
          ? (D = te(D))
          : b === "comma" &&
            c(D) &&
            (D = e.maybeMap(D, function (_t) {
              return _t instanceof Date ? te(_t) : _t;
            })),
        D === null)
      ) {
        if (z) return Q && !ke ? Q(A, g.encoder, be, "key", _e) : A;
        D = "";
      }
      if (v(D) || e.isBuffer(D)) {
        if (Q) {
          var le = ke ? A : Q(A, g.encoder, be, "key", _e);
          return [Ae(le) + "=" + Ae(Q(D, g.encoder, be, "value", _e))];
        }
        return [Ae(A) + "=" + Ae(String(D))];
      }
      var he = [];
      if (typeof D > "u") return he;
      var W;
      if (b === "comma" && c(D))
        ke && Q && (D = e.maybeMap(D, Q)),
          (W = [{ value: D.length > 0 ? D.join(",") || null : void 0 }]);
      else if (c(me)) W = me;
      else {
        var re = Object.keys(D);
        W = ae ? re.sort(ae) : re;
      }
      var Y = G ? String(A).replace(/\./g, "%2E") : String(A),
        ue = N && c(D) && D.length === 1 ? Y + "[]" : Y;
      if (U && c(D) && D.length === 0) return ue + "[]";
      for (var ne = 0; ne < W.length; ++ne) {
        var de = W[ne],
          ve =
            typeof de == "object" && de && typeof de.value < "u"
              ? de.value
              : D[de];
        if (!(H && ve === null)) {
          var Ie = xe && G ? String(de).replace(/\./g, "%2E") : String(de),
            Ue = c(D)
              ? typeof b == "function"
                ? b(ue, Ie)
                : ue
              : ue + (xe ? "." + Ie : "[" + Ie + "]");
          Se.set(_, X);
          var Ye = r();
          Ye.set(x, Se),
            d(
              he,
              k(
                ve,
                Ue,
                b,
                N,
                U,
                z,
                H,
                G,
                b === "comma" && ke && c(D) ? null : Q,
                me,
                ae,
                xe,
                te,
                _e,
                Ae,
                ke,
                be,
                Ye
              )
            );
        }
      }
      return he;
    },
    E = function (_) {
      if (!_) return g;
      if (
        typeof _.allowEmptyArrays < "u" &&
        typeof _.allowEmptyArrays != "boolean"
      )
        throw new TypeError(
          "`allowEmptyArrays` option can only be `true` or `false`, when provided"
        );
      if (
        typeof _.encodeDotInKeys < "u" &&
        typeof _.encodeDotInKeys != "boolean"
      )
        throw new TypeError(
          "`encodeDotInKeys` option can only be `true` or `false`, when provided"
        );
      if (
        _.encoder !== null &&
        typeof _.encoder < "u" &&
        typeof _.encoder != "function"
      )
        throw new TypeError("Encoder has to be a function.");
      var A = _.charset || g.charset;
      if (
        typeof _.charset < "u" &&
        _.charset !== "utf-8" &&
        _.charset !== "iso-8859-1"
      )
        throw new TypeError(
          "The charset option must be either utf-8, iso-8859-1, or undefined"
        );
      var b = i.default;
      if (typeof _.format < "u") {
        if (!o.call(i.formatters, _.format))
          throw new TypeError("Unknown format option provided.");
        b = _.format;
      }
      var N = i.formatters[b],
        U = g.filter;
      (typeof _.filter == "function" || c(_.filter)) && (U = _.filter);
      var z;
      if (
        (_.arrayFormat in l
          ? (z = _.arrayFormat)
          : "indices" in _
          ? (z = _.indices ? "indices" : "repeat")
          : (z = g.arrayFormat),
        "commaRoundTrip" in _ && typeof _.commaRoundTrip != "boolean")
      )
        throw new TypeError("`commaRoundTrip` must be a boolean, or absent");
      var H =
        typeof _.allowDots > "u"
          ? _.encodeDotInKeys === !0
            ? !0
            : g.allowDots
          : !!_.allowDots;
      return {
        addQueryPrefix:
          typeof _.addQueryPrefix == "boolean"
            ? _.addQueryPrefix
            : g.addQueryPrefix,
        allowDots: H,
        allowEmptyArrays:
          typeof _.allowEmptyArrays == "boolean"
            ? !!_.allowEmptyArrays
            : g.allowEmptyArrays,
        arrayFormat: z,
        charset: A,
        charsetSentinel:
          typeof _.charsetSentinel == "boolean"
            ? _.charsetSentinel
            : g.charsetSentinel,
        commaRoundTrip: !!_.commaRoundTrip,
        delimiter: typeof _.delimiter > "u" ? g.delimiter : _.delimiter,
        encode: typeof _.encode == "boolean" ? _.encode : g.encode,
        encodeDotInKeys:
          typeof _.encodeDotInKeys == "boolean"
            ? _.encodeDotInKeys
            : g.encodeDotInKeys,
        encoder: typeof _.encoder == "function" ? _.encoder : g.encoder,
        encodeValuesOnly:
          typeof _.encodeValuesOnly == "boolean"
            ? _.encodeValuesOnly
            : g.encodeValuesOnly,
        filter: U,
        format: b,
        formatter: N,
        serializeDate:
          typeof _.serializeDate == "function"
            ? _.serializeDate
            : g.serializeDate,
        skipNulls: typeof _.skipNulls == "boolean" ? _.skipNulls : g.skipNulls,
        sort: typeof _.sort == "function" ? _.sort : null,
        strictNullHandling:
          typeof _.strictNullHandling == "boolean"
            ? _.strictNullHandling
            : g.strictNullHandling,
      };
    };
  return (
    (rc = function (k, _) {
      var A = k,
        b = E(_),
        N,
        U;
      typeof b.filter == "function"
        ? ((U = b.filter), (A = U("", A)))
        : c(b.filter) && ((U = b.filter), (N = U));
      var z = [];
      if (typeof A != "object" || A === null) return "";
      var H = l[b.arrayFormat],
        G = H === "comma" && b.commaRoundTrip;
      N || (N = Object.keys(A)), b.sort && N.sort(b.sort);
      for (var Q = r(), me = 0; me < N.length; ++me) {
        var ae = N[me],
          xe = A[ae];
        (b.skipNulls && xe === null) ||
          d(
            z,
            w(
              xe,
              ae,
              H,
              G,
              b.allowEmptyArrays,
              b.strictNullHandling,
              b.skipNulls,
              b.encodeDotInKeys,
              b.encode ? b.encoder : null,
              b.filter,
              b.sort,
              b.allowDots,
              b.serializeDate,
              b.format,
              b.formatter,
              b.encodeValuesOnly,
              b.charset,
              Q
            )
          );
      }
      var te = z.join(b.delimiter),
        _e = b.addQueryPrefix === !0 ? "?" : "";
      return (
        b.charsetSentinel &&
          (b.charset === "iso-8859-1"
            ? (_e += "utf8=%26%2310003%3B&")
            : (_e += "utf8=%E2%9C%93&")),
        te.length > 0 ? _e + te : ""
      );
    }),
    rc
  );
}
var nc, jp;
function Vw() {
  if (jp) return nc;
  jp = 1;
  var r = hy(),
    e = Object.prototype.hasOwnProperty,
    i = Array.isArray,
    o = {
      allowDots: !1,
      allowEmptyArrays: !1,
      allowPrototypes: !1,
      allowSparse: !1,
      arrayLimit: 20,
      charset: "utf-8",
      charsetSentinel: !1,
      comma: !1,
      decodeDotInKeys: !1,
      decoder: r.decode,
      delimiter: "&",
      depth: 5,
      duplicates: "combine",
      ignoreQueryPrefix: !1,
      interpretNumericEntities: !1,
      parameterLimit: 1e3,
      parseArrays: !0,
      plainObjects: !1,
      strictDepth: !1,
      strictNullHandling: !1,
      throwOnLimitExceeded: !1,
    },
    l = function (x) {
      return x.replace(/&#(\d+);/g, function (w, E) {
        return String.fromCharCode(parseInt(E, 10));
      });
    },
    c = function (x, w, E) {
      if (x && typeof x == "string" && w.comma && x.indexOf(",") > -1)
        return x.split(",");
      if (w.throwOnLimitExceeded && E >= w.arrayLimit)
        throw new RangeError(
          "Array limit exceeded. Only " +
            w.arrayLimit +
            " element" +
            (w.arrayLimit === 1 ? "" : "s") +
            " allowed in an array."
        );
      return x;
    },
    f = "utf8=%26%2310003%3B",
    d = "utf8=%E2%9C%93",
    m = function (w, E) {
      var k = { __proto__: null },
        _ = E.ignoreQueryPrefix ? w.replace(/^\?/, "") : w;
      _ = _.replace(/%5B/gi, "[").replace(/%5D/gi, "]");
      var A = E.parameterLimit === 1 / 0 ? void 0 : E.parameterLimit,
        b = _.split(E.delimiter, E.throwOnLimitExceeded ? A + 1 : A);
      if (E.throwOnLimitExceeded && b.length > A)
        throw new RangeError(
          "Parameter limit exceeded. Only " +
            A +
            " parameter" +
            (A === 1 ? "" : "s") +
            " allowed."
        );
      var N = -1,
        U,
        z = E.charset;
      if (E.charsetSentinel)
        for (U = 0; U < b.length; ++U)
          b[U].indexOf("utf8=") === 0 &&
            (b[U] === d ? (z = "utf-8") : b[U] === f && (z = "iso-8859-1"),
            (N = U),
            (U = b.length));
      for (U = 0; U < b.length; ++U)
        if (U !== N) {
          var H = b[U],
            G = H.indexOf("]="),
            Q = G === -1 ? H.indexOf("=") : G + 1,
            me,
            ae;
          Q === -1
            ? ((me = E.decoder(H, o.decoder, z, "key")),
              (ae = E.strictNullHandling ? null : ""))
            : ((me = E.decoder(H.slice(0, Q), o.decoder, z, "key")),
              (ae = r.maybeMap(
                c(H.slice(Q + 1), E, i(k[me]) ? k[me].length : 0),
                function (te) {
                  return E.decoder(te, o.decoder, z, "value");
                }
              ))),
            ae &&
              E.interpretNumericEntities &&
              z === "iso-8859-1" &&
              (ae = l(String(ae))),
            H.indexOf("[]=") > -1 && (ae = i(ae) ? [ae] : ae);
          var xe = e.call(k, me);
          xe && E.duplicates === "combine"
            ? (k[me] = r.combine(k[me], ae))
            : (!xe || E.duplicates === "last") && (k[me] = ae);
        }
      return k;
    },
    p = function (x, w, E, k) {
      var _ = 0;
      if (x.length > 0 && x[x.length - 1] === "[]") {
        var A = x.slice(0, -1).join("");
        _ = Array.isArray(w) && w[A] ? w[A].length : 0;
      }
      for (var b = k ? w : c(w, E, _), N = x.length - 1; N >= 0; --N) {
        var U,
          z = x[N];
        if (z === "[]" && E.parseArrays)
          U =
            E.allowEmptyArrays &&
            (b === "" || (E.strictNullHandling && b === null))
              ? []
              : r.combine([], b);
        else {
          U = E.plainObjects ? { __proto__: null } : {};
          var H =
              z.charAt(0) === "[" && z.charAt(z.length - 1) === "]"
                ? z.slice(1, -1)
                : z,
            G = E.decodeDotInKeys ? H.replace(/%2E/g, ".") : H,
            Q = parseInt(G, 10);
          !E.parseArrays && G === ""
            ? (U = { 0: b })
            : !isNaN(Q) &&
              z !== G &&
              String(Q) === G &&
              Q >= 0 &&
              E.parseArrays &&
              Q <= E.arrayLimit
            ? ((U = []), (U[Q] = b))
            : G !== "__proto__" && (U[G] = b);
        }
        b = U;
      }
      return b;
    },
    g = function (w, E, k, _) {
      if (w) {
        var A = k.allowDots ? w.replace(/\.([^.[]+)/g, "[$1]") : w,
          b = /(\[[^[\]]*])/,
          N = /(\[[^[\]]*])/g,
          U = k.depth > 0 && b.exec(A),
          z = U ? A.slice(0, U.index) : A,
          H = [];
        if (z) {
          if (
            !k.plainObjects &&
            e.call(Object.prototype, z) &&
            !k.allowPrototypes
          )
            return;
          H.push(z);
        }
        for (
          var G = 0;
          k.depth > 0 && (U = N.exec(A)) !== null && G < k.depth;

        ) {
          if (
            ((G += 1),
            !k.plainObjects &&
              e.call(Object.prototype, U[1].slice(1, -1)) &&
              !k.allowPrototypes)
          )
            return;
          H.push(U[1]);
        }
        if (U) {
          if (k.strictDepth === !0)
            throw new RangeError(
              "Input depth exceeded depth option of " +
                k.depth +
                " and strictDepth is true"
            );
          H.push("[" + A.slice(U.index) + "]");
        }
        return p(H, E, k, _);
      }
    },
    v = function (w) {
      if (!w) return o;
      if (
        typeof w.allowEmptyArrays < "u" &&
        typeof w.allowEmptyArrays != "boolean"
      )
        throw new TypeError(
          "`allowEmptyArrays` option can only be `true` or `false`, when provided"
        );
      if (
        typeof w.decodeDotInKeys < "u" &&
        typeof w.decodeDotInKeys != "boolean"
      )
        throw new TypeError(
          "`decodeDotInKeys` option can only be `true` or `false`, when provided"
        );
      if (
        w.decoder !== null &&
        typeof w.decoder < "u" &&
        typeof w.decoder != "function"
      )
        throw new TypeError("Decoder has to be a function.");
      if (
        typeof w.charset < "u" &&
        w.charset !== "utf-8" &&
        w.charset !== "iso-8859-1"
      )
        throw new TypeError(
          "The charset option must be either utf-8, iso-8859-1, or undefined"
        );
      if (
        typeof w.throwOnLimitExceeded < "u" &&
        typeof w.throwOnLimitExceeded != "boolean"
      )
        throw new TypeError("`throwOnLimitExceeded` option must be a boolean");
      var E = typeof w.charset > "u" ? o.charset : w.charset,
        k = typeof w.duplicates > "u" ? o.duplicates : w.duplicates;
      if (k !== "combine" && k !== "first" && k !== "last")
        throw new TypeError(
          "The duplicates option must be either combine, first, or last"
        );
      var _ =
        typeof w.allowDots > "u"
          ? w.decodeDotInKeys === !0
            ? !0
            : o.allowDots
          : !!w.allowDots;
      return {
        allowDots: _,
        allowEmptyArrays:
          typeof w.allowEmptyArrays == "boolean"
            ? !!w.allowEmptyArrays
            : o.allowEmptyArrays,
        allowPrototypes:
          typeof w.allowPrototypes == "boolean"
            ? w.allowPrototypes
            : o.allowPrototypes,
        allowSparse:
          typeof w.allowSparse == "boolean" ? w.allowSparse : o.allowSparse,
        arrayLimit:
          typeof w.arrayLimit == "number" ? w.arrayLimit : o.arrayLimit,
        charset: E,
        charsetSentinel:
          typeof w.charsetSentinel == "boolean"
            ? w.charsetSentinel
            : o.charsetSentinel,
        comma: typeof w.comma == "boolean" ? w.comma : o.comma,
        decodeDotInKeys:
          typeof w.decodeDotInKeys == "boolean"
            ? w.decodeDotInKeys
            : o.decodeDotInKeys,
        decoder: typeof w.decoder == "function" ? w.decoder : o.decoder,
        delimiter:
          typeof w.delimiter == "string" || r.isRegExp(w.delimiter)
            ? w.delimiter
            : o.delimiter,
        depth:
          typeof w.depth == "number" || w.depth === !1 ? +w.depth : o.depth,
        duplicates: k,
        ignoreQueryPrefix: w.ignoreQueryPrefix === !0,
        interpretNumericEntities:
          typeof w.interpretNumericEntities == "boolean"
            ? w.interpretNumericEntities
            : o.interpretNumericEntities,
        parameterLimit:
          typeof w.parameterLimit == "number"
            ? w.parameterLimit
            : o.parameterLimit,
        parseArrays: w.parseArrays !== !1,
        plainObjects:
          typeof w.plainObjects == "boolean" ? w.plainObjects : o.plainObjects,
        strictDepth:
          typeof w.strictDepth == "boolean" ? !!w.strictDepth : o.strictDepth,
        strictNullHandling:
          typeof w.strictNullHandling == "boolean"
            ? w.strictNullHandling
            : o.strictNullHandling,
        throwOnLimitExceeded:
          typeof w.throwOnLimitExceeded == "boolean"
            ? w.throwOnLimitExceeded
            : !1,
      };
    };
  return (
    (nc = function (x, w) {
      var E = v(w);
      if (x === "" || x === null || typeof x > "u")
        return E.plainObjects ? { __proto__: null } : {};
      for (
        var k = typeof x == "string" ? m(x, E) : x,
          _ = E.plainObjects ? { __proto__: null } : {},
          A = Object.keys(k),
          b = 0;
        b < A.length;
        ++b
      ) {
        var N = A[b],
          U = g(N, k[N], E, typeof x == "string");
        _ = r.merge(_, U, E);
      }
      return E.allowSparse === !0 ? _ : r.compact(_);
    }),
    nc
  );
}
var ic, $p;
function Gw() {
  if ($p) return ic;
  $p = 1;
  var r = qw(),
    e = Vw(),
    i = Zc();
  return (ic = { formats: i, parse: e, stringify: r }), ic;
}
var zp = Gw();
function Ww(r) {
  return typeof r == "symbol" || r instanceof Symbol;
}
function Xw() {}
function Yw(r) {
  return r == null || (typeof r != "object" && typeof r != "function");
}
function Qw(r) {
  return ArrayBuffer.isView(r) && !(r instanceof DataView);
}
function bc(r) {
  return Object.getOwnPropertySymbols(r).filter((e) =>
    Object.prototype.propertyIsEnumerable.call(r, e)
  );
}
function fa(r) {
  return r == null
    ? r === void 0
      ? "[object Undefined]"
      : "[object Null]"
    : Object.prototype.toString.call(r);
}
const dy = "[object RegExp]",
  py = "[object String]",
  my = "[object Number]",
  yy = "[object Boolean]",
  Tc = "[object Arguments]",
  gy = "[object Symbol]",
  vy = "[object Date]",
  _y = "[object Map]",
  wy = "[object Set]",
  xy = "[object Array]",
  Kw = "[object Function]",
  Sy = "[object ArrayBuffer]",
  sa = "[object Object]",
  Jw = "[object Error]",
  Ey = "[object DataView]",
  Py = "[object Uint8Array]",
  Ay = "[object Uint8ClampedArray]",
  Cy = "[object Uint16Array]",
  ky = "[object Uint32Array]",
  Zw = "[object BigUint64Array]",
  Ry = "[object Int8Array]",
  by = "[object Int16Array]",
  Ty = "[object Int32Array]",
  e1 = "[object BigInt64Array]",
  Oy = "[object Float32Array]",
  My = "[object Float64Array]";
function Si(r, e, i, o = new Map(), l = void 0) {
  const c = l?.(r, e, i, o);
  if (c != null) return c;
  if (Yw(r)) return r;
  if (o.has(r)) return o.get(r);
  if (Array.isArray(r)) {
    const f = new Array(r.length);
    o.set(r, f);
    for (let d = 0; d < r.length; d++) f[d] = Si(r[d], d, i, o, l);
    return (
      Object.hasOwn(r, "index") && (f.index = r.index),
      Object.hasOwn(r, "input") && (f.input = r.input),
      f
    );
  }
  if (r instanceof Date) return new Date(r.getTime());
  if (r instanceof RegExp) {
    const f = new RegExp(r.source, r.flags);
    return (f.lastIndex = r.lastIndex), f;
  }
  if (r instanceof Map) {
    const f = new Map();
    o.set(r, f);
    for (const [d, m] of r) f.set(d, Si(m, d, i, o, l));
    return f;
  }
  if (r instanceof Set) {
    const f = new Set();
    o.set(r, f);
    for (const d of r) f.add(Si(d, void 0, i, o, l));
    return f;
  }
  if (typeof Buffer < "u" && Buffer.isBuffer(r)) return r.subarray();
  if (Qw(r)) {
    const f = new (Object.getPrototypeOf(r).constructor)(r.length);
    o.set(r, f);
    for (let d = 0; d < r.length; d++) f[d] = Si(r[d], d, i, o, l);
    return f;
  }
  if (
    r instanceof ArrayBuffer ||
    (typeof SharedArrayBuffer < "u" && r instanceof SharedArrayBuffer)
  )
    return r.slice(0);
  if (r instanceof DataView) {
    const f = new DataView(r.buffer.slice(0), r.byteOffset, r.byteLength);
    return o.set(r, f), ys(f, r, i, o, l), f;
  }
  if (typeof File < "u" && r instanceof File) {
    const f = new File([r], r.name, { type: r.type });
    return o.set(r, f), ys(f, r, i, o, l), f;
  }
  if (r instanceof Blob) {
    const f = new Blob([r], { type: r.type });
    return o.set(r, f), ys(f, r, i, o, l), f;
  }
  if (r instanceof Error) {
    const f = new r.constructor();
    return (
      o.set(r, f),
      (f.message = r.message),
      (f.name = r.name),
      (f.stack = r.stack),
      (f.cause = r.cause),
      ys(f, r, i, o, l),
      f
    );
  }
  if (typeof r == "object" && t1(r)) {
    const f = Object.create(Object.getPrototypeOf(r));
    return o.set(r, f), ys(f, r, i, o, l), f;
  }
  return r;
}
function ys(r, e, i = r, o, l) {
  const c = [...Object.keys(e), ...bc(e)];
  for (let f = 0; f < c.length; f++) {
    const d = c[f],
      m = Object.getOwnPropertyDescriptor(r, d);
    (m == null || m.writable) && (r[d] = Si(e[d], d, i, o, l));
  }
}
function t1(r) {
  switch (fa(r)) {
    case Tc:
    case xy:
    case Sy:
    case Ey:
    case yy:
    case vy:
    case Oy:
    case My:
    case Ry:
    case by:
    case Ty:
    case _y:
    case my:
    case sa:
    case dy:
    case wy:
    case py:
    case gy:
    case Py:
    case Ay:
    case Cy:
    case ky:
      return !0;
    default:
      return !1;
  }
}
function _s(r) {
  return Si(r, void 0, r, new Map(), void 0);
}
function Hp(r) {
  if (!r || typeof r != "object") return !1;
  const e = Object.getPrototypeOf(r);
  return e === null ||
    e === Object.prototype ||
    Object.getPrototypeOf(e) === null
    ? Object.prototype.toString.call(r) === "[object Object]"
    : !1;
}
function ha(r) {
  return r === "__proto__";
}
function Iy(r, e) {
  return r === e || (Number.isNaN(r) && Number.isNaN(e));
}
function r1(r, e, i) {
  return ws(r, e, void 0, void 0, void 0, void 0, i);
}
function ws(r, e, i, o, l, c, f) {
  const d = f(r, e, i, o, l, c);
  if (d !== void 0) return d;
  if (typeof r == typeof e)
    switch (typeof r) {
      case "bigint":
      case "string":
      case "boolean":
      case "symbol":
      case "undefined":
        return r === e;
      case "number":
        return r === e || Object.is(r, e);
      case "function":
        return r === e;
      case "object":
        return Ps(r, e, c, f);
    }
  return Ps(r, e, c, f);
}
function Ps(r, e, i, o) {
  if (Object.is(r, e)) return !0;
  let l = fa(r),
    c = fa(e);
  if ((l === Tc && (l = sa), c === Tc && (c = sa), l !== c)) return !1;
  switch (l) {
    case py:
      return r.toString() === e.toString();
    case my: {
      const m = r.valueOf(),
        p = e.valueOf();
      return Iy(m, p);
    }
    case yy:
    case vy:
    case gy:
      return Object.is(r.valueOf(), e.valueOf());
    case dy:
      return r.source === e.source && r.flags === e.flags;
    case Kw:
      return r === e;
  }
  i = i ?? new Map();
  const f = i.get(r),
    d = i.get(e);
  if (f != null && d != null) return f === e;
  i.set(r, e), i.set(e, r);
  try {
    switch (l) {
      case _y: {
        if (r.size !== e.size) return !1;
        for (const [m, p] of r.entries())
          if (!e.has(m) || !ws(p, e.get(m), m, r, e, i, o)) return !1;
        return !0;
      }
      case wy: {
        if (r.size !== e.size) return !1;
        const m = Array.from(r.values()),
          p = Array.from(e.values());
        for (let g = 0; g < m.length; g++) {
          const v = m[g],
            x = p.findIndex((w) => ws(v, w, void 0, r, e, i, o));
          if (x === -1) return !1;
          p.splice(x, 1);
        }
        return !0;
      }
      case xy:
      case Py:
      case Ay:
      case Cy:
      case ky:
      case Zw:
      case Ry:
      case by:
      case Ty:
      case e1:
      case Oy:
      case My: {
        if (
          (typeof Buffer < "u" && Buffer.isBuffer(r) !== Buffer.isBuffer(e)) ||
          r.length !== e.length
        )
          return !1;
        for (let m = 0; m < r.length; m++)
          if (!ws(r[m], e[m], m, r, e, i, o)) return !1;
        return !0;
      }
      case Sy:
        return r.byteLength !== e.byteLength
          ? !1
          : Ps(new Uint8Array(r), new Uint8Array(e), i, o);
      case Ey:
        return r.byteLength !== e.byteLength || r.byteOffset !== e.byteOffset
          ? !1
          : Ps(new Uint8Array(r), new Uint8Array(e), i, o);
      case Jw:
        return r.name === e.name && r.message === e.message;
      case sa: {
        if (!(Ps(r.constructor, e.constructor, i, o) || (Hp(r) && Hp(e))))
          return !1;
        const p = [...Object.keys(r), ...bc(r)],
          g = [...Object.keys(e), ...bc(e)];
        if (p.length !== g.length) return !1;
        for (let v = 0; v < p.length; v++) {
          const x = p[v],
            w = r[x];
          if (!Object.hasOwn(e, x)) return !1;
          const E = e[x];
          if (!ws(w, E, x, r, e, i, o)) return !1;
        }
        return !0;
      }
      default:
        return !1;
    }
  } finally {
    i.delete(r), i.delete(e);
  }
}
function n1(r, e) {
  return r1(r, e, Xw);
}
const i1 = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};
function s1(r) {
  return r.replace(/[&<>"']/g, (e) => i1[e]);
}
function Oc(r, e) {
  let i;
  return function (...o) {
    clearTimeout(i), (i = setTimeout(() => r.apply(this, o), e));
  };
}
function cr(r, e) {
  return document.dispatchEvent(new CustomEvent(`inertia:${r}`, e));
}
var qp = (r) => cr("before", { cancelable: !0, detail: { visit: r } }),
  o1 = (r) => cr("error", { detail: { errors: r } }),
  a1 = (r) => cr("exception", { cancelable: !0, detail: { exception: r } }),
  l1 = (r) => cr("finish", { detail: { visit: r } }),
  u1 = (r) => cr("invalid", { cancelable: !0, detail: { response: r } }),
  As = (r) => cr("navigate", { detail: { page: r } }),
  c1 = (r) => cr("progress", { detail: { progress: r } }),
  f1 = (r) => cr("start", { detail: { visit: r } }),
  h1 = (r) => cr("success", { detail: { page: r } }),
  d1 = (r, e) =>
    cr("prefetched", {
      detail: { fetchedAt: Date.now(), response: r.data, visit: e },
    }),
  p1 = (r) => cr("prefetching", { detail: { visit: r } }),
  At = class {
    static set(r, e) {
      typeof window < "u" &&
        window.sessionStorage.setItem(r, JSON.stringify(e));
    }
    static get(r) {
      if (typeof window < "u")
        return JSON.parse(window.sessionStorage.getItem(r) || "null");
    }
    static merge(r, e) {
      const i = this.get(r);
      i === null ? this.set(r, e) : this.set(r, { ...i, ...e });
    }
    static remove(r) {
      typeof window < "u" && window.sessionStorage.removeItem(r);
    }
    static removeNested(r, e) {
      const i = this.get(r);
      i !== null && (delete i[e], this.set(r, i));
    }
    static exists(r) {
      try {
        return this.get(r) !== null;
      } catch {
        return !1;
      }
    }
    static clear() {
      typeof window < "u" && window.sessionStorage.clear();
    }
  };
At.locationVisitKey = "inertiaLocationVisit";
var m1 = async (r) => {
    if (typeof window > "u") throw new Error("Unable to encrypt history");
    const e = Ly(),
      i = await Fy(),
      o = await x1(i);
    if (!o) throw new Error("Unable to encrypt history");
    return await g1(e, o, r);
  },
  Ei = { key: "historyKey", iv: "historyIv" },
  y1 = async (r) => {
    const e = Ly(),
      i = await Fy();
    if (!i) throw new Error("Unable to decrypt history");
    return await v1(e, i, r);
  },
  g1 = async (r, e, i) => {
    if (typeof window > "u") throw new Error("Unable to encrypt history");
    if (typeof window.crypto.subtle > "u")
      return (
        console.warn(
          "Encryption is not supported in this environment. SSL is required."
        ),
        Promise.resolve(i)
      );
    const o = new TextEncoder(),
      l = JSON.stringify(i),
      c = new Uint8Array(l.length * 3),
      f = o.encodeInto(l, c);
    return window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: r },
      e,
      c.subarray(0, f.written)
    );
  },
  v1 = async (r, e, i) => {
    if (typeof window.crypto.subtle > "u")
      return (
        console.warn(
          "Decryption is not supported in this environment. SSL is required."
        ),
        Promise.resolve(i)
      );
    const o = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: r },
      e,
      i
    );
    return JSON.parse(new TextDecoder().decode(o));
  },
  Ly = () => {
    const r = At.get(Ei.iv);
    if (r) return new Uint8Array(r);
    const e = window.crypto.getRandomValues(new Uint8Array(12));
    return At.set(Ei.iv, Array.from(e)), e;
  },
  _1 = async () =>
    typeof window.crypto.subtle > "u"
      ? (console.warn(
          "Encryption is not supported in this environment. SSL is required."
        ),
        Promise.resolve(null))
      : window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, !0, [
          "encrypt",
          "decrypt",
        ]),
  w1 = async (r) => {
    if (typeof window.crypto.subtle > "u")
      return (
        console.warn(
          "Encryption is not supported in this environment. SSL is required."
        ),
        Promise.resolve()
      );
    const e = await window.crypto.subtle.exportKey("raw", r);
    At.set(Ei.key, Array.from(new Uint8Array(e)));
  },
  x1 = async (r) => {
    if (r) return r;
    const e = await _1();
    return e ? (await w1(e), e) : null;
  },
  Fy = async () => {
    const r = At.get(Ei.key);
    return r
      ? await window.crypto.subtle.importKey(
          "raw",
          new Uint8Array(r),
          { name: "AES-GCM", length: 256 },
          !0,
          ["encrypt", "decrypt"]
        )
      : null;
  },
  lr = class {
    static save() {
      Oe.saveScrollPositions(
        Array.from(this.regions()).map((r) => ({
          top: r.scrollTop,
          left: r.scrollLeft,
        }))
      );
    }
    static regions() {
      return document.querySelectorAll("[scroll-region]");
    }
    static reset() {
      const r = typeof window < "u" ? window.location.hash : null;
      r || window.scrollTo(0, 0),
        this.regions().forEach((e) => {
          typeof e.scrollTo == "function"
            ? e.scrollTo(0, 0)
            : ((e.scrollTop = 0), (e.scrollLeft = 0));
        }),
        this.save(),
        r &&
          setTimeout(() => {
            const e = document.getElementById(r.slice(1));
            e ? e.scrollIntoView() : window.scrollTo(0, 0);
          });
    }
    static restore(r) {
      this.restoreDocument(),
        this.regions().forEach((e, i) => {
          const o = r[i];
          o &&
            (typeof e.scrollTo == "function"
              ? e.scrollTo(o.left, o.top)
              : ((e.scrollTop = o.top), (e.scrollLeft = o.left)));
        });
    }
    static restoreDocument() {
      const r = Oe.getDocumentScrollPosition();
      typeof window < "u" && window.scrollTo(r.left, r.top);
    }
    static onScroll(r) {
      const e = r.target;
      typeof e.hasAttribute == "function" &&
        e.hasAttribute("scroll-region") &&
        this.save();
    }
    static onWindowScroll() {
      Oe.saveDocumentScrollPosition({
        top: window.scrollY,
        left: window.scrollX,
      });
    }
  };
function Mc(r) {
  return (
    r instanceof File ||
    r instanceof Blob ||
    (r instanceof FileList && r.length > 0) ||
    (r instanceof FormData && Array.from(r.values()).some((e) => Mc(e))) ||
    (typeof r == "object" && r !== null && Object.values(r).some((e) => Mc(e)))
  );
}
var Vp = (r) => r instanceof FormData;
function Ny(r, e = new FormData(), i = null) {
  r = r || {};
  for (const o in r)
    Object.prototype.hasOwnProperty.call(r, o) && By(e, Dy(i, o), r[o]);
  return e;
}
function Dy(r, e) {
  return r ? r + "[" + e + "]" : e;
}
function By(r, e, i) {
  if (Array.isArray(i))
    return Array.from(i.keys()).forEach((o) =>
      By(r, Dy(e, o.toString()), i[o])
    );
  if (i instanceof Date) return r.append(e, i.toISOString());
  if (i instanceof File) return r.append(e, i, i.name);
  if (i instanceof Blob) return r.append(e, i);
  if (typeof i == "boolean") return r.append(e, i ? "1" : "0");
  if (typeof i == "string") return r.append(e, i);
  if (typeof i == "number") return r.append(e, `${i}`);
  if (i == null) return r.append(e, "");
  Ny(i, r, e);
}
function yn(r) {
  return new URL(
    r.toString(),
    typeof window > "u" ? void 0 : window.location.toString()
  );
}
var S1 = (r, e, i, o, l) => {
  let c = typeof r == "string" ? yn(r) : r;
  if (((Mc(e) || o) && !Vp(e) && (e = Ny(e)), Vp(e))) return [c, e];
  const [f, d] = Uy(i, c, e, l);
  return [yn(f), d];
};
function Uy(r, e, i, o = "brackets") {
  const l = /^[a-z][a-z0-9+.-]*:\/\//i.test(e.toString()),
    c = l || e.toString().startsWith("/"),
    f = !c && !e.toString().startsWith("#") && !e.toString().startsWith("?"),
    d = /^[.]{1,2}([/]|$)/.test(e.toString()),
    m = e.toString().includes("?") || (r === "get" && Object.keys(i).length),
    p = e.toString().includes("#"),
    g = new URL(
      e.toString(),
      typeof window > "u" ? "http://localhost" : window.location.toString()
    );
  if (r === "get" && Object.keys(i).length) {
    const v = { ignoreQueryPrefix: !0, parseArrays: !1 };
    (g.search = zp.stringify(
      { ...zp.parse(g.search, v), ...i },
      { encodeValuesOnly: !0, arrayFormat: o }
    )),
      (i = {});
  }
  return [
    [
      l ? `${g.protocol}//${g.host}` : "",
      c ? g.pathname : "",
      f ? g.pathname.substring(d ? 0 : 1) : "",
      m ? g.search : "",
      p ? g.hash : "",
    ].join(""),
    i,
  ];
}
function da(r) {
  return (r = new URL(r.href)), (r.hash = ""), r;
}
var Gp = (r, e) => {
    r.hash && !e.hash && da(r).href === e.href && (e.hash = r.hash);
  },
  Ic = (r, e) => da(r).href === da(e).href,
  E1 = class {
    constructor() {
      (this.componentId = {}),
        (this.listeners = []),
        (this.isFirstPageLoad = !0),
        (this.cleared = !1);
    }
    init({ initialPage: r, swapComponent: e, resolveComponent: i }) {
      return (
        (this.page = r),
        (this.swapComponent = e),
        (this.resolveComponent = i),
        this
      );
    }
    set(
      r,
      { replace: e = !1, preserveScroll: i = !1, preserveState: o = !1 } = {}
    ) {
      this.componentId = {};
      const l = this.componentId;
      return (
        r.clearHistory && Oe.clear(),
        this.resolve(r.component).then((c) => {
          if (l !== this.componentId) return;
          r.rememberedState ?? (r.rememberedState = {});
          const f = typeof window < "u" ? window.location : new URL(r.url);
          return (
            (e = e || Ic(yn(r.url), f)),
            new Promise((d) => {
              e
                ? Oe.replaceState(r, () => d(null))
                : Oe.pushState(r, () => d(null));
            }).then(() => {
              const d = !this.isTheSame(r);
              return (
                (this.page = r),
                (this.cleared = !1),
                d && this.fireEventsFor("newComponent"),
                this.isFirstPageLoad && this.fireEventsFor("firstLoad"),
                (this.isFirstPageLoad = !1),
                this.swap({ component: c, page: r, preserveState: o }).then(
                  () => {
                    i || lr.reset(),
                      $n.fireInternalEvent("loadDeferredProps"),
                      e || As(r);
                  }
                )
              );
            })
          );
        })
      );
    }
    setQuietly(r, { preserveState: e = !1 } = {}) {
      return this.resolve(r.component).then(
        (i) => (
          (this.page = r),
          (this.cleared = !1),
          Oe.setCurrent(r),
          this.swap({ component: i, page: r, preserveState: e })
        )
      );
    }
    clear() {
      this.cleared = !0;
    }
    isCleared() {
      return this.cleared;
    }
    get() {
      return this.page;
    }
    merge(r) {
      this.page = { ...this.page, ...r };
    }
    setUrlHash(r) {
      this.page.url.includes(r) || (this.page.url += r);
    }
    remember(r) {
      this.page.rememberedState = r;
    }
    swap({ component: r, page: e, preserveState: i }) {
      return this.swapComponent({ component: r, page: e, preserveState: i });
    }
    resolve(r) {
      return Promise.resolve(this.resolveComponent(r));
    }
    isTheSame(r) {
      return this.page.component === r.component;
    }
    on(r, e) {
      return (
        this.listeners.push({ event: r, callback: e }),
        () => {
          this.listeners = this.listeners.filter(
            (i) => i.event !== r && i.callback !== e
          );
        }
      );
    }
    fireEventsFor(r) {
      this.listeners.filter((e) => e.event === r).forEach((e) => e.callback());
    }
  },
  pe = new E1(),
  jy = class {
    constructor() {
      (this.items = []), (this.processingPromise = null);
    }
    add(r) {
      return this.items.push(r), this.process();
    }
    process() {
      return (
        this.processingPromise ??
          (this.processingPromise = this.processNext().then(() => {
            this.processingPromise = null;
          })),
        this.processingPromise
      );
    }
    processNext() {
      const r = this.items.shift();
      return r
        ? Promise.resolve(r()).then(() => this.processNext())
        : Promise.resolve();
    }
  },
  xs = typeof window > "u",
  gs = new jy(),
  Wp = !xs && /CriOS/.test(window.navigator.userAgent),
  P1 = class {
    constructor() {
      (this.rememberedState = "rememberedState"),
        (this.scrollRegions = "scrollRegions"),
        (this.preserveUrl = !1),
        (this.current = {}),
        (this.initialState = null);
    }
    remember(r, e) {
      this.replaceState({
        ...pe.get(),
        rememberedState: { ...(pe.get()?.rememberedState ?? {}), [e]: r },
      });
    }
    restore(r) {
      if (!xs)
        return this.current[this.rememberedState]
          ? this.current[this.rememberedState]?.[r]
          : this.initialState?.[this.rememberedState]?.[r];
    }
    pushState(r, e = null) {
      if (!xs) {
        if (this.preserveUrl) {
          e && e();
          return;
        }
        (this.current = r),
          gs.add(() =>
            this.getPageData(r).then((i) => {
              const o = () => {
                this.doPushState({ page: i }, r.url), e && e();
              };
              Wp ? setTimeout(o) : o();
            })
          );
      }
    }
    getPageData(r) {
      return new Promise((e) => (r.encryptHistory ? m1(r).then(e) : e(r)));
    }
    processQueue() {
      return gs.process();
    }
    decrypt(r = null) {
      if (xs) return Promise.resolve(r ?? pe.get());
      const e = r ?? window.history.state?.page;
      return this.decryptPageData(e).then((i) => {
        if (!i) throw new Error("Unable to decrypt history");
        return (
          this.initialState === null
            ? (this.initialState = i ?? void 0)
            : (this.current = i ?? {}),
          i
        );
      });
    }
    decryptPageData(r) {
      return r instanceof ArrayBuffer ? y1(r) : Promise.resolve(r);
    }
    saveScrollPositions(r) {
      gs.add(() =>
        Promise.resolve().then(() => {
          window.history.state?.page &&
            this.doReplaceState({
              page: window.history.state.page,
              scrollRegions: r,
            });
        })
      );
    }
    saveDocumentScrollPosition(r) {
      gs.add(() =>
        Promise.resolve().then(() => {
          window.history.state?.page &&
            this.doReplaceState({
              page: window.history.state.page,
              documentScrollPosition: r,
            });
        })
      );
    }
    getScrollRegions() {
      return window.history.state?.scrollRegions || [];
    }
    getDocumentScrollPosition() {
      return (
        window.history.state?.documentScrollPosition || { top: 0, left: 0 }
      );
    }
    replaceState(r, e = null) {
      if ((pe.merge(r), !xs)) {
        if (this.preserveUrl) {
          e && e();
          return;
        }
        (this.current = r),
          gs.add(() =>
            this.getPageData(r).then((i) => {
              const o = () => {
                this.doReplaceState({ page: i }, r.url), e && e();
              };
              Wp ? setTimeout(o) : o();
            })
          );
      }
    }
    doReplaceState(r, e) {
      window.history.replaceState(
        {
          ...r,
          scrollRegions: r.scrollRegions ?? window.history.state?.scrollRegions,
          documentScrollPosition:
            r.documentScrollPosition ??
            window.history.state?.documentScrollPosition,
        },
        "",
        e
      );
    }
    doPushState(r, e) {
      window.history.pushState(r, "", e);
    }
    getState(r, e) {
      return this.current?.[r] ?? e;
    }
    deleteState(r) {
      this.current[r] !== void 0 &&
        (delete this.current[r], this.replaceState(this.current));
    }
    hasAnyState() {
      return !!this.getAllState();
    }
    clear() {
      At.remove(Ei.key), At.remove(Ei.iv);
    }
    setCurrent(r) {
      this.current = r;
    }
    isValidState(r) {
      return !!r.page;
    }
    getAllState() {
      return this.current;
    }
  };
typeof window < "u" &&
  window.history.scrollRestoration &&
  (window.history.scrollRestoration = "manual");
var Oe = new P1(),
  A1 = class {
    constructor() {
      this.internalListeners = [];
    }
    init() {
      typeof window < "u" &&
        (window.addEventListener(
          "popstate",
          this.handlePopstateEvent.bind(this)
        ),
        window.addEventListener(
          "scroll",
          Oc(lr.onWindowScroll.bind(lr), 100),
          !0
        )),
        typeof document < "u" &&
          document.addEventListener(
            "scroll",
            Oc(lr.onScroll.bind(lr), 100),
            !0
          );
    }
    onGlobalEvent(r, e) {
      const i = (o) => {
        const l = e(o);
        o.cancelable && !o.defaultPrevented && l === !1 && o.preventDefault();
      };
      return this.registerListener(`inertia:${r}`, i);
    }
    on(r, e) {
      return (
        this.internalListeners.push({ event: r, listener: e }),
        () => {
          this.internalListeners = this.internalListeners.filter(
            (i) => i.listener !== e
          );
        }
      );
    }
    onMissingHistoryItem() {
      pe.clear(), this.fireInternalEvent("missingHistoryItem");
    }
    fireInternalEvent(r) {
      this.internalListeners
        .filter((e) => e.event === r)
        .forEach((e) => e.listener());
    }
    registerListener(r, e) {
      return (
        document.addEventListener(r, e),
        () => document.removeEventListener(r, e)
      );
    }
    handlePopstateEvent(r) {
      const e = r.state || null;
      if (e === null) {
        const i = yn(pe.get().url);
        (i.hash = window.location.hash),
          Oe.replaceState({ ...pe.get(), url: i.href }),
          lr.reset();
        return;
      }
      if (!Oe.isValidState(e)) return this.onMissingHistoryItem();
      Oe.decrypt(e.page)
        .then((i) => {
          if (pe.get().version !== i.version) {
            this.onMissingHistoryItem();
            return;
          }
          Qt.cancelAll(),
            pe.setQuietly(i, { preserveState: !1 }).then(() => {
              window.requestAnimationFrame(() => {
                lr.restore(Oe.getScrollRegions());
              }),
                As(pe.get());
            });
        })
        .catch(() => {
          this.onMissingHistoryItem();
        });
    }
  },
  $n = new A1(),
  C1 = class {
    constructor() {
      this.type = this.resolveType();
    }
    resolveType() {
      return typeof window > "u"
        ? "navigate"
        : window.performance &&
          window.performance.getEntriesByType &&
          window.performance.getEntriesByType("navigation").length > 0
        ? window.performance.getEntriesByType("navigation")[0].type
        : "navigate";
    }
    get() {
      return this.type;
    }
    isBackForward() {
      return this.type === "back_forward";
    }
    isReload() {
      return this.type === "reload";
    }
  },
  sc = new C1(),
  k1 = class {
    static handle() {
      this.clearRememberedStateOnReload(),
        [this.handleBackForward, this.handleLocation, this.handleDefault].find(
          (e) => e.bind(this)()
        );
    }
    static clearRememberedStateOnReload() {
      sc.isReload() && Oe.deleteState(Oe.rememberedState);
    }
    static handleBackForward() {
      if (!sc.isBackForward() || !Oe.hasAnyState()) return !1;
      const r = Oe.getScrollRegions();
      return (
        Oe.decrypt()
          .then((e) => {
            pe.set(e, { preserveScroll: !0, preserveState: !0 }).then(() => {
              lr.restore(r), As(pe.get());
            });
          })
          .catch(() => {
            $n.onMissingHistoryItem();
          }),
        !0
      );
    }
    static handleLocation() {
      if (!At.exists(At.locationVisitKey)) return !1;
      const r = At.get(At.locationVisitKey) || {};
      return (
        At.remove(At.locationVisitKey),
        typeof window < "u" && pe.setUrlHash(window.location.hash),
        Oe.decrypt(pe.get())
          .then(() => {
            const e = Oe.getState(Oe.rememberedState, {}),
              i = Oe.getScrollRegions();
            pe.remember(e),
              pe
                .set(pe.get(), {
                  preserveScroll: r.preserveScroll,
                  preserveState: !0,
                })
                .then(() => {
                  r.preserveScroll && lr.restore(i), As(pe.get());
                });
          })
          .catch(() => {
            $n.onMissingHistoryItem();
          }),
        !0
      );
    }
    static handleDefault() {
      typeof window < "u" && pe.setUrlHash(window.location.hash),
        pe.set(pe.get(), { preserveScroll: !0, preserveState: !0 }).then(() => {
          sc.isReload() && lr.restore(Oe.getScrollRegions()), As(pe.get());
        });
    }
  },
  R1 = class {
    constructor(r, e, i) {
      (this.id = null),
        (this.throttle = !1),
        (this.keepAlive = !1),
        (this.cbCount = 0),
        (this.keepAlive = i.keepAlive ?? !1),
        (this.cb = e),
        (this.interval = r),
        (i.autoStart ?? !0) && this.start();
    }
    stop() {
      this.id && clearInterval(this.id);
    }
    start() {
      typeof window > "u" ||
        (this.stop(),
        (this.id = window.setInterval(() => {
          (!this.throttle || this.cbCount % 10 === 0) && this.cb(),
            this.throttle && this.cbCount++;
        }, this.interval)));
    }
    isInBackground(r) {
      (this.throttle = this.keepAlive ? !1 : r),
        this.throttle && (this.cbCount = 0);
    }
  },
  b1 = class {
    constructor() {
      (this.polls = []), this.setupVisibilityListener();
    }
    add(r, e, i) {
      const o = new R1(r, e, i);
      return (
        this.polls.push(o), { stop: () => o.stop(), start: () => o.start() }
      );
    }
    clear() {
      this.polls.forEach((r) => r.stop()), (this.polls = []);
    }
    setupVisibilityListener() {
      typeof document > "u" ||
        document.addEventListener(
          "visibilitychange",
          () => {
            this.polls.forEach((r) => r.isInBackground(document.hidden));
          },
          !1
        );
    }
  },
  T1 = new b1(),
  $y = (r, e, i) => {
    if (r === e) return !0;
    for (const o in r)
      if (!i.includes(o) && r[o] !== e[o] && !O1(r[o], e[o])) return !1;
    return !0;
  },
  O1 = (r, e) => {
    switch (typeof r) {
      case "object":
        return $y(r, e, []);
      case "function":
        return r.toString() === e.toString();
      default:
        return r === e;
    }
  },
  M1 = { ms: 1, s: 1e3, m: 1e3 * 60, h: 1e3 * 60 * 60, d: 1e3 * 60 * 60 * 24 },
  Xp = (r) => {
    if (typeof r == "number") return r;
    for (const [e, i] of Object.entries(M1))
      if (r.endsWith(e)) return parseFloat(r) * i;
    return parseInt(r);
  },
  I1 = class {
    constructor() {
      (this.cached = []),
        (this.inFlightRequests = []),
        (this.removalTimers = []),
        (this.currentUseId = null);
    }
    add(r, e, { cacheFor: i }) {
      if (this.findInFlight(r)) return Promise.resolve();
      const l = this.findCached(r);
      if (!r.fresh && l && l.staleTimestamp > Date.now())
        return Promise.resolve();
      const [c, f] = this.extractStaleValues(i),
        d = new Promise((m, p) => {
          e({
            ...r,
            onCancel: () => {
              this.remove(r), r.onCancel(), p();
            },
            onError: (g) => {
              this.remove(r), r.onError(g), p();
            },
            onPrefetching(g) {
              r.onPrefetching(g);
            },
            onPrefetched(g, v) {
              r.onPrefetched(g, v);
            },
            onPrefetchResponse(g) {
              m(g);
            },
          });
        }).then(
          (m) => (
            this.remove(r),
            this.cached.push({
              params: { ...r },
              staleTimestamp: Date.now() + c,
              response: d,
              singleUse: f === 0,
              timestamp: Date.now(),
              inFlight: !1,
            }),
            this.scheduleForRemoval(r, f),
            (this.inFlightRequests = this.inFlightRequests.filter(
              (p) => !this.paramsAreEqual(p.params, r)
            )),
            m.handlePrefetch(),
            m
          )
        );
      return (
        this.inFlightRequests.push({
          params: { ...r },
          response: d,
          staleTimestamp: null,
          inFlight: !0,
        }),
        d
      );
    }
    removeAll() {
      (this.cached = []),
        this.removalTimers.forEach((r) => {
          clearTimeout(r.timer);
        }),
        (this.removalTimers = []);
    }
    remove(r) {
      (this.cached = this.cached.filter(
        (e) => !this.paramsAreEqual(e.params, r)
      )),
        this.clearTimer(r);
    }
    extractStaleValues(r) {
      const [e, i] = this.cacheForToStaleAndExpires(r);
      return [Xp(e), Xp(i)];
    }
    cacheForToStaleAndExpires(r) {
      if (!Array.isArray(r)) return [r, r];
      switch (r.length) {
        case 0:
          return [0, 0];
        case 1:
          return [r[0], r[0]];
        default:
          return [r[0], r[1]];
      }
    }
    clearTimer(r) {
      const e = this.removalTimers.find((i) =>
        this.paramsAreEqual(i.params, r)
      );
      e &&
        (clearTimeout(e.timer),
        (this.removalTimers = this.removalTimers.filter((i) => i !== e)));
    }
    scheduleForRemoval(r, e) {
      if (!(typeof window > "u") && (this.clearTimer(r), e > 0)) {
        const i = window.setTimeout(() => this.remove(r), e);
        this.removalTimers.push({ params: r, timer: i });
      }
    }
    get(r) {
      return this.findCached(r) || this.findInFlight(r);
    }
    use(r, e) {
      const i = `${e.url.pathname}-${Date.now()}-${Math.random()
        .toString(36)
        .substring(7)}`;
      return (
        (this.currentUseId = i),
        r.response.then((o) => {
          if (this.currentUseId === i)
            return (
              o.mergeParams({ ...e, onPrefetched: () => {} }),
              this.removeSingleUseItems(e),
              o.handle()
            );
        })
      );
    }
    removeSingleUseItems(r) {
      this.cached = this.cached.filter((e) =>
        this.paramsAreEqual(e.params, r) ? !e.singleUse : !0
      );
    }
    findCached(r) {
      return this.cached.find((e) => this.paramsAreEqual(e.params, r)) || null;
    }
    findInFlight(r) {
      return (
        this.inFlightRequests.find((e) => this.paramsAreEqual(e.params, r)) ||
        null
      );
    }
    withoutPurposePrefetchHeader(r) {
      const e = _s(r);
      return e.headers.Purpose === "prefetch" && delete e.headers.Purpose, e;
    }
    paramsAreEqual(r, e) {
      return $y(
        this.withoutPurposePrefetchHeader(r),
        this.withoutPurposePrefetchHeader(e),
        [
          "showProgress",
          "replace",
          "prefetch",
          "onBefore",
          "onStart",
          "onProgress",
          "onFinish",
          "onCancel",
          "onSuccess",
          "onError",
          "onPrefetched",
          "onCancelToken",
          "onPrefetching",
          "async",
        ]
      );
    }
  },
  Fn = new I1(),
  L1 = class zy {
    constructor(e) {
      if (((this.callbacks = []), !e.prefetch)) this.params = e;
      else {
        const i = {
          onBefore: this.wrapCallback(e, "onBefore"),
          onStart: this.wrapCallback(e, "onStart"),
          onProgress: this.wrapCallback(e, "onProgress"),
          onFinish: this.wrapCallback(e, "onFinish"),
          onCancel: this.wrapCallback(e, "onCancel"),
          onSuccess: this.wrapCallback(e, "onSuccess"),
          onError: this.wrapCallback(e, "onError"),
          onCancelToken: this.wrapCallback(e, "onCancelToken"),
          onPrefetched: this.wrapCallback(e, "onPrefetched"),
          onPrefetching: this.wrapCallback(e, "onPrefetching"),
        };
        this.params = {
          ...e,
          ...i,
          onPrefetchResponse: e.onPrefetchResponse || (() => {}),
        };
      }
    }
    static create(e) {
      return new zy(e);
    }
    data() {
      return this.params.method === "get" ? null : this.params.data;
    }
    queryParams() {
      return this.params.method === "get" ? this.params.data : {};
    }
    isPartial() {
      return (
        this.params.only.length > 0 ||
        this.params.except.length > 0 ||
        this.params.reset.length > 0
      );
    }
    onCancelToken(e) {
      this.params.onCancelToken({ cancel: e });
    }
    markAsFinished() {
      (this.params.completed = !0),
        (this.params.cancelled = !1),
        (this.params.interrupted = !1);
    }
    markAsCancelled({ cancelled: e = !0, interrupted: i = !1 }) {
      this.params.onCancel(),
        (this.params.completed = !1),
        (this.params.cancelled = e),
        (this.params.interrupted = i);
    }
    wasCancelledAtAll() {
      return this.params.cancelled || this.params.interrupted;
    }
    onFinish() {
      this.params.onFinish(this.params);
    }
    onStart() {
      this.params.onStart(this.params);
    }
    onPrefetching() {
      this.params.onPrefetching(this.params);
    }
    onPrefetchResponse(e) {
      this.params.onPrefetchResponse && this.params.onPrefetchResponse(e);
    }
    all() {
      return this.params;
    }
    headers() {
      const e = { ...this.params.headers };
      this.isPartial() &&
        (e["X-Inertia-Partial-Component"] = pe.get().component);
      const i = this.params.only.concat(this.params.reset);
      return (
        i.length > 0 && (e["X-Inertia-Partial-Data"] = i.join(",")),
        this.params.except.length > 0 &&
          (e["X-Inertia-Partial-Except"] = this.params.except.join(",")),
        this.params.reset.length > 0 &&
          (e["X-Inertia-Reset"] = this.params.reset.join(",")),
        this.params.errorBag &&
          this.params.errorBag.length > 0 &&
          (e["X-Inertia-Error-Bag"] = this.params.errorBag),
        e
      );
    }
    setPreserveOptions(e) {
      (this.params.preserveScroll = this.resolvePreserveOption(
        this.params.preserveScroll,
        e
      )),
        (this.params.preserveState = this.resolvePreserveOption(
          this.params.preserveState,
          e
        ));
    }
    runCallbacks() {
      this.callbacks.forEach(({ name: e, args: i }) => {
        this.params[e](...i);
      });
    }
    merge(e) {
      this.params = { ...this.params, ...e };
    }
    wrapCallback(e, i) {
      return (...o) => {
        this.recordCallback(i, o), e[i](...o);
      };
    }
    recordCallback(e, i) {
      this.callbacks.push({ name: e, args: i });
    }
    resolvePreserveOption(e, i) {
      return typeof e == "function"
        ? e(i)
        : e === "errors"
        ? Object.keys(i.props.errors || {}).length > 0
        : e;
    }
  },
  F1 = {
    modal: null,
    listener: null,
    show(r) {
      typeof r == "object" &&
        (r = `All Inertia requests must receive a valid Inertia response, however a plain JSON response was received.<hr>${JSON.stringify(
          r
        )}`);
      const e = document.createElement("html");
      (e.innerHTML = r),
        e
          .querySelectorAll("a")
          .forEach((o) => o.setAttribute("target", "_top")),
        (this.modal = document.createElement("div")),
        (this.modal.style.position = "fixed"),
        (this.modal.style.width = "100vw"),
        (this.modal.style.height = "100vh"),
        (this.modal.style.padding = "50px"),
        (this.modal.style.boxSizing = "border-box"),
        (this.modal.style.backgroundColor = "rgba(0, 0, 0, .6)"),
        (this.modal.style.zIndex = 2e5),
        this.modal.addEventListener("click", () => this.hide());
      const i = document.createElement("iframe");
      if (
        ((i.style.backgroundColor = "white"),
        (i.style.borderRadius = "5px"),
        (i.style.width = "100%"),
        (i.style.height = "100%"),
        this.modal.appendChild(i),
        document.body.prepend(this.modal),
        (document.body.style.overflow = "hidden"),
        !i.contentWindow)
      )
        throw new Error("iframe not yet ready.");
      i.contentWindow.document.open(),
        i.contentWindow.document.write(e.outerHTML),
        i.contentWindow.document.close(),
        (this.listener = this.hideOnEscape.bind(this)),
        document.addEventListener("keydown", this.listener);
    },
    hide() {
      (this.modal.outerHTML = ""),
        (this.modal = null),
        (document.body.style.overflow = "visible"),
        document.removeEventListener("keydown", this.listener);
    },
    hideOnEscape(r) {
      r.keyCode === 27 && this.hide();
    },
  },
  N1 = new jy(),
  Yp = class Hy {
    constructor(e, i, o) {
      (this.requestParams = e), (this.response = i), (this.originatingPage = o);
    }
    static create(e, i, o) {
      return new Hy(e, i, o);
    }
    async handlePrefetch() {
      Ic(this.requestParams.all().url, window.location) && this.handle();
    }
    async handle() {
      return N1.add(() => this.process());
    }
    async process() {
      if (this.requestParams.all().prefetch)
        return (
          (this.requestParams.all().prefetch = !1),
          this.requestParams
            .all()
            .onPrefetched(this.response, this.requestParams.all()),
          d1(this.response, this.requestParams.all()),
          Promise.resolve()
        );
      if ((this.requestParams.runCallbacks(), !this.isInertiaResponse()))
        return this.handleNonInertiaResponse();
      await Oe.processQueue(),
        (Oe.preserveUrl = this.requestParams.all().preserveUrl),
        await this.setPage();
      const e = pe.get().props.errors || {};
      if (Object.keys(e).length > 0) {
        const i = this.getScopedErrors(e);
        return o1(i), this.requestParams.all().onError(i);
      }
      h1(pe.get()),
        await this.requestParams.all().onSuccess(pe.get()),
        (Oe.preserveUrl = !1);
    }
    mergeParams(e) {
      this.requestParams.merge(e);
    }
    async handleNonInertiaResponse() {
      if (this.isLocationVisit()) {
        const i = yn(this.getHeader("x-inertia-location"));
        return Gp(this.requestParams.all().url, i), this.locationVisit(i);
      }
      const e = {
        ...this.response,
        data: this.getDataFromResponse(this.response.data),
      };
      if (u1(e)) return F1.show(e.data);
    }
    isInertiaResponse() {
      return this.hasHeader("x-inertia");
    }
    hasStatus(e) {
      return this.response.status === e;
    }
    getHeader(e) {
      return this.response.headers[e];
    }
    hasHeader(e) {
      return this.getHeader(e) !== void 0;
    }
    isLocationVisit() {
      return this.hasStatus(409) && this.hasHeader("x-inertia-location");
    }
    locationVisit(e) {
      try {
        if (
          (At.set(At.locationVisitKey, {
            preserveScroll: this.requestParams.all().preserveScroll === !0,
          }),
          typeof window > "u")
        )
          return;
        Ic(window.location, e)
          ? window.location.reload()
          : (window.location.href = e.href);
      } catch {
        return !1;
      }
    }
    async setPage() {
      const e = this.getDataFromResponse(this.response.data);
      return this.shouldSetPage(e)
        ? (this.mergeProps(e),
          await this.setRememberedState(e),
          this.requestParams.setPreserveOptions(e),
          (e.url = Oe.preserveUrl ? pe.get().url : this.pageUrl(e)),
          pe.set(e, {
            replace: this.requestParams.all().replace,
            preserveScroll: this.requestParams.all().preserveScroll,
            preserveState: this.requestParams.all().preserveState,
          }))
        : Promise.resolve();
    }
    getDataFromResponse(e) {
      if (typeof e != "string") return e;
      try {
        return JSON.parse(e);
      } catch {
        return e;
      }
    }
    shouldSetPage(e) {
      if (
        !this.requestParams.all().async ||
        this.originatingPage.component !== e.component
      )
        return !0;
      if (this.originatingPage.component !== pe.get().component) return !1;
      const i = yn(this.originatingPage.url),
        o = yn(pe.get().url);
      return i.origin === o.origin && i.pathname === o.pathname;
    }
    pageUrl(e) {
      const i = yn(e.url);
      return (
        Gp(this.requestParams.all().url, i), i.pathname + i.search + i.hash
      );
    }
    mergeProps(e) {
      if (!this.requestParams.isPartial() || e.component !== pe.get().component)
        return;
      const i = e.mergeProps || [],
        o = e.deepMergeProps || [],
        l = e.matchPropsOn || [];
      i.forEach((c) => {
        const f = e.props[c];
        Array.isArray(f)
          ? (e.props[c] = this.mergeOrMatchItems(
              pe.get().props[c] || [],
              f,
              c,
              l
            ))
          : typeof f == "object" &&
            f !== null &&
            (e.props[c] = { ...(pe.get().props[c] || []), ...f });
      }),
        o.forEach((c) => {
          const f = e.props[c],
            d = pe.get().props[c],
            m = (p, g, v) =>
              Array.isArray(g)
                ? this.mergeOrMatchItems(p, g, v, l)
                : typeof g == "object" && g !== null
                ? Object.keys(g).reduce(
                    (x, w) => (
                      (x[w] = m(p ? p[w] : void 0, g[w], `${v}.${w}`)), x
                    ),
                    { ...p }
                  )
                : g;
          e.props[c] = m(d, f, c);
        }),
        (e.props = { ...pe.get().props, ...e.props });
    }
    mergeOrMatchItems(e, i, o, l) {
      const c = l.find((p) => p.split(".").slice(0, -1).join(".") === o);
      if (!c) return [...(Array.isArray(e) ? e : []), ...i];
      const f = c.split(".").pop() || "",
        d = Array.isArray(e) ? e : [],
        m = new Map();
      return (
        d.forEach((p) => {
          p && typeof p == "object" && f in p
            ? m.set(p[f], p)
            : m.set(Symbol(), p);
        }),
        i.forEach((p) => {
          p && typeof p == "object" && f in p
            ? m.set(p[f], p)
            : m.set(Symbol(), p);
        }),
        Array.from(m.values())
      );
    }
    async setRememberedState(e) {
      const i = await Oe.getState(Oe.rememberedState, {});
      this.requestParams.all().preserveState &&
        i &&
        e.component === pe.get().component &&
        (e.rememberedState = i);
    }
    getScopedErrors(e) {
      return this.requestParams.all().errorBag
        ? e[this.requestParams.all().errorBag || ""] || {}
        : e;
    }
  },
  Qp = class qy {
    constructor(e, i) {
      (this.page = i),
        (this.requestHasFinished = !1),
        (this.requestParams = L1.create(e)),
        (this.cancelToken = new AbortController());
    }
    static create(e, i) {
      return new qy(e, i);
    }
    async send() {
      this.requestParams.onCancelToken(() => this.cancel({ cancelled: !0 })),
        f1(this.requestParams.all()),
        this.requestParams.onStart(),
        this.requestParams.all().prefetch &&
          (this.requestParams.onPrefetching(), p1(this.requestParams.all()));
      const e = this.requestParams.all().prefetch;
      return $e({
        method: this.requestParams.all().method,
        url: da(this.requestParams.all().url).href,
        data: this.requestParams.data(),
        params: this.requestParams.queryParams(),
        signal: this.cancelToken.signal,
        headers: this.getHeaders(),
        onUploadProgress: this.onProgress.bind(this),
        responseType: "text",
      })
        .then(
          (i) => (
            (this.response = Yp.create(this.requestParams, i, this.page)),
            this.response.handle()
          )
        )
        .catch((i) =>
          i?.response
            ? ((this.response = Yp.create(
                this.requestParams,
                i.response,
                this.page
              )),
              this.response.handle())
            : Promise.reject(i)
        )
        .catch((i) => {
          if (!$e.isCancel(i) && a1(i)) return Promise.reject(i);
        })
        .finally(() => {
          this.finish(),
            e &&
              this.response &&
              this.requestParams.onPrefetchResponse(this.response);
        });
    }
    finish() {
      this.requestParams.wasCancelledAtAll() ||
        (this.requestParams.markAsFinished(), this.fireFinishEvents());
    }
    fireFinishEvents() {
      this.requestHasFinished ||
        ((this.requestHasFinished = !0),
        l1(this.requestParams.all()),
        this.requestParams.onFinish());
    }
    cancel({ cancelled: e = !1, interrupted: i = !1 }) {
      this.requestHasFinished ||
        (this.cancelToken.abort(),
        this.requestParams.markAsCancelled({ cancelled: e, interrupted: i }),
        this.fireFinishEvents());
    }
    onProgress(e) {
      this.requestParams.data() instanceof FormData &&
        ((e.percentage = e.progress ? Math.round(e.progress * 100) : 0),
        c1(e),
        this.requestParams.all().onProgress(e));
    }
    getHeaders() {
      const e = {
        ...this.requestParams.headers(),
        Accept: "text/html, application/xhtml+xml",
        "X-Requested-With": "XMLHttpRequest",
        "X-Inertia": !0,
      };
      return pe.get().version && (e["X-Inertia-Version"] = pe.get().version), e;
    }
  },
  Kp = class {
    constructor({ maxConcurrent: r, interruptible: e }) {
      (this.requests = []), (this.maxConcurrent = r), (this.interruptible = e);
    }
    send(r) {
      this.requests.push(r),
        r.send().then(() => {
          this.requests = this.requests.filter((e) => e !== r);
        });
    }
    interruptInFlight() {
      this.cancel({ interrupted: !0 }, !1);
    }
    cancelInFlight() {
      this.cancel({ cancelled: !0 }, !0);
    }
    cancel({ cancelled: r = !1, interrupted: e = !1 } = {}, i) {
      if (!this.shouldCancel(i)) return;
      this.requests.shift()?.cancel({ interrupted: e, cancelled: r });
    }
    shouldCancel(r) {
      return r
        ? !0
        : this.interruptible && this.requests.length >= this.maxConcurrent;
    }
  },
  D1 = class {
    constructor() {
      (this.syncRequestStream = new Kp({
        maxConcurrent: 1,
        interruptible: !0,
      })),
        (this.asyncRequestStream = new Kp({
          maxConcurrent: 1 / 0,
          interruptible: !1,
        }));
    }
    init({ initialPage: r, resolveComponent: e, swapComponent: i }) {
      pe.init({ initialPage: r, resolveComponent: e, swapComponent: i }),
        k1.handle(),
        $n.init(),
        $n.on("missingHistoryItem", () => {
          typeof window < "u" &&
            this.visit(window.location.href, {
              preserveState: !0,
              preserveScroll: !0,
              replace: !0,
            });
        }),
        $n.on("loadDeferredProps", () => {
          this.loadDeferredProps();
        });
    }
    get(r, e = {}, i = {}) {
      return this.visit(r, { ...i, method: "get", data: e });
    }
    post(r, e = {}, i = {}) {
      return this.visit(r, {
        preserveState: !0,
        ...i,
        method: "post",
        data: e,
      });
    }
    put(r, e = {}, i = {}) {
      return this.visit(r, { preserveState: !0, ...i, method: "put", data: e });
    }
    patch(r, e = {}, i = {}) {
      return this.visit(r, {
        preserveState: !0,
        ...i,
        method: "patch",
        data: e,
      });
    }
    delete(r, e = {}) {
      return this.visit(r, { preserveState: !0, ...e, method: "delete" });
    }
    reload(r = {}) {
      if (!(typeof window > "u"))
        return this.visit(window.location.href, {
          ...r,
          preserveScroll: !0,
          preserveState: !0,
          async: !0,
          headers: { ...(r.headers || {}), "Cache-Control": "no-cache" },
        });
    }
    remember(r, e = "default") {
      Oe.remember(r, e);
    }
    restore(r = "default") {
      return Oe.restore(r);
    }
    on(r, e) {
      return typeof window > "u" ? () => {} : $n.onGlobalEvent(r, e);
    }
    cancel() {
      this.syncRequestStream.cancelInFlight();
    }
    cancelAll() {
      this.asyncRequestStream.cancelInFlight(),
        this.syncRequestStream.cancelInFlight();
    }
    poll(r, e = {}, i = {}) {
      return T1.add(r, () => this.reload(e), {
        autoStart: i.autoStart ?? !0,
        keepAlive: i.keepAlive ?? !1,
      });
    }
    visit(r, e = {}) {
      const i = this.getPendingVisit(r, {
          ...e,
          showProgress: e.showProgress ?? !e.async,
        }),
        o = this.getVisitEvents(e);
      if (o.onBefore(i) === !1 || !qp(i)) return;
      const l = i.async ? this.asyncRequestStream : this.syncRequestStream;
      l.interruptInFlight(), !pe.isCleared() && !i.preserveUrl && lr.save();
      const c = { ...i, ...o },
        f = Fn.get(c);
      f
        ? (Jp(f.inFlight), Fn.use(f, c))
        : (Jp(!0), l.send(Qp.create(c, pe.get())));
    }
    getCached(r, e = {}) {
      return Fn.findCached(this.getPrefetchParams(r, e));
    }
    flush(r, e = {}) {
      Fn.remove(this.getPrefetchParams(r, e));
    }
    flushAll() {
      Fn.removeAll();
    }
    getPrefetching(r, e = {}) {
      return Fn.findInFlight(this.getPrefetchParams(r, e));
    }
    prefetch(r, e = {}, { cacheFor: i = 3e4 }) {
      if (e.method !== "get")
        throw new Error("Prefetch requests must use the GET method");
      const o = this.getPendingVisit(r, {
          ...e,
          async: !0,
          showProgress: !1,
          prefetch: !0,
        }),
        l = o.url.origin + o.url.pathname + o.url.search,
        c =
          window.location.origin +
          window.location.pathname +
          window.location.search;
      if (l === c) return;
      const f = this.getVisitEvents(e);
      if (f.onBefore(o) === !1 || !qp(o)) return;
      Ky(), this.asyncRequestStream.interruptInFlight();
      const d = { ...o, ...f };
      new Promise((p) => {
        const g = () => {
          pe.get() ? p() : setTimeout(g, 50);
        };
        g();
      }).then(() => {
        Fn.add(
          d,
          (p) => {
            this.asyncRequestStream.send(Qp.create(p, pe.get()));
          },
          { cacheFor: i }
        );
      });
    }
    clearHistory() {
      Oe.clear();
    }
    decryptHistory() {
      return Oe.decrypt();
    }
    resolveComponent(r) {
      return pe.resolve(r);
    }
    replace(r) {
      this.clientVisit(r, { replace: !0 });
    }
    push(r) {
      this.clientVisit(r);
    }
    clientVisit(r, { replace: e = !1 } = {}) {
      const i = pe.get(),
        o =
          typeof r.props == "function" ? r.props(i.props) : r.props ?? i.props,
        { onError: l, onFinish: c, onSuccess: f, ...d } = r;
      pe.set(
        { ...i, ...d, props: o },
        {
          replace: e,
          preserveScroll: r.preserveScroll,
          preserveState: r.preserveState,
        }
      )
        .then(() => {
          const m = pe.get().props.errors || {};
          if (Object.keys(m).length === 0) return f?.(pe.get());
          const p = r.errorBag ? m[r.errorBag || ""] || {} : m;
          return l?.(p);
        })
        .finally(() => c?.(r));
    }
    getPrefetchParams(r, e) {
      return {
        ...this.getPendingVisit(r, {
          ...e,
          async: !0,
          showProgress: !1,
          prefetch: !0,
        }),
        ...this.getVisitEvents(e),
      };
    }
    getPendingVisit(r, e, i = {}) {
      const o = {
          method: "get",
          data: {},
          replace: !1,
          preserveScroll: !1,
          preserveState: !1,
          only: [],
          except: [],
          headers: {},
          errorBag: "",
          forceFormData: !1,
          queryStringArrayFormat: "brackets",
          async: !1,
          showProgress: !0,
          fresh: !1,
          reset: [],
          preserveUrl: !1,
          prefetch: !1,
          ...e,
        },
        [l, c] = S1(
          r,
          o.data,
          o.method,
          o.forceFormData,
          o.queryStringArrayFormat
        ),
        f = {
          cancelled: !1,
          completed: !1,
          interrupted: !1,
          ...o,
          ...i,
          url: l,
          data: c,
        };
      return f.prefetch && (f.headers.Purpose = "prefetch"), f;
    }
    getVisitEvents(r) {
      return {
        onCancelToken: r.onCancelToken || (() => {}),
        onBefore: r.onBefore || (() => {}),
        onStart: r.onStart || (() => {}),
        onProgress: r.onProgress || (() => {}),
        onFinish: r.onFinish || (() => {}),
        onCancel: r.onCancel || (() => {}),
        onSuccess: r.onSuccess || (() => {}),
        onError: r.onError || (() => {}),
        onPrefetched: r.onPrefetched || (() => {}),
        onPrefetching: r.onPrefetching || (() => {}),
      };
    }
    loadDeferredProps() {
      const r = pe.get()?.deferredProps;
      r &&
        Object.entries(r).forEach(([e, i]) => {
          this.reload({ only: i });
        });
    }
  },
  B1 = {
    buildDOMElement(r) {
      const e = document.createElement("template");
      e.innerHTML = r;
      const i = e.content.firstChild;
      if (!r.startsWith("<script ")) return i;
      const o = document.createElement("script");
      return (
        (o.innerHTML = i.innerHTML),
        i.getAttributeNames().forEach((l) => {
          o.setAttribute(l, i.getAttribute(l) || "");
        }),
        o
      );
    },
    isInertiaManagedElement(r) {
      return (
        r.nodeType === Node.ELEMENT_NODE && r.getAttribute("inertia") !== null
      );
    },
    findMatchingElementIndex(r, e) {
      const i = r.getAttribute("inertia");
      return i !== null
        ? e.findIndex((o) => o.getAttribute("inertia") === i)
        : -1;
    },
    update: Oc(function (r) {
      const e = r.map((o) => this.buildDOMElement(o));
      Array.from(document.head.childNodes)
        .filter((o) => this.isInertiaManagedElement(o))
        .forEach((o) => {
          const l = this.findMatchingElementIndex(o, e);
          if (l === -1) {
            o?.parentNode?.removeChild(o);
            return;
          }
          const c = e.splice(l, 1)[0];
          c && !o.isEqualNode(c) && o?.parentNode?.replaceChild(c, o);
        }),
        e.forEach((o) => document.head.appendChild(o));
    }, 1),
  };
function U1(r, e, i) {
  const o = {};
  let l = 0;
  function c() {
    const v = (l += 1);
    return (o[v] = []), v.toString();
  }
  function f(v) {
    v === null || Object.keys(o).indexOf(v) === -1 || (delete o[v], g());
  }
  function d(v) {
    Object.keys(o).indexOf(v) === -1 && (o[v] = []);
  }
  function m(v, x = []) {
    v !== null && Object.keys(o).indexOf(v) > -1 && (o[v] = x), g();
  }
  function p() {
    const v = e(""),
      x = { ...(v ? { title: `<title inertia="">${v}</title>` } : {}) },
      w = Object.values(o)
        .reduce((E, k) => E.concat(k), [])
        .reduce((E, k) => {
          if (k.indexOf("<") === -1) return E;
          if (k.indexOf("<title ") === 0) {
            const A = k.match(/(<title [^>]+>)(.*?)(<\/title>)/);
            return (E.title = A ? `${A[1]}${e(A[2])}${A[3]}` : k), E;
          }
          const _ = k.match(/ inertia="[^"]+"/);
          return _ ? (E[_[0]] = k) : (E[Object.keys(E).length] = k), E;
        }, x);
    return Object.values(w);
  }
  function g() {
    r ? i(p()) : B1.update(p());
  }
  return (
    g(),
    {
      forceUpdate: g,
      createProvider: function () {
        const v = c();
        return {
          reconnect: () => d(v),
          update: (x) => m(v, x),
          disconnect: () => f(v),
        };
      },
    }
  );
}
var et = "nprogress",
  Xt,
  lt = {
    minimum: 0.08,
    easing: "linear",
    positionUsing: "translate3d",
    speed: 200,
    trickle: !0,
    trickleSpeed: 200,
    showSpinner: !0,
    barSelector: '[role="bar"]',
    spinnerSelector: '[role="spinner"]',
    parent: "body",
    color: "#29d",
    includeCSS: !0,
    template: [
      '<div class="bar" role="bar">',
      '<div class="peg"></div>',
      "</div>",
      '<div class="spinner" role="spinner">',
      '<div class="spinner-icon"></div>',
      "</div>",
    ].join(""),
  },
  _n = null,
  j1 = (r) => {
    Object.assign(lt, r),
      lt.includeCSS && G1(lt.color),
      (Xt = document.createElement("div")),
      (Xt.id = et),
      (Xt.innerHTML = lt.template);
  },
  Ca = (r) => {
    const e = Vy();
    (r = Qy(r, lt.minimum, 1)), (_n = r === 1 ? null : r);
    const i = z1(!e),
      o = i.querySelector(lt.barSelector),
      l = lt.speed,
      c = lt.easing;
    i.offsetWidth,
      V1((f) => {
        const d =
          lt.positionUsing === "translate3d"
            ? {
                transition: `all ${l}ms ${c}`,
                transform: `translate3d(${oa(r)}%,0,0)`,
              }
            : lt.positionUsing === "translate"
            ? {
                transition: `all ${l}ms ${c}`,
                transform: `translate(${oa(r)}%,0)`,
              }
            : { marginLeft: `${oa(r)}%` };
        for (const m in d) o.style[m] = d[m];
        if (r !== 1) return setTimeout(f, l);
        (i.style.transition = "none"),
          (i.style.opacity = "1"),
          i.offsetWidth,
          setTimeout(() => {
            (i.style.transition = `all ${l}ms linear`),
              (i.style.opacity = "0"),
              setTimeout(() => {
                Yy(), (i.style.transition = ""), (i.style.opacity = ""), f();
              }, l);
          }, l);
      });
  },
  Vy = () => typeof _n == "number",
  Gy = () => {
    _n || Ca(0);
    const r = function () {
      setTimeout(function () {
        _n && (Wy(), r());
      }, lt.trickleSpeed);
    };
    lt.trickle && r();
  },
  $1 = (r) => {
    (!r && !_n) || (Wy(0.3 + 0.5 * Math.random()), Ca(1));
  },
  Wy = (r) => {
    const e = _n;
    if (e === null) return Gy();
    if (!(e > 1))
      return (
        (r =
          typeof r == "number"
            ? r
            : (() => {
                const i = {
                  0.1: [0, 0.2],
                  0.04: [0.2, 0.5],
                  0.02: [0.5, 0.8],
                  0.005: [0.8, 0.99],
                };
                for (const o in i)
                  if (e >= i[o][0] && e < i[o][1]) return parseFloat(o);
                return 0;
              })()),
        Ca(Qy(e + r, 0, 0.994))
      );
  },
  z1 = (r) => {
    if (H1()) return document.getElementById(et);
    document.documentElement.classList.add(`${et}-busy`);
    const e = Xt.querySelector(lt.barSelector),
      i = r ? "-100" : oa(_n || 0),
      o = Xy();
    return (
      (e.style.transition = "all 0 linear"),
      (e.style.transform = `translate3d(${i}%,0,0)`),
      lt.showSpinner || Xt.querySelector(lt.spinnerSelector)?.remove(),
      o !== document.body && o.classList.add(`${et}-custom-parent`),
      o.appendChild(Xt),
      Xt
    );
  },
  Xy = () => (q1(lt.parent) ? lt.parent : document.querySelector(lt.parent)),
  Yy = () => {
    document.documentElement.classList.remove(`${et}-busy`),
      Xy().classList.remove(`${et}-custom-parent`),
      Xt?.remove();
  },
  H1 = () => document.getElementById(et) !== null,
  q1 = (r) =>
    typeof HTMLElement == "object"
      ? r instanceof HTMLElement
      : r &&
        typeof r == "object" &&
        r.nodeType === 1 &&
        typeof r.nodeName == "string";
function Qy(r, e, i) {
  return r < e ? e : r > i ? i : r;
}
var oa = (r) => (-1 + r) * 100,
  V1 = (() => {
    const r = [],
      e = () => {
        const i = r.shift();
        i && i(e);
      };
    return (i) => {
      r.push(i), r.length === 1 && e();
    };
  })(),
  G1 = (r) => {
    const e = document.createElement("style");
    (e.textContent = `
    #${et} {
      pointer-events: none;
    }

    #${et} .bar {
      background: ${r};

      position: fixed;
      z-index: 1031;
      top: 0;
      left: 0;

      width: 100%;
      height: 2px;
    }

    #${et} .peg {
      display: block;
      position: absolute;
      right: 0px;
      width: 100px;
      height: 100%;
      box-shadow: 0 0 10px ${r}, 0 0 5px ${r};
      opacity: 1.0;

      transform: rotate(3deg) translate(0px, -4px);
    }

    #${et} .spinner {
      display: block;
      position: fixed;
      z-index: 1031;
      top: 15px;
      right: 15px;
    }

    #${et} .spinner-icon {
      width: 18px;
      height: 18px;
      box-sizing: border-box;

      border: solid 2px transparent;
      border-top-color: ${r};
      border-left-color: ${r};
      border-radius: 50%;

      animation: ${et}-spinner 400ms linear infinite;
    }

    .${et}-custom-parent {
      overflow: hidden;
      position: relative;
    }

    .${et}-custom-parent #${et} .spinner,
    .${et}-custom-parent #${et} .bar {
      position: absolute;
    }

    @keyframes ${et}-spinner {
      0%   { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
  `),
      document.head.appendChild(e);
  },
  W1 = () => {
    Xt && (Xt.style.display = "");
  },
  X1 = () => {
    Xt && (Xt.style.display = "none");
  },
  Wt = {
    configure: j1,
    isStarted: Vy,
    done: $1,
    set: Ca,
    remove: Yy,
    start: Gy,
    status: _n,
    show: W1,
    hide: X1,
  },
  aa = 0,
  Jp = (r = !1) => {
    (aa = Math.max(0, aa - 1)), (r || aa === 0) && Wt.show();
  },
  Ky = () => {
    aa++, Wt.hide();
  };
function Y1(r) {
  document.addEventListener("inertia:start", (e) => Q1(e, r)),
    document.addEventListener("inertia:progress", K1);
}
function Q1(r, e) {
  r.detail.visit.showProgress || Ky();
  const i = setTimeout(() => Wt.start(), e);
  document.addEventListener("inertia:finish", (o) => J1(o, i), { once: !0 });
}
function K1(r) {
  Wt.isStarted() &&
    r.detail.progress?.percentage &&
    Wt.set(Math.max(Wt.status, (r.detail.progress.percentage / 100) * 0.9));
}
function J1(r, e) {
  clearTimeout(e),
    Wt.isStarted() &&
      (r.detail.visit.completed
        ? Wt.done()
        : r.detail.visit.interrupted
        ? Wt.set(0)
        : r.detail.visit.cancelled && (Wt.done(), Wt.remove()));
}
function Z1({
  delay: r = 250,
  color: e = "#29d",
  includeCSS: i = !0,
  showSpinner: o = !1,
} = {}) {
  Y1(r), Wt.configure({ showSpinner: o, includeCSS: i, color: e });
}
function oc(r) {
  const e = r.currentTarget.tagName.toLowerCase() === "a";
  return !(
    (r.target && (r?.target).isContentEditable) ||
    r.defaultPrevented ||
    (e && r.altKey) ||
    (e && r.ctrlKey) ||
    (e && r.metaKey) ||
    (e && r.shiftKey) ||
    (e && "button" in r && r.button !== 0)
  );
}
var Qt = new D1();
/* NProgress, (c) 2013, 2014 Rico Sta. Cruz - http://ricostacruz.com/nprogress
 * @license MIT */ var ee = Wc();
const Lc = Mm(ee),
  aE = T0({ __proto__: null, default: Lc }, [ee]);
function Jy(r) {
  switch (typeof r) {
    case "number":
    case "symbol":
      return !1;
    case "string":
      return r.includes(".") || r.includes("[") || r.includes("]");
  }
}
function Zy(r) {
  return typeof r == "string" || typeof r == "symbol"
    ? r
    : Object.is(r?.valueOf?.(), -0)
    ? "-0"
    : String(r);
}
function ef(r) {
  const e = [],
    i = r.length;
  if (i === 0) return e;
  let o = 0,
    l = "",
    c = "",
    f = !1;
  for (r.charCodeAt(0) === 46 && (e.push(""), o++); o < i; ) {
    const d = r[o];
    c
      ? d === "\\" && o + 1 < i
        ? (o++, (l += r[o]))
        : d === c
        ? (c = "")
        : (l += d)
      : f
      ? d === '"' || d === "'"
        ? (c = d)
        : d === "]"
        ? ((f = !1), e.push(l), (l = ""))
        : (l += d)
      : d === "["
      ? ((f = !0), l && (e.push(l), (l = "")))
      : d === "."
      ? l && (e.push(l), (l = ""))
      : (l += d),
      o++;
  }
  return l && e.push(l), e;
}
function eg(r, e, i) {
  if (r == null) return i;
  switch (typeof e) {
    case "string": {
      if (ha(e)) return i;
      const o = r[e];
      return o === void 0 ? (Jy(e) ? eg(r, ef(e), i) : i) : o;
    }
    case "number":
    case "symbol": {
      typeof e == "number" && (e = Zy(e));
      const o = r[e];
      return o === void 0 ? i : o;
    }
    default: {
      if (Array.isArray(e)) return ex(r, e, i);
      if ((Object.is(e?.valueOf(), -0) ? (e = "-0") : (e = String(e)), ha(e)))
        return i;
      const o = r[e];
      return o === void 0 ? i : o;
    }
  }
}
function ex(r, e, i) {
  if (e.length === 0) return i;
  let o = r;
  for (let l = 0; l < e.length; l++) {
    if (o == null || ha(e[l])) return i;
    o = o[e[l]];
  }
  return o === void 0 ? i : o;
}
function Zp(r) {
  return r !== null && (typeof r == "object" || typeof r == "function");
}
const tx = /^(?:0|[1-9]\d*)$/;
function tg(r, e = Number.MAX_SAFE_INTEGER) {
  switch (typeof r) {
    case "number":
      return Number.isInteger(r) && r >= 0 && r < e;
    case "symbol":
      return !1;
    case "string":
      return tx.test(r);
  }
}
function rx(r) {
  return r !== null && typeof r == "object" && fa(r) === "[object Arguments]";
}
function nx(r, e) {
  let i;
  if (
    (Array.isArray(e)
      ? (i = e)
      : typeof e == "string" && Jy(e) && r?.[e] == null
      ? (i = ef(e))
      : (i = [e]),
    i.length === 0)
  )
    return !1;
  let o = r;
  for (let l = 0; l < i.length; l++) {
    const c = i[l];
    if (
      (o == null || !Object.hasOwn(o, c)) &&
      !((Array.isArray(o) || rx(o)) && tg(c) && c < o.length)
    )
      return !1;
    o = o[c];
  }
  return !0;
}
const ix = /\.|\[(?:[^[\]]*|(["'])(?:(?!\1)[^\\]|\\.)*?\1)\]/,
  sx = /^\w*$/;
function ox(r, e) {
  return Array.isArray(r)
    ? !1
    : typeof r == "number" || typeof r == "boolean" || r == null || Ww(r)
    ? !0
    : (typeof r == "string" && (sx.test(r) || !ix.test(r))) ||
      (e != null && Object.hasOwn(e, r));
}
const ax = (r, e, i) => {
  const o = r[e];
  (!(Object.hasOwn(r, e) && Iy(o, i)) || (i === void 0 && !(e in r))) &&
    (r[e] = i);
};
function lx(r, e, i, o) {
  if (r == null && !Zp(r)) return r;
  const l = ox(e, r)
    ? [e]
    : Array.isArray(e)
    ? e
    : typeof e == "string"
    ? ef(e)
    : [e];
  let c = r;
  for (let f = 0; f < l.length && c != null; f++) {
    const d = Zy(l[f]);
    if (ha(d)) continue;
    let m;
    if (f === l.length - 1) m = i(c[d]);
    else {
      const p = c[d],
        g = o?.(p, d, r);
      m = g !== void 0 ? g : Zp(p) ? p : tg(l[f + 1]) ? [] : {};
    }
    ax(c, d, m), (c = c[d]);
  }
  return r;
}
function ac(r, e, i) {
  return lx(
    r,
    e,
    () => i,
    () => {}
  );
}
var rg = ee.createContext(void 0);
rg.displayName = "InertiaHeadContext";
var Fc = rg,
  ng = ee.createContext(void 0);
ng.displayName = "InertiaPageContext";
var Nc = ng,
  Dc = !0,
  em = !1,
  tm = async () => {
    Dc = !1;
  };
function ig({
  children: r,
  initialPage: e,
  initialComponent: i,
  resolveComponent: o,
  titleCallback: l,
  onHeadUpdate: c,
}) {
  const [f, d] = ee.useState({ component: i || null, page: e, key: null }),
    m = ee.useMemo(
      () => U1(typeof window > "u", l || ((g) => g), c || (() => {})),
      []
    );
  if (
    (em ||
      (Qt.init({
        initialPage: e,
        resolveComponent: o,
        swapComponent: async (g) => tm(g),
      }),
      (em = !0)),
    ee.useEffect(() => {
      (tm = async ({ component: g, page: v, preserveState: x }) => {
        if (Dc) {
          Dc = !1;
          return;
        }
        d((w) => ({ component: g, page: v, key: x ? w.key : Date.now() }));
      }),
        Qt.on("navigate", () => m.forceUpdate());
    }, []),
    !f.component)
  )
    return ee.createElement(
      Fc.Provider,
      { value: m },
      ee.createElement(Nc.Provider, { value: f.page }, null)
    );
  const p =
    r ||
    (({ Component: g, props: v, key: x }) => {
      const w = ee.createElement(g, { key: x, ...v });
      return typeof g.layout == "function"
        ? g.layout(w)
        : Array.isArray(g.layout)
        ? g.layout
            .concat(w)
            .reverse()
            .reduce((E, k) => ee.createElement(k, { children: E, ...v }))
        : w;
    });
  return ee.createElement(
    Fc.Provider,
    { value: m },
    ee.createElement(
      Nc.Provider,
      { value: f.page },
      p({ Component: f.component, key: f.key, props: f.page.props })
    )
  );
}
ig.displayName = "Inertia";
async function ux({
  id: r = "app",
  resolve: e,
  setup: i,
  title: o,
  progress: l = {},
  page: c,
  render: f,
}) {
  const d = typeof window > "u",
    m = d ? null : document.getElementById(r),
    p = c || JSON.parse(m.dataset.page),
    g = (w) => Promise.resolve(e(w)).then((E) => E.default || E);
  let v = [];
  const x = await Promise.all([
    g(p.component),
    Qt.decryptHistory().catch(() => {}),
  ]).then(([w]) =>
    i({
      el: m,
      App: ig,
      props: {
        initialPage: p,
        initialComponent: w,
        resolveComponent: g,
        titleCallback: o,
        onHeadUpdate: d ? (E) => (v = E) : null,
      },
    })
  );
  if ((!d && l && Z1(l), d)) {
    const w = await f(
      ee.createElement("div", { id: r, "data-page": JSON.stringify(p) }, x)
    );
    return { head: v, body: w };
  }
}
function lE() {
  const r = ee.useContext(Nc);
  if (!r) throw new Error("usePage must be used within the Inertia component");
  return r;
}
var cx = function ({ children: r, title: e }) {
    const i = ee.useContext(Fc),
      o = ee.useMemo(() => i.createProvider(), [i]),
      l = typeof window > "u";
    ee.useEffect(
      () => (
        o.reconnect(),
        o.update(v(r)),
        () => {
          o.disconnect();
        }
      ),
      [o, r, e]
    );
    function c(x) {
      return (
        [
          "area",
          "base",
          "br",
          "col",
          "embed",
          "hr",
          "img",
          "input",
          "keygen",
          "link",
          "meta",
          "param",
          "source",
          "track",
          "wbr",
        ].indexOf(x.type) > -1
      );
    }
    function f(x) {
      const w = Object.keys(x.props).reduce((E, k) => {
        if (["head-key", "children", "dangerouslySetInnerHTML"].includes(k))
          return E;
        const _ = String(x.props[k]);
        return _ === "" ? E + ` ${k}` : E + ` ${k}="${s1(_)}"`;
      }, "");
      return `<${x.type}${w}>`;
    }
    function d(x) {
      return typeof x.props.children == "string"
        ? x.props.children
        : x.props.children.reduce((w, E) => w + m(E), "");
    }
    function m(x) {
      let w = f(x);
      return (
        x.props.children && (w += d(x)),
        x.props.dangerouslySetInnerHTML &&
          (w += x.props.dangerouslySetInnerHTML.__html),
        c(x) || (w += `</${x.type}>`),
        w
      );
    }
    function p(x) {
      return Lc.cloneElement(x, {
        inertia: x.props["head-key"] !== void 0 ? x.props["head-key"] : "",
      });
    }
    function g(x) {
      return m(p(x));
    }
    function v(x) {
      const w = Lc.Children.toArray(x)
        .filter((E) => E)
        .map((E) => g(E));
      return (
        e &&
          !w.find((E) => E.startsWith("<title")) &&
          w.push(`<title inertia>${e}</title>`),
        w
      );
    }
    return l && o.update(v(r)), null;
  },
  uE = cx,
  Br = () => {},
  sg = ee.forwardRef(
    (
      {
        children: r,
        as: e = "a",
        data: i = {},
        href: o,
        method: l = "get",
        preserveScroll: c = !1,
        preserveState: f = null,
        replace: d = !1,
        only: m = [],
        except: p = [],
        headers: g = {},
        queryStringArrayFormat: v = "brackets",
        async: x = !1,
        onClick: w = Br,
        onCancelToken: E = Br,
        onBefore: k = Br,
        onStart: _ = Br,
        onProgress: A = Br,
        onFinish: b = Br,
        onCancel: N = Br,
        onSuccess: U = Br,
        onError: z = Br,
        prefetch: H = !1,
        cacheFor: G = 0,
        ...Q
      },
      me
    ) => {
      const [ae, xe] = ee.useState(0),
        te = ee.useRef(null),
        _e = ee.useMemo(
          () => (typeof o == "object" ? o.method : l.toLowerCase()),
          [o, l]
        ),
        Ae = ee.useMemo(
          () => ((e = e.toLowerCase()), _e !== "get" ? "button" : e),
          [e, _e]
        ),
        ke = ee.useMemo(
          () => Uy(_e, typeof o == "object" ? o.url : o || "", i, v),
          [o, _e, i, v]
        ),
        be = ee.useMemo(() => ke[0], [ke]),
        Se = ee.useMemo(() => ke[1], [ke]),
        D = ee.useMemo(
          () => ({
            data: Se,
            method: _e,
            preserveScroll: c,
            preserveState: f ?? _e !== "get",
            replace: d,
            only: m,
            except: p,
            headers: g,
            async: x,
          }),
          [Se, _e, c, f, d, m, p, g, x]
        ),
        J = ee.useMemo(
          () => ({
            ...D,
            onCancelToken: E,
            onBefore: k,
            onStart(Y) {
              xe((ue) => ue + 1), _(Y);
            },
            onProgress: A,
            onFinish(Y) {
              xe((ue) => ue - 1), b(Y);
            },
            onCancel: N,
            onSuccess: U,
            onError: z,
          }),
          [D, E, k, _, A, b, N, U, z]
        ),
        X = () => {
          Qt.prefetch(be, D, { cacheFor: B });
        },
        R = ee.useMemo(
          () =>
            H === !0 ? ["hover"] : H === !1 ? [] : Array.isArray(H) ? H : [H],
          Array.isArray(H) ? H : [H]
        ),
        B = ee.useMemo(
          () => (G !== 0 ? G : R.length === 1 && R[0] === "click" ? 0 : 3e4),
          [G, R]
        );
      ee.useEffect(
        () => () => {
          clearTimeout(te.current);
        },
        []
      ),
        ee.useEffect(() => {
          R.includes("mount") && setTimeout(() => X());
        }, R);
      const le = {
          onClick: (Y) => {
            w(Y), oc(Y) && (Y.preventDefault(), Qt.visit(be, J));
          },
        },
        he = {
          onMouseEnter: () => {
            te.current = window.setTimeout(() => {
              X();
            }, 75);
          },
          onMouseLeave: () => {
            clearTimeout(te.current);
          },
          onClick: le.onClick,
        },
        W = {
          onMouseDown: (Y) => {
            oc(Y) && (Y.preventDefault(), X());
          },
          onMouseUp: (Y) => {
            Y.preventDefault(), Qt.visit(be, J);
          },
          onClick: (Y) => {
            w(Y), oc(Y) && Y.preventDefault();
          },
        },
        re = ee.useMemo(
          () => ({ a: { href: be }, button: { type: "button" } }),
          [be]
        );
      return ee.createElement(
        Ae,
        {
          ...Q,
          ...(re[Ae] || {}),
          ref: me,
          ...(R.includes("hover") ? he : R.includes("click") ? W : le),
          "data-loading": ae > 0 ? "" : void 0,
        },
        r
      );
    }
  );
sg.displayName = "InertiaLink";
var cE = sg;
function rm(r, e) {
  const [i, o] = ee.useState(() => {
    const l = Qt.restore(e);
    return l !== void 0 ? l : r;
  });
  return (
    ee.useEffect(() => {
      Qt.remember(i, e);
    }, [i, e]),
    [i, o]
  );
}
function fE(r, e) {
  const i = ee.useRef(null),
    o = typeof r == "string" ? r : null,
    [l, c] = ee.useState((typeof r == "string" ? e : r) || {}),
    f = ee.useRef(null),
    d = ee.useRef(null),
    [m, p] = o ? rm(l, `${o}:data`) : ee.useState(l),
    [g, v] = o ? rm({}, `${o}:errors`) : ee.useState({}),
    [x, w] = ee.useState(!1),
    [E, k] = ee.useState(!1),
    [_, A] = ee.useState(null),
    [b, N] = ee.useState(!1),
    [U, z] = ee.useState(!1),
    H = ee.useRef((W) => W),
    G = ee.useMemo(() => !n1(m, l), [m, l]);
  ee.useEffect(
    () => (
      (i.current = !0),
      () => {
        i.current = !1;
      }
    ),
    []
  );
  const Q = ee.useCallback(
      (...W) => {
        const re = typeof W[0] == "object",
          Y = re ? W[0].method : W[0],
          ue = re ? W[0].url : W[1],
          ne = (re ? W[1] : W[2]) ?? {},
          de = {
            ...ne,
            onCancelToken: (ve) => {
              if (((f.current = ve), ne.onCancelToken))
                return ne.onCancelToken(ve);
            },
            onBefore: (ve) => {
              if ((N(!1), z(!1), clearTimeout(d.current), ne.onBefore))
                return ne.onBefore(ve);
            },
            onStart: (ve) => {
              if ((k(!0), ne.onStart)) return ne.onStart(ve);
            },
            onProgress: (ve) => {
              if ((A(ve), ne.onProgress)) return ne.onProgress(ve);
            },
            onSuccess: (ve) => {
              if (
                (i.current &&
                  (k(!1),
                  A(null),
                  v({}),
                  w(!1),
                  N(!0),
                  z(!0),
                  c(_s(m)),
                  (d.current = setTimeout(() => {
                    i.current && z(!1);
                  }, 2e3))),
                ne.onSuccess)
              )
                return ne.onSuccess(ve);
            },
            onError: (ve) => {
              if ((i.current && (k(!1), A(null), v(ve), w(!0)), ne.onError))
                return ne.onError(ve);
            },
            onCancel: () => {
              if ((i.current && (k(!1), A(null)), ne.onCancel))
                return ne.onCancel();
            },
            onFinish: (ve) => {
              if (
                (i.current && (k(!1), A(null)), (f.current = null), ne.onFinish)
              )
                return ne.onFinish(ve);
            },
          };
        Y === "delete"
          ? Qt.delete(ue, { ...de, data: H.current(m) })
          : Qt[Y](ue, H.current(m), de);
      },
      [m, v, H]
    ),
    me = ee.useCallback(
      (W, re) => {
        p(
          typeof W == "string"
            ? (Y) => ac(_s(Y), W, re)
            : typeof W == "function"
            ? (Y) => W(Y)
            : W
        );
      },
      [p]
    ),
    [ae, xe] = ee.useState(!1),
    te = ee.useCallback(
      (W, re) => {
        typeof W > "u"
          ? (c(m), xe(!0))
          : c((Y) =>
              typeof W == "string" ? ac(_s(Y), W, re) : Object.assign(_s(Y), W)
            );
      },
      [m, c]
    );
  ee.useLayoutEffect(() => {
    ae && (G && c(m), xe(!1));
  }, [ae]);
  const _e = ee.useCallback(
      (...W) => {
        W.length === 0
          ? p(l)
          : p((re) =>
              W.filter((Y) => nx(l, Y)).reduce(
                (Y, ue) => ac(Y, ue, eg(l, ue)),
                { ...re }
              )
            );
      },
      [p, l]
    ),
    Ae = ee.useCallback(
      (W, re) => {
        v((Y) => {
          const ue = { ...Y, ...(typeof W == "string" ? { [W]: re } : W) };
          return w(Object.keys(ue).length > 0), ue;
        });
      },
      [v, w]
    ),
    ke = ee.useCallback(
      (...W) => {
        v((re) => {
          const Y = Object.keys(re).reduce(
            (ue, ne) => ({
              ...ue,
              ...(W.length > 0 && !W.includes(ne) ? { [ne]: re[ne] } : {}),
            }),
            {}
          );
          return w(Object.keys(Y).length > 0), Y;
        });
      },
      [v, w]
    ),
    be = ee.useCallback(
      (...W) => {
        _e(...W), ke(...W);
      },
      [_e, ke]
    ),
    Se = (W) => (re, Y) => {
      Q(W, re, Y);
    },
    D = ee.useCallback(Se("get"), [Q]),
    J = ee.useCallback(Se("post"), [Q]),
    X = ee.useCallback(Se("put"), [Q]),
    R = ee.useCallback(Se("patch"), [Q]),
    B = ee.useCallback(Se("delete"), [Q]),
    le = ee.useCallback(() => {
      f.current && f.current.cancel();
    }, []),
    he = ee.useCallback((W) => {
      H.current = W;
    }, []);
  return {
    data: m,
    setData: me,
    isDirty: G,
    errors: g,
    hasErrors: x,
    processing: E,
    progress: _,
    wasSuccessful: b,
    recentlySuccessful: U,
    transform: he,
    setDefaults: te,
    reset: _e,
    setError: Ae,
    clearErrors: ke,
    resetAndClearErrors: be,
    submit: Q,
    get: D,
    post: J,
    put: X,
    patch: R,
    delete: B,
    cancel: le,
  };
}
var hE = Qt;
async function fx(r, e) {
  for (const i of Array.isArray(r) ? r : [r]) {
    const o = e[i];
    if (!(typeof o > "u")) return typeof o == "function" ? o() : o;
  }
  throw new Error(`Page not found: ${r}`);
}
var ft = ((r) => (
  (r.Application = "application"),
  (r.WebGLPipes = "webgl-pipes"),
  (r.WebGLPipesAdaptor = "webgl-pipes-adaptor"),
  (r.WebGLSystem = "webgl-system"),
  (r.WebGPUPipes = "webgpu-pipes"),
  (r.WebGPUPipesAdaptor = "webgpu-pipes-adaptor"),
  (r.WebGPUSystem = "webgpu-system"),
  (r.CanvasSystem = "canvas-system"),
  (r.CanvasPipesAdaptor = "canvas-pipes-adaptor"),
  (r.CanvasPipes = "canvas-pipes"),
  (r.Asset = "asset"),
  (r.LoadParser = "load-parser"),
  (r.ResolveParser = "resolve-parser"),
  (r.CacheParser = "cache-parser"),
  (r.DetectionParser = "detection-parser"),
  (r.MaskEffect = "mask-effect"),
  (r.BlendMode = "blend-mode"),
  (r.TextureSource = "texture-source"),
  (r.Environment = "environment"),
  (r.ShapeBuilder = "shape-builder"),
  (r.Batcher = "batcher"),
  r
))(ft || {});
const Bc = (r) => {
    if (typeof r == "function" || (typeof r == "object" && r.extension)) {
      if (!r.extension)
        throw new Error("Extension class must have an extension object");
      r = {
        ...(typeof r.extension != "object"
          ? { type: r.extension }
          : r.extension),
        ref: r,
      };
    }
    if (typeof r == "object") r = { ...r };
    else throw new Error("Invalid extension type");
    return typeof r.type == "string" && (r.type = [r.type]), r;
  },
  Yo = (r, e) => Bc(r).priority ?? e,
  xn = {
    _addHandlers: {},
    _removeHandlers: {},
    _queue: {},
    remove(...r) {
      return (
        r.map(Bc).forEach((e) => {
          e.type.forEach((i) => this._removeHandlers[i]?.(e));
        }),
        this
      );
    },
    add(...r) {
      return (
        r.map(Bc).forEach((e) => {
          e.type.forEach((i) => {
            const o = this._addHandlers,
              l = this._queue;
            o[i] ? o[i]?.(e) : ((l[i] = l[i] || []), l[i]?.push(e));
          });
        }),
        this
      );
    },
    handle(r, e, i) {
      const o = this._addHandlers,
        l = this._removeHandlers;
      if (o[r] || l[r])
        throw new Error(`Extension type ${r} already has a handler`);
      (o[r] = e), (l[r] = i);
      const c = this._queue;
      return c[r] && (c[r]?.forEach((f) => e(f)), delete c[r]), this;
    },
    handleByMap(r, e) {
      return this.handle(
        r,
        (i) => {
          i.name && (e[i.name] = i.ref);
        },
        (i) => {
          i.name && delete e[i.name];
        }
      );
    },
    handleByNamedList(r, e, i = -1) {
      return this.handle(
        r,
        (o) => {
          e.findIndex((c) => c.name === o.name) >= 0 ||
            (e.push({ name: o.name, value: o.ref }),
            e.sort((c, f) => Yo(f.value, i) - Yo(c.value, i)));
        },
        (o) => {
          const l = e.findIndex((c) => c.name === o.name);
          l !== -1 && e.splice(l, 1);
        }
      );
    },
    handleByList(r, e, i = -1) {
      return this.handle(
        r,
        (o) => {
          e.includes(o.ref) ||
            (e.push(o.ref), e.sort((l, c) => Yo(c, i) - Yo(l, i)));
        },
        (o) => {
          const l = e.indexOf(o.ref);
          l !== -1 && e.splice(l, 1);
        }
      );
    },
    mixin(r, ...e) {
      for (const i of e)
        Object.defineProperties(
          r.prototype,
          Object.getOwnPropertyDescriptors(i)
        );
    },
  },
  hx = {
    extension: { type: ft.Environment, name: "browser", priority: -1 },
    test: () => !0,
    load: async () => {
      await Pe(
        () => import("./browserAll-F8FjJuYr.js"),
        __vite__mapDeps([0, 1, 2, 3, 4, 5])
      );
    },
  },
  dx = {
    extension: { type: ft.Environment, name: "webworker", priority: 0 },
    test: () => typeof self < "u" && self.WorkerGlobalScope !== void 0,
    load: async () => {
      await Pe(
        () => import("./webworkerAll-DhhJBp7F.js"),
        __vite__mapDeps([1, 2, 3, 4, 5])
      );
    },
  };
class gt {
  constructor(e, i, o) {
    (this._x = i || 0), (this._y = o || 0), (this._observer = e);
  }
  clone(e) {
    return new gt(e ?? this._observer, this._x, this._y);
  }
  set(e = 0, i = e) {
    return (
      (this._x !== e || this._y !== i) &&
        ((this._x = e), (this._y = i), this._observer._onUpdate(this)),
      this
    );
  }
  copyFrom(e) {
    return (
      (this._x !== e.x || this._y !== e.y) &&
        ((this._x = e.x), (this._y = e.y), this._observer._onUpdate(this)),
      this
    );
  }
  copyTo(e) {
    return e.set(this._x, this._y), e;
  }
  equals(e) {
    return e.x === this._x && e.y === this._y;
  }
  toString() {
    return `[pixi.js/math:ObservablePoint x=${this._x} y=${this._y} scope=${this._observer}]`;
  }
  get x() {
    return this._x;
  }
  set x(e) {
    this._x !== e && ((this._x = e), this._observer._onUpdate(this));
  }
  get y() {
    return this._y;
  }
  set y(e) {
    this._y !== e && ((this._y = e), this._observer._onUpdate(this));
  }
}
var lc = { exports: {} },
  nm;
function px() {
  return (
    nm ||
      ((nm = 1),
      (function (r) {
        var e = Object.prototype.hasOwnProperty,
          i = "~";
        function o() {}
        Object.create &&
          ((o.prototype = Object.create(null)), new o().__proto__ || (i = !1));
        function l(m, p, g) {
          (this.fn = m), (this.context = p), (this.once = g || !1);
        }
        function c(m, p, g, v, x) {
          if (typeof g != "function")
            throw new TypeError("The listener must be a function");
          var w = new l(g, v || m, x),
            E = i ? i + p : p;
          return (
            m._events[E]
              ? m._events[E].fn
                ? (m._events[E] = [m._events[E], w])
                : m._events[E].push(w)
              : ((m._events[E] = w), m._eventsCount++),
            m
          );
        }
        function f(m, p) {
          --m._eventsCount === 0 ? (m._events = new o()) : delete m._events[p];
        }
        function d() {
          (this._events = new o()), (this._eventsCount = 0);
        }
        (d.prototype.eventNames = function () {
          var p = [],
            g,
            v;
          if (this._eventsCount === 0) return p;
          for (v in (g = this._events))
            e.call(g, v) && p.push(i ? v.slice(1) : v);
          return Object.getOwnPropertySymbols
            ? p.concat(Object.getOwnPropertySymbols(g))
            : p;
        }),
          (d.prototype.listeners = function (p) {
            var g = i ? i + p : p,
              v = this._events[g];
            if (!v) return [];
            if (v.fn) return [v.fn];
            for (var x = 0, w = v.length, E = new Array(w); x < w; x++)
              E[x] = v[x].fn;
            return E;
          }),
          (d.prototype.listenerCount = function (p) {
            var g = i ? i + p : p,
              v = this._events[g];
            return v ? (v.fn ? 1 : v.length) : 0;
          }),
          (d.prototype.emit = function (p, g, v, x, w, E) {
            var k = i ? i + p : p;
            if (!this._events[k]) return !1;
            var _ = this._events[k],
              A = arguments.length,
              b,
              N;
            if (_.fn) {
              switch ((_.once && this.removeListener(p, _.fn, void 0, !0), A)) {
                case 1:
                  return _.fn.call(_.context), !0;
                case 2:
                  return _.fn.call(_.context, g), !0;
                case 3:
                  return _.fn.call(_.context, g, v), !0;
                case 4:
                  return _.fn.call(_.context, g, v, x), !0;
                case 5:
                  return _.fn.call(_.context, g, v, x, w), !0;
                case 6:
                  return _.fn.call(_.context, g, v, x, w, E), !0;
              }
              for (N = 1, b = new Array(A - 1); N < A; N++)
                b[N - 1] = arguments[N];
              _.fn.apply(_.context, b);
            } else {
              var U = _.length,
                z;
              for (N = 0; N < U; N++)
                switch (
                  (_[N].once && this.removeListener(p, _[N].fn, void 0, !0), A)
                ) {
                  case 1:
                    _[N].fn.call(_[N].context);
                    break;
                  case 2:
                    _[N].fn.call(_[N].context, g);
                    break;
                  case 3:
                    _[N].fn.call(_[N].context, g, v);
                    break;
                  case 4:
                    _[N].fn.call(_[N].context, g, v, x);
                    break;
                  default:
                    if (!b)
                      for (z = 1, b = new Array(A - 1); z < A; z++)
                        b[z - 1] = arguments[z];
                    _[N].fn.apply(_[N].context, b);
                }
            }
            return !0;
          }),
          (d.prototype.on = function (p, g, v) {
            return c(this, p, g, v, !1);
          }),
          (d.prototype.once = function (p, g, v) {
            return c(this, p, g, v, !0);
          }),
          (d.prototype.removeListener = function (p, g, v, x) {
            var w = i ? i + p : p;
            if (!this._events[w]) return this;
            if (!g) return f(this, w), this;
            var E = this._events[w];
            if (E.fn)
              E.fn === g &&
                (!x || E.once) &&
                (!v || E.context === v) &&
                f(this, w);
            else {
              for (var k = 0, _ = [], A = E.length; k < A; k++)
                (E[k].fn !== g ||
                  (x && !E[k].once) ||
                  (v && E[k].context !== v)) &&
                  _.push(E[k]);
              _.length
                ? (this._events[w] = _.length === 1 ? _[0] : _)
                : f(this, w);
            }
            return this;
          }),
          (d.prototype.removeAllListeners = function (p) {
            var g;
            return (
              p
                ? ((g = i ? i + p : p), this._events[g] && f(this, g))
                : ((this._events = new o()), (this._eventsCount = 0)),
              this
            );
          }),
          (d.prototype.off = d.prototype.removeListener),
          (d.prototype.addListener = d.prototype.on),
          (d.prefixed = i),
          (d.EventEmitter = d),
          (r.exports = d);
      })(lc)),
    lc.exports
  );
}
var mx = px();
const qr = Mm(mx),
  yx = Math.PI * 2,
  gx = 180 / Math.PI,
  vx = Math.PI / 180;
class Er {
  constructor(e = 0, i = 0) {
    (this.x = 0), (this.y = 0), (this.x = e), (this.y = i);
  }
  clone() {
    return new Er(this.x, this.y);
  }
  copyFrom(e) {
    return this.set(e.x, e.y), this;
  }
  copyTo(e) {
    return e.set(this.x, this.y), e;
  }
  equals(e) {
    return e.x === this.x && e.y === this.y;
  }
  set(e = 0, i = e) {
    return (this.x = e), (this.y = i), this;
  }
  toString() {
    return `[pixi.js/math:Point x=${this.x} y=${this.y}]`;
  }
  static get shared() {
    return (uc.x = 0), (uc.y = 0), uc;
  }
}
const uc = new Er();
class Ve {
  constructor(e = 1, i = 0, o = 0, l = 1, c = 0, f = 0) {
    (this.array = null),
      (this.a = e),
      (this.b = i),
      (this.c = o),
      (this.d = l),
      (this.tx = c),
      (this.ty = f);
  }
  fromArray(e) {
    (this.a = e[0]),
      (this.b = e[1]),
      (this.c = e[3]),
      (this.d = e[4]),
      (this.tx = e[2]),
      (this.ty = e[5]);
  }
  set(e, i, o, l, c, f) {
    return (
      (this.a = e),
      (this.b = i),
      (this.c = o),
      (this.d = l),
      (this.tx = c),
      (this.ty = f),
      this
    );
  }
  toArray(e, i) {
    this.array || (this.array = new Float32Array(9));
    const o = i || this.array;
    return (
      e
        ? ((o[0] = this.a),
          (o[1] = this.b),
          (o[2] = 0),
          (o[3] = this.c),
          (o[4] = this.d),
          (o[5] = 0),
          (o[6] = this.tx),
          (o[7] = this.ty),
          (o[8] = 1))
        : ((o[0] = this.a),
          (o[1] = this.c),
          (o[2] = this.tx),
          (o[3] = this.b),
          (o[4] = this.d),
          (o[5] = this.ty),
          (o[6] = 0),
          (o[7] = 0),
          (o[8] = 1)),
      o
    );
  }
  apply(e, i) {
    i = i || new Er();
    const o = e.x,
      l = e.y;
    return (
      (i.x = this.a * o + this.c * l + this.tx),
      (i.y = this.b * o + this.d * l + this.ty),
      i
    );
  }
  applyInverse(e, i) {
    i = i || new Er();
    const o = this.a,
      l = this.b,
      c = this.c,
      f = this.d,
      d = this.tx,
      m = this.ty,
      p = 1 / (o * f + c * -l),
      g = e.x,
      v = e.y;
    return (
      (i.x = f * p * g + -c * p * v + (m * c - d * f) * p),
      (i.y = o * p * v + -l * p * g + (-m * o + d * l) * p),
      i
    );
  }
  translate(e, i) {
    return (this.tx += e), (this.ty += i), this;
  }
  scale(e, i) {
    return (
      (this.a *= e),
      (this.d *= i),
      (this.c *= e),
      (this.b *= i),
      (this.tx *= e),
      (this.ty *= i),
      this
    );
  }
  rotate(e) {
    const i = Math.cos(e),
      o = Math.sin(e),
      l = this.a,
      c = this.c,
      f = this.tx;
    return (
      (this.a = l * i - this.b * o),
      (this.b = l * o + this.b * i),
      (this.c = c * i - this.d * o),
      (this.d = c * o + this.d * i),
      (this.tx = f * i - this.ty * o),
      (this.ty = f * o + this.ty * i),
      this
    );
  }
  append(e) {
    const i = this.a,
      o = this.b,
      l = this.c,
      c = this.d;
    return (
      (this.a = e.a * i + e.b * l),
      (this.b = e.a * o + e.b * c),
      (this.c = e.c * i + e.d * l),
      (this.d = e.c * o + e.d * c),
      (this.tx = e.tx * i + e.ty * l + this.tx),
      (this.ty = e.tx * o + e.ty * c + this.ty),
      this
    );
  }
  appendFrom(e, i) {
    const o = e.a,
      l = e.b,
      c = e.c,
      f = e.d,
      d = e.tx,
      m = e.ty,
      p = i.a,
      g = i.b,
      v = i.c,
      x = i.d;
    return (
      (this.a = o * p + l * v),
      (this.b = o * g + l * x),
      (this.c = c * p + f * v),
      (this.d = c * g + f * x),
      (this.tx = d * p + m * v + i.tx),
      (this.ty = d * g + m * x + i.ty),
      this
    );
  }
  setTransform(e, i, o, l, c, f, d, m, p) {
    return (
      (this.a = Math.cos(d + p) * c),
      (this.b = Math.sin(d + p) * c),
      (this.c = -Math.sin(d - m) * f),
      (this.d = Math.cos(d - m) * f),
      (this.tx = e - (o * this.a + l * this.c)),
      (this.ty = i - (o * this.b + l * this.d)),
      this
    );
  }
  prepend(e) {
    const i = this.tx;
    if (e.a !== 1 || e.b !== 0 || e.c !== 0 || e.d !== 1) {
      const o = this.a,
        l = this.c;
      (this.a = o * e.a + this.b * e.c),
        (this.b = o * e.b + this.b * e.d),
        (this.c = l * e.a + this.d * e.c),
        (this.d = l * e.b + this.d * e.d);
    }
    return (
      (this.tx = i * e.a + this.ty * e.c + e.tx),
      (this.ty = i * e.b + this.ty * e.d + e.ty),
      this
    );
  }
  decompose(e) {
    const i = this.a,
      o = this.b,
      l = this.c,
      c = this.d,
      f = e.pivot,
      d = -Math.atan2(-l, c),
      m = Math.atan2(o, i),
      p = Math.abs(d + m);
    return (
      p < 1e-5 || Math.abs(yx - p) < 1e-5
        ? ((e.rotation = m), (e.skew.x = e.skew.y = 0))
        : ((e.rotation = 0), (e.skew.x = d), (e.skew.y = m)),
      (e.scale.x = Math.sqrt(i * i + o * o)),
      (e.scale.y = Math.sqrt(l * l + c * c)),
      (e.position.x = this.tx + (f.x * i + f.y * l)),
      (e.position.y = this.ty + (f.x * o + f.y * c)),
      e
    );
  }
  invert() {
    const e = this.a,
      i = this.b,
      o = this.c,
      l = this.d,
      c = this.tx,
      f = e * l - i * o;
    return (
      (this.a = l / f),
      (this.b = -i / f),
      (this.c = -o / f),
      (this.d = e / f),
      (this.tx = (o * this.ty - l * c) / f),
      (this.ty = -(e * this.ty - i * c) / f),
      this
    );
  }
  isIdentity() {
    return (
      this.a === 1 &&
      this.b === 0 &&
      this.c === 0 &&
      this.d === 1 &&
      this.tx === 0 &&
      this.ty === 0
    );
  }
  identity() {
    return (
      (this.a = 1),
      (this.b = 0),
      (this.c = 0),
      (this.d = 1),
      (this.tx = 0),
      (this.ty = 0),
      this
    );
  }
  clone() {
    const e = new Ve();
    return (
      (e.a = this.a),
      (e.b = this.b),
      (e.c = this.c),
      (e.d = this.d),
      (e.tx = this.tx),
      (e.ty = this.ty),
      e
    );
  }
  copyTo(e) {
    return (
      (e.a = this.a),
      (e.b = this.b),
      (e.c = this.c),
      (e.d = this.d),
      (e.tx = this.tx),
      (e.ty = this.ty),
      e
    );
  }
  copyFrom(e) {
    return (
      (this.a = e.a),
      (this.b = e.b),
      (this.c = e.c),
      (this.d = e.d),
      (this.tx = e.tx),
      (this.ty = e.ty),
      this
    );
  }
  equals(e) {
    return (
      e.a === this.a &&
      e.b === this.b &&
      e.c === this.c &&
      e.d === this.d &&
      e.tx === this.tx &&
      e.ty === this.ty
    );
  }
  toString() {
    return `[pixi.js:Matrix a=${this.a} b=${this.b} c=${this.c} d=${this.d} tx=${this.tx} ty=${this.ty}]`;
  }
  static get IDENTITY() {
    return wx.identity();
  }
  static get shared() {
    return _x.identity();
  }
}
const _x = new Ve(),
  wx = new Ve(),
  Nn = [1, 1, 0, -1, -1, -1, 0, 1, 1, 1, 0, -1, -1, -1, 0, 1],
  Dn = [0, 1, 1, 1, 0, -1, -1, -1, 0, 1, 1, 1, 0, -1, -1, -1],
  Bn = [0, -1, -1, -1, 0, 1, 1, 1, 0, 1, 1, 1, 0, -1, -1, -1],
  Un = [1, 1, 0, -1, -1, -1, 0, 1, -1, -1, 0, 1, 1, 1, 0, -1],
  Uc = [],
  og = [],
  Qo = Math.sign;
function xx() {
  for (let r = 0; r < 16; r++) {
    const e = [];
    Uc.push(e);
    for (let i = 0; i < 16; i++) {
      const o = Qo(Nn[r] * Nn[i] + Bn[r] * Dn[i]),
        l = Qo(Dn[r] * Nn[i] + Un[r] * Dn[i]),
        c = Qo(Nn[r] * Bn[i] + Bn[r] * Un[i]),
        f = Qo(Dn[r] * Bn[i] + Un[r] * Un[i]);
      for (let d = 0; d < 16; d++)
        if (Nn[d] === o && Dn[d] === l && Bn[d] === c && Un[d] === f) {
          e.push(d);
          break;
        }
    }
  }
  for (let r = 0; r < 16; r++) {
    const e = new Ve();
    e.set(Nn[r], Dn[r], Bn[r], Un[r], 0, 0), og.push(e);
  }
}
xx();
const qe = {
    E: 0,
    SE: 1,
    S: 2,
    SW: 3,
    W: 4,
    NW: 5,
    N: 6,
    NE: 7,
    MIRROR_VERTICAL: 8,
    MAIN_DIAGONAL: 10,
    MIRROR_HORIZONTAL: 12,
    REVERSE_DIAGONAL: 14,
    uX: (r) => Nn[r],
    uY: (r) => Dn[r],
    vX: (r) => Bn[r],
    vY: (r) => Un[r],
    inv: (r) => (r & 8 ? r & 15 : -r & 7),
    add: (r, e) => Uc[r][e],
    sub: (r, e) => Uc[r][qe.inv(e)],
    rotate180: (r) => r ^ 4,
    isVertical: (r) => (r & 3) === 2,
    byDirection: (r, e) =>
      Math.abs(r) * 2 <= Math.abs(e)
        ? e >= 0
          ? qe.S
          : qe.N
        : Math.abs(e) * 2 <= Math.abs(r)
        ? r > 0
          ? qe.E
          : qe.W
        : e > 0
        ? r > 0
          ? qe.SE
          : qe.SW
        : r > 0
        ? qe.NE
        : qe.NW,
    matrixAppendRotationInv: (r, e, i = 0, o = 0) => {
      const l = og[qe.inv(e)];
      (l.tx = i), (l.ty = o), r.append(l);
    },
  },
  Ko = [new Er(), new Er(), new Er(), new Er()];
class Pr {
  constructor(e = 0, i = 0, o = 0, l = 0) {
    (this.type = "rectangle"),
      (this.x = Number(e)),
      (this.y = Number(i)),
      (this.width = Number(o)),
      (this.height = Number(l));
  }
  get left() {
    return this.x;
  }
  get right() {
    return this.x + this.width;
  }
  get top() {
    return this.y;
  }
  get bottom() {
    return this.y + this.height;
  }
  isEmpty() {
    return this.left === this.right || this.top === this.bottom;
  }
  static get EMPTY() {
    return new Pr(0, 0, 0, 0);
  }
  clone() {
    return new Pr(this.x, this.y, this.width, this.height);
  }
  copyFromBounds(e) {
    return (
      (this.x = e.minX),
      (this.y = e.minY),
      (this.width = e.maxX - e.minX),
      (this.height = e.maxY - e.minY),
      this
    );
  }
  copyFrom(e) {
    return (
      (this.x = e.x),
      (this.y = e.y),
      (this.width = e.width),
      (this.height = e.height),
      this
    );
  }
  copyTo(e) {
    return e.copyFrom(this), e;
  }
  contains(e, i) {
    return this.width <= 0 || this.height <= 0
      ? !1
      : e >= this.x &&
          e < this.x + this.width &&
          i >= this.y &&
          i < this.y + this.height;
  }
  strokeContains(e, i, o, l = 0.5) {
    const { width: c, height: f } = this;
    if (c <= 0 || f <= 0) return !1;
    const d = this.x,
      m = this.y,
      p = o * (1 - l),
      g = o - p,
      v = d - p,
      x = d + c + p,
      w = m - p,
      E = m + f + p,
      k = d + g,
      _ = d + c - g,
      A = m + g,
      b = m + f - g;
    return (
      e >= v &&
      e <= x &&
      i >= w &&
      i <= E &&
      !(e > k && e < _ && i > A && i < b)
    );
  }
  intersects(e, i) {
    if (!i) {
      const Q = this.x < e.x ? e.x : this.x;
      if ((this.right > e.right ? e.right : this.right) <= Q) return !1;
      const ae = this.y < e.y ? e.y : this.y;
      return (this.bottom > e.bottom ? e.bottom : this.bottom) > ae;
    }
    const o = this.left,
      l = this.right,
      c = this.top,
      f = this.bottom;
    if (l <= o || f <= c) return !1;
    const d = Ko[0].set(e.left, e.top),
      m = Ko[1].set(e.left, e.bottom),
      p = Ko[2].set(e.right, e.top),
      g = Ko[3].set(e.right, e.bottom);
    if (p.x <= d.x || m.y <= d.y) return !1;
    const v = Math.sign(i.a * i.d - i.b * i.c);
    if (
      v === 0 ||
      (i.apply(d, d),
      i.apply(m, m),
      i.apply(p, p),
      i.apply(g, g),
      Math.max(d.x, m.x, p.x, g.x) <= o ||
        Math.min(d.x, m.x, p.x, g.x) >= l ||
        Math.max(d.y, m.y, p.y, g.y) <= c ||
        Math.min(d.y, m.y, p.y, g.y) >= f)
    )
      return !1;
    const x = v * (m.y - d.y),
      w = v * (d.x - m.x),
      E = x * o + w * c,
      k = x * l + w * c,
      _ = x * o + w * f,
      A = x * l + w * f;
    if (
      Math.max(E, k, _, A) <= x * d.x + w * d.y ||
      Math.min(E, k, _, A) >= x * g.x + w * g.y
    )
      return !1;
    const b = v * (d.y - p.y),
      N = v * (p.x - d.x),
      U = b * o + N * c,
      z = b * l + N * c,
      H = b * o + N * f,
      G = b * l + N * f;
    return !(
      Math.max(U, z, H, G) <= b * d.x + N * d.y ||
      Math.min(U, z, H, G) >= b * g.x + N * g.y
    );
  }
  pad(e = 0, i = e) {
    return (
      (this.x -= e),
      (this.y -= i),
      (this.width += e * 2),
      (this.height += i * 2),
      this
    );
  }
  fit(e) {
    const i = Math.max(this.x, e.x),
      o = Math.min(this.x + this.width, e.x + e.width),
      l = Math.max(this.y, e.y),
      c = Math.min(this.y + this.height, e.y + e.height);
    return (
      (this.x = i),
      (this.width = Math.max(o - i, 0)),
      (this.y = l),
      (this.height = Math.max(c - l, 0)),
      this
    );
  }
  ceil(e = 1, i = 0.001) {
    const o = Math.ceil((this.x + this.width - i) * e) / e,
      l = Math.ceil((this.y + this.height - i) * e) / e;
    return (
      (this.x = Math.floor((this.x + i) * e) / e),
      (this.y = Math.floor((this.y + i) * e) / e),
      (this.width = o - this.x),
      (this.height = l - this.y),
      this
    );
  }
  enlarge(e) {
    const i = Math.min(this.x, e.x),
      o = Math.max(this.x + this.width, e.x + e.width),
      l = Math.min(this.y, e.y),
      c = Math.max(this.y + this.height, e.y + e.height);
    return (
      (this.x = i),
      (this.width = o - i),
      (this.y = l),
      (this.height = c - l),
      this
    );
  }
  getBounds(e) {
    return e || (e = new Pr()), e.copyFrom(this), e;
  }
  containsRect(e) {
    if (this.width <= 0 || this.height <= 0) return !1;
    const i = e.x,
      o = e.y,
      l = e.x + e.width,
      c = e.y + e.height;
    return (
      i >= this.x &&
      i < this.x + this.width &&
      o >= this.y &&
      o < this.y + this.height &&
      l >= this.x &&
      l < this.x + this.width &&
      c >= this.y &&
      c < this.y + this.height
    );
  }
  set(e, i, o, l) {
    return (
      (this.x = e), (this.y = i), (this.width = o), (this.height = l), this
    );
  }
  toString() {
    return `[pixi.js/math:Rectangle x=${this.x} y=${this.y} width=${this.width} height=${this.height}]`;
  }
}
const cc = { default: -1 };
function gn(r = "default") {
  return cc[r] === void 0 && (cc[r] = -1), ++cc[r];
}
const im = {},
  Pi = "8.0.0",
  dE = "8.3.4";
function zr(r, e, i = 3) {
  if (im[e]) return;
  let o = new Error().stack;
  typeof o > "u"
    ? console.warn(
        "PixiJS Deprecation Warning: ",
        `${e}
Deprecated since v${r}`
      )
    : ((o = o
        .split(
          `
`
        )
        .splice(i).join(`
`)),
      console.groupCollapsed
        ? (console.groupCollapsed(
            "%cPixiJS Deprecation Warning: %c%s",
            "color:#614108;background:#fffbe6",
            "font-weight:normal;color:#614108;background:#fffbe6",
            `${e}
Deprecated since v${r}`
          ),
          console.warn(o),
          console.groupEnd())
        : (console.warn(
            "PixiJS Deprecation Warning: ",
            `${e}
Deprecated since v${r}`
          ),
          console.warn(o))),
    (im[e] = !0);
}
const ag = () => {};
function sm(r) {
  return (
    (r += r === 0 ? 1 : 0),
    --r,
    (r |= r >>> 1),
    (r |= r >>> 2),
    (r |= r >>> 4),
    (r |= r >>> 8),
    (r |= r >>> 16),
    r + 1
  );
}
function om(r) {
  return !(r & (r - 1)) && !!r;
}
function Sx(r) {
  const e = {};
  for (const i in r) r[i] !== void 0 && (e[i] = r[i]);
  return e;
}
const am = Object.create(null);
function Ex(r) {
  const e = am[r];
  return e === void 0 && (am[r] = gn("resource")), e;
}
const lg = class ug extends qr {
  constructor(e = {}) {
    super(),
      (this._resourceType = "textureSampler"),
      (this._touched = 0),
      (this._maxAnisotropy = 1),
      (this.destroyed = !1),
      (e = { ...ug.defaultOptions, ...e }),
      (this.addressMode = e.addressMode),
      (this.addressModeU = e.addressModeU ?? this.addressModeU),
      (this.addressModeV = e.addressModeV ?? this.addressModeV),
      (this.addressModeW = e.addressModeW ?? this.addressModeW),
      (this.scaleMode = e.scaleMode),
      (this.magFilter = e.magFilter ?? this.magFilter),
      (this.minFilter = e.minFilter ?? this.minFilter),
      (this.mipmapFilter = e.mipmapFilter ?? this.mipmapFilter),
      (this.lodMinClamp = e.lodMinClamp),
      (this.lodMaxClamp = e.lodMaxClamp),
      (this.compare = e.compare),
      (this.maxAnisotropy = e.maxAnisotropy ?? 1);
  }
  set addressMode(e) {
    (this.addressModeU = e), (this.addressModeV = e), (this.addressModeW = e);
  }
  get addressMode() {
    return this.addressModeU;
  }
  set wrapMode(e) {
    zr(Pi, "TextureStyle.wrapMode is now TextureStyle.addressMode"),
      (this.addressMode = e);
  }
  get wrapMode() {
    return this.addressMode;
  }
  set scaleMode(e) {
    (this.magFilter = e), (this.minFilter = e), (this.mipmapFilter = e);
  }
  get scaleMode() {
    return this.magFilter;
  }
  set maxAnisotropy(e) {
    (this._maxAnisotropy = Math.min(e, 16)),
      this._maxAnisotropy > 1 && (this.scaleMode = "linear");
  }
  get maxAnisotropy() {
    return this._maxAnisotropy;
  }
  get _resourceId() {
    return this._sharedResourceId || this._generateResourceId();
  }
  update() {
    this.emit("change", this), (this._sharedResourceId = null);
  }
  _generateResourceId() {
    const e = `${this.addressModeU}-${this.addressModeV}-${this.addressModeW}-${this.magFilter}-${this.minFilter}-${this.mipmapFilter}-${this.lodMinClamp}-${this.lodMaxClamp}-${this.compare}-${this._maxAnisotropy}`;
    return (this._sharedResourceId = Ex(e)), this._resourceId;
  }
  destroy() {
    (this.destroyed = !0),
      this.emit("destroy", this),
      this.emit("change", this),
      this.removeAllListeners();
  }
};
lg.defaultOptions = { addressMode: "clamp-to-edge", scaleMode: "linear" };
let cg = lg;
const fg = class hg extends qr {
  constructor(e = {}) {
    super(),
      (this.options = e),
      (this.uid = gn("textureSource")),
      (this._resourceType = "textureSource"),
      (this._resourceId = gn("resource")),
      (this.uploadMethodId = "unknown"),
      (this._resolution = 1),
      (this.pixelWidth = 1),
      (this.pixelHeight = 1),
      (this.width = 1),
      (this.height = 1),
      (this.sampleCount = 1),
      (this.mipLevelCount = 1),
      (this.autoGenerateMipmaps = !1),
      (this.format = "rgba8unorm"),
      (this.dimension = "2d"),
      (this.antialias = !1),
      (this._touched = 0),
      (this._batchTick = -1),
      (this._textureBindLocation = -1),
      (e = { ...hg.defaultOptions, ...e }),
      (this.label = e.label ?? ""),
      (this.resource = e.resource),
      (this.autoGarbageCollect = e.autoGarbageCollect),
      (this._resolution = e.resolution),
      e.width
        ? (this.pixelWidth = e.width * this._resolution)
        : (this.pixelWidth = this.resource ? this.resourceWidth ?? 1 : 1),
      e.height
        ? (this.pixelHeight = e.height * this._resolution)
        : (this.pixelHeight = this.resource ? this.resourceHeight ?? 1 : 1),
      (this.width = this.pixelWidth / this._resolution),
      (this.height = this.pixelHeight / this._resolution),
      (this.format = e.format),
      (this.dimension = e.dimensions),
      (this.mipLevelCount = e.mipLevelCount),
      (this.autoGenerateMipmaps = e.autoGenerateMipmaps),
      (this.sampleCount = e.sampleCount),
      (this.antialias = e.antialias),
      (this.alphaMode = e.alphaMode),
      (this.style = new cg(Sx(e))),
      (this.destroyed = !1),
      this._refreshPOT();
  }
  get source() {
    return this;
  }
  get style() {
    return this._style;
  }
  set style(e) {
    this.style !== e &&
      (this._style?.off("change", this._onStyleChange, this),
      (this._style = e),
      this._style?.on("change", this._onStyleChange, this),
      this._onStyleChange());
  }
  get addressMode() {
    return this._style.addressMode;
  }
  set addressMode(e) {
    this._style.addressMode = e;
  }
  get repeatMode() {
    return this._style.addressMode;
  }
  set repeatMode(e) {
    this._style.addressMode = e;
  }
  get magFilter() {
    return this._style.magFilter;
  }
  set magFilter(e) {
    this._style.magFilter = e;
  }
  get minFilter() {
    return this._style.minFilter;
  }
  set minFilter(e) {
    this._style.minFilter = e;
  }
  get mipmapFilter() {
    return this._style.mipmapFilter;
  }
  set mipmapFilter(e) {
    this._style.mipmapFilter = e;
  }
  get lodMinClamp() {
    return this._style.lodMinClamp;
  }
  set lodMinClamp(e) {
    this._style.lodMinClamp = e;
  }
  get lodMaxClamp() {
    return this._style.lodMaxClamp;
  }
  set lodMaxClamp(e) {
    this._style.lodMaxClamp = e;
  }
  _onStyleChange() {
    this.emit("styleChange", this);
  }
  update() {
    if (this.resource) {
      const e = this._resolution;
      if (this.resize(this.resourceWidth / e, this.resourceHeight / e)) return;
    }
    this.emit("update", this);
  }
  destroy() {
    (this.destroyed = !0),
      this.emit("destroy", this),
      this.emit("change", this),
      this._style && (this._style.destroy(), (this._style = null)),
      (this.uploadMethodId = null),
      (this.resource = null),
      this.removeAllListeners();
  }
  unload() {
    (this._resourceId = gn("resource")),
      this.emit("change", this),
      this.emit("unload", this);
  }
  get resourceWidth() {
    const { resource: e } = this;
    return e.naturalWidth || e.videoWidth || e.displayWidth || e.width;
  }
  get resourceHeight() {
    const { resource: e } = this;
    return e.naturalHeight || e.videoHeight || e.displayHeight || e.height;
  }
  get resolution() {
    return this._resolution;
  }
  set resolution(e) {
    this._resolution !== e &&
      ((this._resolution = e),
      (this.width = this.pixelWidth / e),
      (this.height = this.pixelHeight / e));
  }
  resize(e, i, o) {
    o || (o = this._resolution), e || (e = this.width), i || (i = this.height);
    const l = Math.round(e * o),
      c = Math.round(i * o);
    return (
      (this.width = l / o),
      (this.height = c / o),
      (this._resolution = o),
      this.pixelWidth === l && this.pixelHeight === c
        ? !1
        : (this._refreshPOT(),
          (this.pixelWidth = l),
          (this.pixelHeight = c),
          this.emit("resize", this),
          (this._resourceId = gn("resource")),
          this.emit("change", this),
          !0)
    );
  }
  updateMipmaps() {
    this.autoGenerateMipmaps &&
      this.mipLevelCount > 1 &&
      this.emit("updateMipmaps", this);
  }
  set wrapMode(e) {
    this._style.wrapMode = e;
  }
  get wrapMode() {
    return this._style.wrapMode;
  }
  set scaleMode(e) {
    this._style.scaleMode = e;
  }
  get scaleMode() {
    return this._style.scaleMode;
  }
  _refreshPOT() {
    this.isPowerOfTwo = om(this.pixelWidth) && om(this.pixelHeight);
  }
  static test(e) {
    throw new Error("Unimplemented");
  }
};
fg.defaultOptions = {
  resolution: 1,
  format: "bgra8unorm",
  alphaMode: "premultiply-alpha-on-upload",
  dimensions: "2d",
  mipLevelCount: 1,
  autoGenerateMipmaps: !1,
  sampleCount: 1,
  antialias: !1,
  autoGarbageCollect: !1,
};
let fr = fg;
class tf extends fr {
  constructor(e) {
    const i = e.resource || new Float32Array(e.width * e.height * 4);
    let o = e.format;
    o ||
      (i instanceof Float32Array
        ? (o = "rgba32float")
        : i instanceof Int32Array || i instanceof Uint32Array
        ? (o = "rgba32uint")
        : i instanceof Int16Array || i instanceof Uint16Array
        ? (o = "rgba16uint")
        : (i instanceof Int8Array, (o = "bgra8unorm"))),
      super({ ...e, resource: i, format: o }),
      (this.uploadMethodId = "buffer");
  }
  static test(e) {
    return (
      e instanceof Int8Array ||
      e instanceof Uint8Array ||
      e instanceof Uint8ClampedArray ||
      e instanceof Int16Array ||
      e instanceof Uint16Array ||
      e instanceof Int32Array ||
      e instanceof Uint32Array ||
      e instanceof Float32Array
    );
  }
}
tf.extension = ft.TextureSource;
const lm = new Ve();
class Px {
  constructor(e, i) {
    (this.mapCoord = new Ve()),
      (this.uClampFrame = new Float32Array(4)),
      (this.uClampOffset = new Float32Array(2)),
      (this._textureID = -1),
      (this._updateID = 0),
      (this.clampOffset = 0),
      typeof i > "u"
        ? (this.clampMargin = e.width < 10 ? 0 : 0.5)
        : (this.clampMargin = i),
      (this.isSimple = !1),
      (this.texture = e);
  }
  get texture() {
    return this._texture;
  }
  set texture(e) {
    this.texture !== e &&
      (this._texture?.removeListener("update", this.update, this),
      (this._texture = e),
      this._texture.addListener("update", this.update, this),
      this.update());
  }
  multiplyUvs(e, i) {
    i === void 0 && (i = e);
    const o = this.mapCoord;
    for (let l = 0; l < e.length; l += 2) {
      const c = e[l],
        f = e[l + 1];
      (i[l] = c * o.a + f * o.c + o.tx), (i[l + 1] = c * o.b + f * o.d + o.ty);
    }
    return i;
  }
  update() {
    const e = this._texture;
    this._updateID++;
    const i = e.uvs;
    this.mapCoord.set(
      i.x1 - i.x0,
      i.y1 - i.y0,
      i.x3 - i.x0,
      i.y3 - i.y0,
      i.x0,
      i.y0
    );
    const o = e.orig,
      l = e.trim;
    l &&
      (lm.set(
        o.width / l.width,
        0,
        0,
        o.height / l.height,
        -l.x / l.width,
        -l.y / l.height
      ),
      this.mapCoord.append(lm));
    const c = e.source,
      f = this.uClampFrame,
      d = this.clampMargin / c._resolution,
      m = this.clampOffset / c._resolution;
    return (
      (f[0] = (e.frame.x + d + m) / c.width),
      (f[1] = (e.frame.y + d + m) / c.height),
      (f[2] = (e.frame.x + e.frame.width - d + m) / c.width),
      (f[3] = (e.frame.y + e.frame.height - d + m) / c.height),
      (this.uClampOffset[0] = this.clampOffset / c.pixelWidth),
      (this.uClampOffset[1] = this.clampOffset / c.pixelHeight),
      (this.isSimple =
        e.frame.width === c.width &&
        e.frame.height === c.height &&
        e.rotate === 0),
      !0
    );
  }
}
class tt extends qr {
  constructor({
    source: e,
    label: i,
    frame: o,
    orig: l,
    trim: c,
    defaultAnchor: f,
    defaultBorders: d,
    rotate: m,
    dynamic: p,
  } = {}) {
    if (
      (super(),
      (this.uid = gn("texture")),
      (this.uvs = { x0: 0, y0: 0, x1: 0, y1: 0, x2: 0, y2: 0, x3: 0, y3: 0 }),
      (this.frame = new Pr()),
      (this.noFrame = !1),
      (this.dynamic = !1),
      (this.isTexture = !0),
      (this.label = i),
      (this.source = e?.source ?? new fr()),
      (this.noFrame = !o),
      o)
    )
      this.frame.copyFrom(o);
    else {
      const { width: g, height: v } = this._source;
      (this.frame.width = g), (this.frame.height = v);
    }
    (this.orig = l || this.frame),
      (this.trim = c),
      (this.rotate = m ?? 0),
      (this.defaultAnchor = f),
      (this.defaultBorders = d),
      (this.destroyed = !1),
      (this.dynamic = p || !1),
      this.updateUvs();
  }
  set source(e) {
    this._source && this._source.off("resize", this.update, this),
      (this._source = e),
      e.on("resize", this.update, this),
      this.emit("update", this);
  }
  get source() {
    return this._source;
  }
  get textureMatrix() {
    return (
      this._textureMatrix || (this._textureMatrix = new Px(this)),
      this._textureMatrix
    );
  }
  get width() {
    return this.orig.width;
  }
  get height() {
    return this.orig.height;
  }
  updateUvs() {
    const { uvs: e, frame: i } = this,
      { width: o, height: l } = this._source,
      c = i.x / o,
      f = i.y / l,
      d = i.width / o,
      m = i.height / l;
    let p = this.rotate;
    if (p) {
      const g = d / 2,
        v = m / 2,
        x = c + g,
        w = f + v;
      (p = qe.add(p, qe.NW)),
        (e.x0 = x + g * qe.uX(p)),
        (e.y0 = w + v * qe.uY(p)),
        (p = qe.add(p, 2)),
        (e.x1 = x + g * qe.uX(p)),
        (e.y1 = w + v * qe.uY(p)),
        (p = qe.add(p, 2)),
        (e.x2 = x + g * qe.uX(p)),
        (e.y2 = w + v * qe.uY(p)),
        (p = qe.add(p, 2)),
        (e.x3 = x + g * qe.uX(p)),
        (e.y3 = w + v * qe.uY(p));
    } else
      (e.x0 = c),
        (e.y0 = f),
        (e.x1 = c + d),
        (e.y1 = f),
        (e.x2 = c + d),
        (e.y2 = f + m),
        (e.x3 = c),
        (e.y3 = f + m);
  }
  destroy(e = !1) {
    this._source && e && (this._source.destroy(), (this._source = null)),
      (this._textureMatrix = null),
      (this.destroyed = !0),
      this.emit("destroy", this),
      this.removeAllListeners();
  }
  update() {
    this.noFrame &&
      ((this.frame.width = this._source.width),
      (this.frame.height = this._source.height)),
      this.updateUvs(),
      this.emit("update", this);
  }
  get baseTexture() {
    return zr(Pi, "Texture.baseTexture is now Texture.source"), this._source;
  }
}
tt.EMPTY = new tt({ label: "EMPTY", source: new fr({ label: "EMPTY" }) });
tt.EMPTY.destroy = ag;
tt.WHITE = new tt({
  source: new tf({
    resource: new Uint8Array([255, 255, 255, 255]),
    width: 1,
    height: 1,
    alphaMode: "premultiply-alpha-on-upload",
    label: "WHITE",
  }),
  label: "WHITE",
});
tt.WHITE.destroy = ag;
function Ax(r, e, i) {
  const { width: o, height: l } = i.orig,
    c = i.trim;
  if (c) {
    const f = c.width,
      d = c.height;
    (r.minX = c.x - e._x * o),
      (r.maxX = r.minX + f),
      (r.minY = c.y - e._y * l),
      (r.maxY = r.minY + d);
  } else
    (r.minX = -e._x * o),
      (r.maxX = r.minX + o),
      (r.minY = -e._y * l),
      (r.maxY = r.minY + l);
}
const um = new Ve();
class wn {
  constructor(e = 1 / 0, i = 1 / 0, o = -1 / 0, l = -1 / 0) {
    (this.minX = 1 / 0),
      (this.minY = 1 / 0),
      (this.maxX = -1 / 0),
      (this.maxY = -1 / 0),
      (this.matrix = um),
      (this.minX = e),
      (this.minY = i),
      (this.maxX = o),
      (this.maxY = l);
  }
  isEmpty() {
    return this.minX > this.maxX || this.minY > this.maxY;
  }
  get rectangle() {
    this._rectangle || (this._rectangle = new Pr());
    const e = this._rectangle;
    return (
      this.minX > this.maxX || this.minY > this.maxY
        ? ((e.x = 0), (e.y = 0), (e.width = 0), (e.height = 0))
        : e.copyFromBounds(this),
      e
    );
  }
  clear() {
    return (
      (this.minX = 1 / 0),
      (this.minY = 1 / 0),
      (this.maxX = -1 / 0),
      (this.maxY = -1 / 0),
      (this.matrix = um),
      this
    );
  }
  set(e, i, o, l) {
    (this.minX = e), (this.minY = i), (this.maxX = o), (this.maxY = l);
  }
  addFrame(e, i, o, l, c) {
    c || (c = this.matrix);
    const f = c.a,
      d = c.b,
      m = c.c,
      p = c.d,
      g = c.tx,
      v = c.ty;
    let x = this.minX,
      w = this.minY,
      E = this.maxX,
      k = this.maxY,
      _ = f * e + m * i + g,
      A = d * e + p * i + v;
    _ < x && (x = _),
      A < w && (w = A),
      _ > E && (E = _),
      A > k && (k = A),
      (_ = f * o + m * i + g),
      (A = d * o + p * i + v),
      _ < x && (x = _),
      A < w && (w = A),
      _ > E && (E = _),
      A > k && (k = A),
      (_ = f * e + m * l + g),
      (A = d * e + p * l + v),
      _ < x && (x = _),
      A < w && (w = A),
      _ > E && (E = _),
      A > k && (k = A),
      (_ = f * o + m * l + g),
      (A = d * o + p * l + v),
      _ < x && (x = _),
      A < w && (w = A),
      _ > E && (E = _),
      A > k && (k = A),
      (this.minX = x),
      (this.minY = w),
      (this.maxX = E),
      (this.maxY = k);
  }
  addRect(e, i) {
    this.addFrame(e.x, e.y, e.x + e.width, e.y + e.height, i);
  }
  addBounds(e, i) {
    this.addFrame(e.minX, e.minY, e.maxX, e.maxY, i);
  }
  addBoundsMask(e) {
    (this.minX = this.minX > e.minX ? this.minX : e.minX),
      (this.minY = this.minY > e.minY ? this.minY : e.minY),
      (this.maxX = this.maxX < e.maxX ? this.maxX : e.maxX),
      (this.maxY = this.maxY < e.maxY ? this.maxY : e.maxY);
  }
  applyMatrix(e) {
    const i = this.minX,
      o = this.minY,
      l = this.maxX,
      c = this.maxY,
      { a: f, b: d, c: m, d: p, tx: g, ty: v } = e;
    let x = f * i + m * o + g,
      w = d * i + p * o + v;
    (this.minX = x),
      (this.minY = w),
      (this.maxX = x),
      (this.maxY = w),
      (x = f * l + m * o + g),
      (w = d * l + p * o + v),
      (this.minX = x < this.minX ? x : this.minX),
      (this.minY = w < this.minY ? w : this.minY),
      (this.maxX = x > this.maxX ? x : this.maxX),
      (this.maxY = w > this.maxY ? w : this.maxY),
      (x = f * i + m * c + g),
      (w = d * i + p * c + v),
      (this.minX = x < this.minX ? x : this.minX),
      (this.minY = w < this.minY ? w : this.minY),
      (this.maxX = x > this.maxX ? x : this.maxX),
      (this.maxY = w > this.maxY ? w : this.maxY),
      (x = f * l + m * c + g),
      (w = d * l + p * c + v),
      (this.minX = x < this.minX ? x : this.minX),
      (this.minY = w < this.minY ? w : this.minY),
      (this.maxX = x > this.maxX ? x : this.maxX),
      (this.maxY = w > this.maxY ? w : this.maxY);
  }
  fit(e) {
    return (
      this.minX < e.left && (this.minX = e.left),
      this.maxX > e.right && (this.maxX = e.right),
      this.minY < e.top && (this.minY = e.top),
      this.maxY > e.bottom && (this.maxY = e.bottom),
      this
    );
  }
  fitBounds(e, i, o, l) {
    return (
      this.minX < e && (this.minX = e),
      this.maxX > i && (this.maxX = i),
      this.minY < o && (this.minY = o),
      this.maxY > l && (this.maxY = l),
      this
    );
  }
  pad(e, i = e) {
    return (
      (this.minX -= e),
      (this.maxX += e),
      (this.minY -= i),
      (this.maxY += i),
      this
    );
  }
  ceil() {
    return (
      (this.minX = Math.floor(this.minX)),
      (this.minY = Math.floor(this.minY)),
      (this.maxX = Math.ceil(this.maxX)),
      (this.maxY = Math.ceil(this.maxY)),
      this
    );
  }
  clone() {
    return new wn(this.minX, this.minY, this.maxX, this.maxY);
  }
  scale(e, i = e) {
    return (
      (this.minX *= e),
      (this.minY *= i),
      (this.maxX *= e),
      (this.maxY *= i),
      this
    );
  }
  get x() {
    return this.minX;
  }
  set x(e) {
    const i = this.maxX - this.minX;
    (this.minX = e), (this.maxX = e + i);
  }
  get y() {
    return this.minY;
  }
  set y(e) {
    const i = this.maxY - this.minY;
    (this.minY = e), (this.maxY = e + i);
  }
  get width() {
    return this.maxX - this.minX;
  }
  set width(e) {
    this.maxX = this.minX + e;
  }
  get height() {
    return this.maxY - this.minY;
  }
  set height(e) {
    this.maxY = this.minY + e;
  }
  get left() {
    return this.minX;
  }
  get right() {
    return this.maxX;
  }
  get top() {
    return this.minY;
  }
  get bottom() {
    return this.maxY;
  }
  get isPositive() {
    return this.maxX - this.minX > 0 && this.maxY - this.minY > 0;
  }
  get isValid() {
    return this.minX + this.minY !== 1 / 0;
  }
  addVertexData(e, i, o, l) {
    let c = this.minX,
      f = this.minY,
      d = this.maxX,
      m = this.maxY;
    l || (l = this.matrix);
    const p = l.a,
      g = l.b,
      v = l.c,
      x = l.d,
      w = l.tx,
      E = l.ty;
    for (let k = i; k < o; k += 2) {
      const _ = e[k],
        A = e[k + 1],
        b = p * _ + v * A + w,
        N = g * _ + x * A + E;
      (c = b < c ? b : c),
        (f = N < f ? N : f),
        (d = b > d ? b : d),
        (m = N > m ? N : m);
    }
    (this.minX = c), (this.minY = f), (this.maxX = d), (this.maxY = m);
  }
  containsPoint(e, i) {
    return this.minX <= e && this.minY <= i && this.maxX >= e && this.maxY >= i;
  }
  toString() {
    return `[pixi.js:Bounds minX=${this.minX} minY=${this.minY} maxX=${this.maxX} maxY=${this.maxY} width=${this.width} height=${this.height}]`;
  }
  copyFrom(e) {
    return (
      (this.minX = e.minX),
      (this.minY = e.minY),
      (this.maxX = e.maxX),
      (this.maxY = e.maxY),
      this
    );
  }
}
var Cx = { grad: 0.9, turn: 360, rad: 360 / (2 * Math.PI) },
  Ur = function (r) {
    return typeof r == "string" ? r.length > 0 : typeof r == "number";
  },
  at = function (r, e, i) {
    return (
      e === void 0 && (e = 0),
      i === void 0 && (i = Math.pow(10, e)),
      Math.round(i * r) / i + 0
    );
  },
  Yt = function (r, e, i) {
    return (
      e === void 0 && (e = 0),
      i === void 0 && (i = 1),
      r > i ? i : r > e ? r : e
    );
  },
  dg = function (r) {
    return (r = isFinite(r) ? r % 360 : 0) > 0 ? r : r + 360;
  },
  cm = function (r) {
    return {
      r: Yt(r.r, 0, 255),
      g: Yt(r.g, 0, 255),
      b: Yt(r.b, 0, 255),
      a: Yt(r.a),
    };
  },
  fc = function (r) {
    return { r: at(r.r), g: at(r.g), b: at(r.b), a: at(r.a, 3) };
  },
  kx = /^#([0-9a-f]{3,8})$/i,
  Jo = function (r) {
    var e = r.toString(16);
    return e.length < 2 ? "0" + e : e;
  },
  pg = function (r) {
    var e = r.r,
      i = r.g,
      o = r.b,
      l = r.a,
      c = Math.max(e, i, o),
      f = c - Math.min(e, i, o),
      d = f
        ? c === e
          ? (i - o) / f
          : c === i
          ? 2 + (o - e) / f
          : 4 + (e - i) / f
        : 0;
    return {
      h: 60 * (d < 0 ? d + 6 : d),
      s: c ? (f / c) * 100 : 0,
      v: (c / 255) * 100,
      a: l,
    };
  },
  mg = function (r) {
    var e = r.h,
      i = r.s,
      o = r.v,
      l = r.a;
    (e = (e / 360) * 6), (i /= 100), (o /= 100);
    var c = Math.floor(e),
      f = o * (1 - i),
      d = o * (1 - (e - c) * i),
      m = o * (1 - (1 - e + c) * i),
      p = c % 6;
    return {
      r: 255 * [o, d, f, f, m, o][p],
      g: 255 * [m, o, o, d, f, f][p],
      b: 255 * [f, f, m, o, o, d][p],
      a: l,
    };
  },
  fm = function (r) {
    return { h: dg(r.h), s: Yt(r.s, 0, 100), l: Yt(r.l, 0, 100), a: Yt(r.a) };
  },
  hm = function (r) {
    return { h: at(r.h), s: at(r.s), l: at(r.l), a: at(r.a, 3) };
  },
  dm = function (r) {
    return mg(
      ((i = (e = r).s),
      {
        h: e.h,
        s:
          (i *= ((o = e.l) < 50 ? o : 100 - o) / 100) > 0
            ? ((2 * i) / (o + i)) * 100
            : 0,
        v: o + i,
        a: e.a,
      })
    );
    var e, i, o;
  },
  Cs = function (r) {
    return {
      h: (e = pg(r)).h,
      s:
        (l = ((200 - (i = e.s)) * (o = e.v)) / 100) > 0 && l < 200
          ? ((i * o) / 100 / (l <= 100 ? l : 200 - l)) * 100
          : 0,
      l: l / 2,
      a: e.a,
    };
    var e, i, o, l;
  },
  Rx =
    /^hsla?\(\s*([+-]?\d*\.?\d+)(deg|rad|grad|turn)?\s*,\s*([+-]?\d*\.?\d+)%\s*,\s*([+-]?\d*\.?\d+)%\s*(?:,\s*([+-]?\d*\.?\d+)(%)?\s*)?\)$/i,
  bx =
    /^hsla?\(\s*([+-]?\d*\.?\d+)(deg|rad|grad|turn)?\s+([+-]?\d*\.?\d+)%\s+([+-]?\d*\.?\d+)%\s*(?:\/\s*([+-]?\d*\.?\d+)(%)?\s*)?\)$/i,
  Tx =
    /^rgba?\(\s*([+-]?\d*\.?\d+)(%)?\s*,\s*([+-]?\d*\.?\d+)(%)?\s*,\s*([+-]?\d*\.?\d+)(%)?\s*(?:,\s*([+-]?\d*\.?\d+)(%)?\s*)?\)$/i,
  Ox =
    /^rgba?\(\s*([+-]?\d*\.?\d+)(%)?\s+([+-]?\d*\.?\d+)(%)?\s+([+-]?\d*\.?\d+)(%)?\s*(?:\/\s*([+-]?\d*\.?\d+)(%)?\s*)?\)$/i,
  jc = {
    string: [
      [
        function (r) {
          var e = kx.exec(r);
          return e
            ? (r = e[1]).length <= 4
              ? {
                  r: parseInt(r[0] + r[0], 16),
                  g: parseInt(r[1] + r[1], 16),
                  b: parseInt(r[2] + r[2], 16),
                  a:
                    r.length === 4 ? at(parseInt(r[3] + r[3], 16) / 255, 2) : 1,
                }
              : r.length === 6 || r.length === 8
              ? {
                  r: parseInt(r.substr(0, 2), 16),
                  g: parseInt(r.substr(2, 2), 16),
                  b: parseInt(r.substr(4, 2), 16),
                  a:
                    r.length === 8
                      ? at(parseInt(r.substr(6, 2), 16) / 255, 2)
                      : 1,
                }
              : null
            : null;
        },
        "hex",
      ],
      [
        function (r) {
          var e = Tx.exec(r) || Ox.exec(r);
          return e
            ? e[2] !== e[4] || e[4] !== e[6]
              ? null
              : cm({
                  r: Number(e[1]) / (e[2] ? 100 / 255 : 1),
                  g: Number(e[3]) / (e[4] ? 100 / 255 : 1),
                  b: Number(e[5]) / (e[6] ? 100 / 255 : 1),
                  a: e[7] === void 0 ? 1 : Number(e[7]) / (e[8] ? 100 : 1),
                })
            : null;
        },
        "rgb",
      ],
      [
        function (r) {
          var e = Rx.exec(r) || bx.exec(r);
          if (!e) return null;
          var i,
            o,
            l = fm({
              h:
                ((i = e[1]),
                (o = e[2]),
                o === void 0 && (o = "deg"),
                Number(i) * (Cx[o] || 1)),
              s: Number(e[3]),
              l: Number(e[4]),
              a: e[5] === void 0 ? 1 : Number(e[5]) / (e[6] ? 100 : 1),
            });
          return dm(l);
        },
        "hsl",
      ],
    ],
    object: [
      [
        function (r) {
          var e = r.r,
            i = r.g,
            o = r.b,
            l = r.a,
            c = l === void 0 ? 1 : l;
          return Ur(e) && Ur(i) && Ur(o)
            ? cm({ r: Number(e), g: Number(i), b: Number(o), a: Number(c) })
            : null;
        },
        "rgb",
      ],
      [
        function (r) {
          var e = r.h,
            i = r.s,
            o = r.l,
            l = r.a,
            c = l === void 0 ? 1 : l;
          if (!Ur(e) || !Ur(i) || !Ur(o)) return null;
          var f = fm({
            h: Number(e),
            s: Number(i),
            l: Number(o),
            a: Number(c),
          });
          return dm(f);
        },
        "hsl",
      ],
      [
        function (r) {
          var e = r.h,
            i = r.s,
            o = r.v,
            l = r.a,
            c = l === void 0 ? 1 : l;
          if (!Ur(e) || !Ur(i) || !Ur(o)) return null;
          var f = (function (d) {
            return {
              h: dg(d.h),
              s: Yt(d.s, 0, 100),
              v: Yt(d.v, 0, 100),
              a: Yt(d.a),
            };
          })({ h: Number(e), s: Number(i), v: Number(o), a: Number(c) });
          return mg(f);
        },
        "hsv",
      ],
    ],
  },
  pm = function (r, e) {
    for (var i = 0; i < e.length; i++) {
      var o = e[i][0](r);
      if (o) return [o, e[i][1]];
    }
    return [null, void 0];
  },
  Mx = function (r) {
    return typeof r == "string"
      ? pm(r.trim(), jc.string)
      : typeof r == "object" && r !== null
      ? pm(r, jc.object)
      : [null, void 0];
  },
  hc = function (r, e) {
    var i = Cs(r);
    return { h: i.h, s: Yt(i.s + 100 * e, 0, 100), l: i.l, a: i.a };
  },
  dc = function (r) {
    return (299 * r.r + 587 * r.g + 114 * r.b) / 1e3 / 255;
  },
  mm = function (r, e) {
    var i = Cs(r);
    return { h: i.h, s: i.s, l: Yt(i.l + 100 * e, 0, 100), a: i.a };
  },
  $c = (function () {
    function r(e) {
      (this.parsed = Mx(e)[0]),
        (this.rgba = this.parsed || { r: 0, g: 0, b: 0, a: 1 });
    }
    return (
      (r.prototype.isValid = function () {
        return this.parsed !== null;
      }),
      (r.prototype.brightness = function () {
        return at(dc(this.rgba), 2);
      }),
      (r.prototype.isDark = function () {
        return dc(this.rgba) < 0.5;
      }),
      (r.prototype.isLight = function () {
        return dc(this.rgba) >= 0.5;
      }),
      (r.prototype.toHex = function () {
        return (
          (e = fc(this.rgba)),
          (i = e.r),
          (o = e.g),
          (l = e.b),
          (f = (c = e.a) < 1 ? Jo(at(255 * c)) : ""),
          "#" + Jo(i) + Jo(o) + Jo(l) + f
        );
        var e, i, o, l, c, f;
      }),
      (r.prototype.toRgb = function () {
        return fc(this.rgba);
      }),
      (r.prototype.toRgbString = function () {
        return (
          (e = fc(this.rgba)),
          (i = e.r),
          (o = e.g),
          (l = e.b),
          (c = e.a) < 1
            ? "rgba(" + i + ", " + o + ", " + l + ", " + c + ")"
            : "rgb(" + i + ", " + o + ", " + l + ")"
        );
        var e, i, o, l, c;
      }),
      (r.prototype.toHsl = function () {
        return hm(Cs(this.rgba));
      }),
      (r.prototype.toHslString = function () {
        return (
          (e = hm(Cs(this.rgba))),
          (i = e.h),
          (o = e.s),
          (l = e.l),
          (c = e.a) < 1
            ? "hsla(" + i + ", " + o + "%, " + l + "%, " + c + ")"
            : "hsl(" + i + ", " + o + "%, " + l + "%)"
        );
        var e, i, o, l, c;
      }),
      (r.prototype.toHsv = function () {
        return (
          (e = pg(this.rgba)),
          { h: at(e.h), s: at(e.s), v: at(e.v), a: at(e.a, 3) }
        );
        var e;
      }),
      (r.prototype.invert = function () {
        return Sr({
          r: 255 - (e = this.rgba).r,
          g: 255 - e.g,
          b: 255 - e.b,
          a: e.a,
        });
        var e;
      }),
      (r.prototype.saturate = function (e) {
        return e === void 0 && (e = 0.1), Sr(hc(this.rgba, e));
      }),
      (r.prototype.desaturate = function (e) {
        return e === void 0 && (e = 0.1), Sr(hc(this.rgba, -e));
      }),
      (r.prototype.grayscale = function () {
        return Sr(hc(this.rgba, -1));
      }),
      (r.prototype.lighten = function (e) {
        return e === void 0 && (e = 0.1), Sr(mm(this.rgba, e));
      }),
      (r.prototype.darken = function (e) {
        return e === void 0 && (e = 0.1), Sr(mm(this.rgba, -e));
      }),
      (r.prototype.rotate = function (e) {
        return e === void 0 && (e = 15), this.hue(this.hue() + e);
      }),
      (r.prototype.alpha = function (e) {
        return typeof e == "number"
          ? Sr({ r: (i = this.rgba).r, g: i.g, b: i.b, a: e })
          : at(this.rgba.a, 3);
        var i;
      }),
      (r.prototype.hue = function (e) {
        var i = Cs(this.rgba);
        return typeof e == "number"
          ? Sr({ h: e, s: i.s, l: i.l, a: i.a })
          : at(i.h);
      }),
      (r.prototype.isEqual = function (e) {
        return this.toHex() === Sr(e).toHex();
      }),
      r
    );
  })(),
  Sr = function (r) {
    return r instanceof $c ? r : new $c(r);
  },
  ym = [],
  Ix = function (r) {
    r.forEach(function (e) {
      ym.indexOf(e) < 0 && (e($c, jc), ym.push(e));
    });
  };
function Lx(r, e) {
  var i = {
      white: "#ffffff",
      bisque: "#ffe4c4",
      blue: "#0000ff",
      cadetblue: "#5f9ea0",
      chartreuse: "#7fff00",
      chocolate: "#d2691e",
      coral: "#ff7f50",
      antiquewhite: "#faebd7",
      aqua: "#00ffff",
      azure: "#f0ffff",
      whitesmoke: "#f5f5f5",
      papayawhip: "#ffefd5",
      plum: "#dda0dd",
      blanchedalmond: "#ffebcd",
      black: "#000000",
      gold: "#ffd700",
      goldenrod: "#daa520",
      gainsboro: "#dcdcdc",
      cornsilk: "#fff8dc",
      cornflowerblue: "#6495ed",
      burlywood: "#deb887",
      aquamarine: "#7fffd4",
      beige: "#f5f5dc",
      crimson: "#dc143c",
      cyan: "#00ffff",
      darkblue: "#00008b",
      darkcyan: "#008b8b",
      darkgoldenrod: "#b8860b",
      darkkhaki: "#bdb76b",
      darkgray: "#a9a9a9",
      darkgreen: "#006400",
      darkgrey: "#a9a9a9",
      peachpuff: "#ffdab9",
      darkmagenta: "#8b008b",
      darkred: "#8b0000",
      darkorchid: "#9932cc",
      darkorange: "#ff8c00",
      darkslateblue: "#483d8b",
      gray: "#808080",
      darkslategray: "#2f4f4f",
      darkslategrey: "#2f4f4f",
      deeppink: "#ff1493",
      deepskyblue: "#00bfff",
      wheat: "#f5deb3",
      firebrick: "#b22222",
      floralwhite: "#fffaf0",
      ghostwhite: "#f8f8ff",
      darkviolet: "#9400d3",
      magenta: "#ff00ff",
      green: "#008000",
      dodgerblue: "#1e90ff",
      grey: "#808080",
      honeydew: "#f0fff0",
      hotpink: "#ff69b4",
      blueviolet: "#8a2be2",
      forestgreen: "#228b22",
      lawngreen: "#7cfc00",
      indianred: "#cd5c5c",
      indigo: "#4b0082",
      fuchsia: "#ff00ff",
      brown: "#a52a2a",
      maroon: "#800000",
      mediumblue: "#0000cd",
      lightcoral: "#f08080",
      darkturquoise: "#00ced1",
      lightcyan: "#e0ffff",
      ivory: "#fffff0",
      lightyellow: "#ffffe0",
      lightsalmon: "#ffa07a",
      lightseagreen: "#20b2aa",
      linen: "#faf0e6",
      mediumaquamarine: "#66cdaa",
      lemonchiffon: "#fffacd",
      lime: "#00ff00",
      khaki: "#f0e68c",
      mediumseagreen: "#3cb371",
      limegreen: "#32cd32",
      mediumspringgreen: "#00fa9a",
      lightskyblue: "#87cefa",
      lightblue: "#add8e6",
      midnightblue: "#191970",
      lightpink: "#ffb6c1",
      mistyrose: "#ffe4e1",
      moccasin: "#ffe4b5",
      mintcream: "#f5fffa",
      lightslategray: "#778899",
      lightslategrey: "#778899",
      navajowhite: "#ffdead",
      navy: "#000080",
      mediumvioletred: "#c71585",
      powderblue: "#b0e0e6",
      palegoldenrod: "#eee8aa",
      oldlace: "#fdf5e6",
      paleturquoise: "#afeeee",
      mediumturquoise: "#48d1cc",
      mediumorchid: "#ba55d3",
      rebeccapurple: "#663399",
      lightsteelblue: "#b0c4de",
      mediumslateblue: "#7b68ee",
      thistle: "#d8bfd8",
      tan: "#d2b48c",
      orchid: "#da70d6",
      mediumpurple: "#9370db",
      purple: "#800080",
      pink: "#ffc0cb",
      skyblue: "#87ceeb",
      springgreen: "#00ff7f",
      palegreen: "#98fb98",
      red: "#ff0000",
      yellow: "#ffff00",
      slateblue: "#6a5acd",
      lavenderblush: "#fff0f5",
      peru: "#cd853f",
      palevioletred: "#db7093",
      violet: "#ee82ee",
      teal: "#008080",
      slategray: "#708090",
      slategrey: "#708090",
      aliceblue: "#f0f8ff",
      darkseagreen: "#8fbc8f",
      darkolivegreen: "#556b2f",
      greenyellow: "#adff2f",
      seagreen: "#2e8b57",
      seashell: "#fff5ee",
      tomato: "#ff6347",
      silver: "#c0c0c0",
      sienna: "#a0522d",
      lavender: "#e6e6fa",
      lightgreen: "#90ee90",
      orange: "#ffa500",
      orangered: "#ff4500",
      steelblue: "#4682b4",
      royalblue: "#4169e1",
      turquoise: "#40e0d0",
      yellowgreen: "#9acd32",
      salmon: "#fa8072",
      saddlebrown: "#8b4513",
      sandybrown: "#f4a460",
      rosybrown: "#bc8f8f",
      darksalmon: "#e9967a",
      lightgoldenrodyellow: "#fafad2",
      snow: "#fffafa",
      lightgrey: "#d3d3d3",
      lightgray: "#d3d3d3",
      dimgray: "#696969",
      dimgrey: "#696969",
      olivedrab: "#6b8e23",
      olive: "#808000",
    },
    o = {};
  for (var l in i) o[i[l]] = l;
  var c = {};
  (r.prototype.toName = function (f) {
    if (!(this.rgba.a || this.rgba.r || this.rgba.g || this.rgba.b))
      return "transparent";
    var d,
      m,
      p = o[this.toHex()];
    if (p) return p;
    if (f?.closest) {
      var g = this.toRgb(),
        v = 1 / 0,
        x = "black";
      if (!c.length) for (var w in i) c[w] = new r(i[w]).toRgb();
      for (var E in i) {
        var k =
          ((d = g),
          (m = c[E]),
          Math.pow(d.r - m.r, 2) +
            Math.pow(d.g - m.g, 2) +
            Math.pow(d.b - m.b, 2));
        k < v && ((v = k), (x = E));
      }
      return x;
    }
  }),
    e.string.push([
      function (f) {
        var d = f.toLowerCase(),
          m = d === "transparent" ? "#0000" : i[d];
        return m ? new r(m).toRgb() : null;
      },
      "name",
    ]);
}
Ix([Lx]);
const Ai = class Ss {
  constructor(e = 16777215) {
    (this._value = null),
      (this._components = new Float32Array(4)),
      this._components.fill(1),
      (this._int = 16777215),
      (this.value = e);
  }
  get red() {
    return this._components[0];
  }
  get green() {
    return this._components[1];
  }
  get blue() {
    return this._components[2];
  }
  get alpha() {
    return this._components[3];
  }
  setValue(e) {
    return (this.value = e), this;
  }
  set value(e) {
    if (e instanceof Ss)
      (this._value = this._cloneSource(e._value)),
        (this._int = e._int),
        this._components.set(e._components);
    else {
      if (e === null) throw new Error("Cannot set Color#value to null");
      (this._value === null || !this._isSourceEqual(this._value, e)) &&
        ((this._value = this._cloneSource(e)), this._normalize(this._value));
    }
  }
  get value() {
    return this._value;
  }
  _cloneSource(e) {
    return typeof e == "string" ||
      typeof e == "number" ||
      e instanceof Number ||
      e === null
      ? e
      : Array.isArray(e) || ArrayBuffer.isView(e)
      ? e.slice(0)
      : typeof e == "object" && e !== null
      ? { ...e }
      : e;
  }
  _isSourceEqual(e, i) {
    const o = typeof e;
    if (o !== typeof i) return !1;
    if (o === "number" || o === "string" || e instanceof Number) return e === i;
    if (
      (Array.isArray(e) && Array.isArray(i)) ||
      (ArrayBuffer.isView(e) && ArrayBuffer.isView(i))
    )
      return e.length !== i.length ? !1 : e.every((c, f) => c === i[f]);
    if (e !== null && i !== null) {
      const c = Object.keys(e),
        f = Object.keys(i);
      return c.length !== f.length ? !1 : c.every((d) => e[d] === i[d]);
    }
    return e === i;
  }
  toRgba() {
    const [e, i, o, l] = this._components;
    return { r: e, g: i, b: o, a: l };
  }
  toRgb() {
    const [e, i, o] = this._components;
    return { r: e, g: i, b: o };
  }
  toRgbaString() {
    const [e, i, o] = this.toUint8RgbArray();
    return `rgba(${e},${i},${o},${this.alpha})`;
  }
  toUint8RgbArray(e) {
    const [i, o, l] = this._components;
    return (
      this._arrayRgb || (this._arrayRgb = []),
      e || (e = this._arrayRgb),
      (e[0] = Math.round(i * 255)),
      (e[1] = Math.round(o * 255)),
      (e[2] = Math.round(l * 255)),
      e
    );
  }
  toArray(e) {
    this._arrayRgba || (this._arrayRgba = []), e || (e = this._arrayRgba);
    const [i, o, l, c] = this._components;
    return (e[0] = i), (e[1] = o), (e[2] = l), (e[3] = c), e;
  }
  toRgbArray(e) {
    this._arrayRgb || (this._arrayRgb = []), e || (e = this._arrayRgb);
    const [i, o, l] = this._components;
    return (e[0] = i), (e[1] = o), (e[2] = l), e;
  }
  toNumber() {
    return this._int;
  }
  toBgrNumber() {
    const [e, i, o] = this.toUint8RgbArray();
    return (o << 16) + (i << 8) + e;
  }
  toLittleEndianNumber() {
    const e = this._int;
    return (e >> 16) + (e & 65280) + ((e & 255) << 16);
  }
  multiply(e) {
    const [i, o, l, c] = Ss._temp.setValue(e)._components;
    return (
      (this._components[0] *= i),
      (this._components[1] *= o),
      (this._components[2] *= l),
      (this._components[3] *= c),
      this._refreshInt(),
      (this._value = null),
      this
    );
  }
  premultiply(e, i = !0) {
    return (
      i &&
        ((this._components[0] *= e),
        (this._components[1] *= e),
        (this._components[2] *= e)),
      (this._components[3] = e),
      this._refreshInt(),
      (this._value = null),
      this
    );
  }
  toPremultiplied(e, i = !0) {
    if (e === 1) return (255 << 24) + this._int;
    if (e === 0) return i ? 0 : this._int;
    let o = (this._int >> 16) & 255,
      l = (this._int >> 8) & 255,
      c = this._int & 255;
    return (
      i &&
        ((o = (o * e + 0.5) | 0),
        (l = (l * e + 0.5) | 0),
        (c = (c * e + 0.5) | 0)),
      ((e * 255) << 24) + (o << 16) + (l << 8) + c
    );
  }
  toHex() {
    const e = this._int.toString(16);
    return `#${"000000".substring(0, 6 - e.length) + e}`;
  }
  toHexa() {
    const i = Math.round(this._components[3] * 255).toString(16);
    return this.toHex() + "00".substring(0, 2 - i.length) + i;
  }
  setAlpha(e) {
    return (this._components[3] = this._clamp(e)), this;
  }
  _normalize(e) {
    let i, o, l, c;
    if (
      (typeof e == "number" || e instanceof Number) &&
      e >= 0 &&
      e <= 16777215
    ) {
      const f = e;
      (i = ((f >> 16) & 255) / 255),
        (o = ((f >> 8) & 255) / 255),
        (l = (f & 255) / 255),
        (c = 1);
    } else if (
      (Array.isArray(e) || e instanceof Float32Array) &&
      e.length >= 3 &&
      e.length <= 4
    )
      (e = this._clamp(e)), ([i, o, l, c = 1] = e);
    else if (
      (e instanceof Uint8Array || e instanceof Uint8ClampedArray) &&
      e.length >= 3 &&
      e.length <= 4
    )
      (e = this._clamp(e, 0, 255)),
        ([i, o, l, c = 255] = e),
        (i /= 255),
        (o /= 255),
        (l /= 255),
        (c /= 255);
    else if (typeof e == "string" || typeof e == "object") {
      if (typeof e == "string") {
        const d = Ss.HEX_PATTERN.exec(e);
        d && (e = `#${d[2]}`);
      }
      const f = Sr(e);
      f.isValid() &&
        (({ r: i, g: o, b: l, a: c } = f.rgba),
        (i /= 255),
        (o /= 255),
        (l /= 255));
    }
    if (i !== void 0)
      (this._components[0] = i),
        (this._components[1] = o),
        (this._components[2] = l),
        (this._components[3] = c),
        this._refreshInt();
    else throw new Error(`Unable to convert color ${e}`);
  }
  _refreshInt() {
    this._clamp(this._components);
    const [e, i, o] = this._components;
    this._int = ((e * 255) << 16) + ((i * 255) << 8) + ((o * 255) | 0);
  }
  _clamp(e, i = 0, o = 1) {
    return typeof e == "number"
      ? Math.min(Math.max(e, i), o)
      : (e.forEach((l, c) => {
          e[c] = Math.min(Math.max(l, i), o);
        }),
        e);
  }
  static isColorLike(e) {
    return (
      typeof e == "number" ||
      typeof e == "string" ||
      e instanceof Number ||
      e instanceof Ss ||
      Array.isArray(e) ||
      e instanceof Uint8Array ||
      e instanceof Uint8ClampedArray ||
      e instanceof Float32Array ||
      (e.r !== void 0 && e.g !== void 0 && e.b !== void 0) ||
      (e.r !== void 0 && e.g !== void 0 && e.b !== void 0 && e.a !== void 0) ||
      (e.h !== void 0 && e.s !== void 0 && e.l !== void 0) ||
      (e.h !== void 0 && e.s !== void 0 && e.l !== void 0 && e.a !== void 0) ||
      (e.h !== void 0 && e.s !== void 0 && e.v !== void 0) ||
      (e.h !== void 0 && e.s !== void 0 && e.v !== void 0 && e.a !== void 0)
    );
  }
};
Ai.shared = new Ai();
Ai._temp = new Ai();
Ai.HEX_PATTERN = /^(#|0x)?(([a-f0-9]{3}){1,2}([a-f0-9]{2})?)$/i;
let Fx = Ai;
const Nx = { cullArea: null, cullable: !1, cullableChildren: !0 };
let pc = 0;
const gm = 500;
function vn(...r) {
  pc !== gm &&
    (pc++,
    pc === gm
      ? console.warn(
          "PixiJS Warning: too many warnings, no more warnings will be reported to the console by PixiJS."
        )
      : console.warn("PixiJS Warning: ", ...r));
}
class rf {
  constructor(e, i) {
    (this._pool = []),
      (this._count = 0),
      (this._index = 0),
      (this._classType = e),
      i && this.prepopulate(i);
  }
  prepopulate(e) {
    for (let i = 0; i < e; i++)
      this._pool[this._index++] = new this._classType();
    this._count += e;
  }
  get(e) {
    let i;
    return (
      this._index > 0
        ? (i = this._pool[--this._index])
        : (i = new this._classType()),
      i.init?.(e),
      i
    );
  }
  return(e) {
    e.reset?.(), (this._pool[this._index++] = e);
  }
  get totalSize() {
    return this._count;
  }
  get totalFree() {
    return this._index;
  }
  get totalUsed() {
    return this._count - this._index;
  }
  clear() {
    (this._pool.length = 0), (this._index = 0);
  }
}
class Dx {
  constructor() {
    this._poolsByClass = new Map();
  }
  prepopulate(e, i) {
    this.getPool(e).prepopulate(i);
  }
  get(e, i) {
    return this.getPool(e).get(i);
  }
  return(e) {
    this.getPool(e.constructor).return(e);
  }
  getPool(e) {
    return (
      this._poolsByClass.has(e) || this._poolsByClass.set(e, new rf(e)),
      this._poolsByClass.get(e)
    );
  }
  stats() {
    const e = {};
    return (
      this._poolsByClass.forEach((i) => {
        const o = e[i._classType.name]
          ? i._classType.name + i._classType.ID
          : i._classType.name;
        e[o] = { free: i.totalFree, used: i.totalUsed, size: i.totalSize };
      }),
      e
    );
  }
}
const pa = new Dx(),
  Bx = {
    get isCachedAsTexture() {
      return !!this.renderGroup?.isCachedAsTexture;
    },
    cacheAsTexture(r) {
      typeof r == "boolean" && r === !1
        ? this.disableRenderGroup()
        : (this.enableRenderGroup(),
          this.renderGroup.enableCacheAsTexture(r === !0 ? {} : r));
    },
    updateCacheTexture() {
      this.renderGroup?.updateCacheTexture();
    },
    get cacheAsBitmap() {
      return this.isCachedAsTexture;
    },
    set cacheAsBitmap(r) {
      zr("v8.6.0", "cacheAsBitmap is deprecated, use cacheAsTexture instead."),
        this.cacheAsTexture(r);
    },
  };
function Ux(r, e, i) {
  const o = r.length;
  let l;
  if (e >= o || i === 0) return;
  i = e + i > o ? o - e : i;
  const c = o - i;
  for (l = e; l < c; ++l) r[l] = r[l + i];
  r.length = c;
}
const jx = {
    allowChildren: !0,
    removeChildren(r = 0, e) {
      const i = e ?? this.children.length,
        o = i - r,
        l = [];
      if (o > 0 && o <= i) {
        for (let f = i - 1; f >= r; f--) {
          const d = this.children[f];
          d && (l.push(d), (d.parent = null));
        }
        Ux(this.children, r, i);
        const c = this.renderGroup || this.parentRenderGroup;
        c && c.removeChildren(l);
        for (let f = 0; f < l.length; ++f) {
          const d = l[f];
          d.parentRenderLayer?.detach(d),
            this.emit("childRemoved", d, this, f),
            l[f].emit("removed", this);
        }
        return l.length > 0 && this._didViewChangeTick++, l;
      } else if (o === 0 && this.children.length === 0) return l;
      throw new RangeError(
        "removeChildren: numeric values are outside the acceptable range."
      );
    },
    removeChildAt(r) {
      const e = this.getChildAt(r);
      return this.removeChild(e);
    },
    getChildAt(r) {
      if (r < 0 || r >= this.children.length)
        throw new Error(`getChildAt: Index (${r}) does not exist.`);
      return this.children[r];
    },
    setChildIndex(r, e) {
      if (e < 0 || e >= this.children.length)
        throw new Error(
          `The index ${e} supplied is out of bounds ${this.children.length}`
        );
      this.getChildIndex(r), this.addChildAt(r, e);
    },
    getChildIndex(r) {
      const e = this.children.indexOf(r);
      if (e === -1)
        throw new Error("The supplied Container must be a child of the caller");
      return e;
    },
    addChildAt(r, e) {
      this.allowChildren ||
        zr(
          Pi,
          "addChildAt: Only Containers will be allowed to add children in v8.0.0"
        );
      const { children: i } = this;
      if (e < 0 || e > i.length)
        throw new Error(
          `${r}addChildAt: The index ${e} supplied is out of bounds ${i.length}`
        );
      if (r.parent) {
        const l = r.parent.children.indexOf(r);
        if (r.parent === this && l === e) return r;
        l !== -1 && r.parent.children.splice(l, 1);
      }
      e === i.length ? i.push(r) : i.splice(e, 0, r),
        (r.parent = this),
        (r.didChange = !0),
        (r._updateFlags = 15);
      const o = this.renderGroup || this.parentRenderGroup;
      return (
        o && o.addChild(r),
        this.sortableChildren && (this.sortDirty = !0),
        this.emit("childAdded", r, this, e),
        r.emit("added", this),
        r
      );
    },
    swapChildren(r, e) {
      if (r === e) return;
      const i = this.getChildIndex(r),
        o = this.getChildIndex(e);
      (this.children[i] = e), (this.children[o] = r);
      const l = this.renderGroup || this.parentRenderGroup;
      l && (l.structureDidChange = !0), this._didContainerChangeTick++;
    },
    removeFromParent() {
      this.parent?.removeChild(this);
    },
    reparentChild(...r) {
      return r.length === 1
        ? this.reparentChildAt(r[0], this.children.length)
        : (r.forEach((e) => this.reparentChildAt(e, this.children.length)),
          r[0]);
    },
    reparentChildAt(r, e) {
      if (r.parent === this) return this.setChildIndex(r, e), r;
      const i = r.worldTransform.clone();
      r.removeFromParent(), this.addChildAt(r, e);
      const o = this.worldTransform.clone();
      return o.invert(), i.prepend(o), r.setFromMatrix(i), r;
    },
    replaceChild(r, e) {
      r.updateLocalTransform(),
        this.addChildAt(e, this.getChildIndex(r)),
        e.setFromMatrix(r.localTransform),
        e.updateLocalTransform(),
        this.removeChild(r);
    },
  },
  $x = {
    collectRenderables(r, e, i) {
      (this.parentRenderLayer && this.parentRenderLayer !== i) ||
        this.globalDisplayStatus < 7 ||
        !this.includeInBuild ||
        (this.sortableChildren && this.sortChildren(),
        this.isSimple
          ? this.collectRenderablesSimple(r, e, i)
          : this.renderGroup
          ? e.renderPipes.renderGroup.addRenderGroup(this.renderGroup, r)
          : this.collectRenderablesWithEffects(r, e, i));
    },
    collectRenderablesSimple(r, e, i) {
      const o = this.children,
        l = o.length;
      for (let c = 0; c < l; c++) o[c].collectRenderables(r, e, i);
    },
    collectRenderablesWithEffects(r, e, i) {
      const { renderPipes: o } = e;
      for (let l = 0; l < this.effects.length; l++) {
        const c = this.effects[l];
        o[c.pipe].push(c, this, r);
      }
      this.collectRenderablesSimple(r, e, i);
      for (let l = this.effects.length - 1; l >= 0; l--) {
        const c = this.effects[l];
        o[c.pipe].pop(c, this, r);
      }
    },
  };
class vm {
  constructor() {
    (this.pipe = "filter"), (this.priority = 1);
  }
  destroy() {
    for (let e = 0; e < this.filters.length; e++) this.filters[e].destroy();
    (this.filters = null), (this.filterArea = null);
  }
}
class zx {
  constructor() {
    (this._effectClasses = []), (this._tests = []), (this._initialized = !1);
  }
  init() {
    this._initialized ||
      ((this._initialized = !0),
      this._effectClasses.forEach((e) => {
        this.add({ test: e.test, maskClass: e });
      }));
  }
  add(e) {
    this._tests.push(e);
  }
  getMaskEffect(e) {
    this._initialized || this.init();
    for (let i = 0; i < this._tests.length; i++) {
      const o = this._tests[i];
      if (o.test(e)) return pa.get(o.maskClass, e);
    }
    return e;
  }
  returnMaskEffect(e) {
    pa.return(e);
  }
}
const zc = new zx();
xn.handleByList(ft.MaskEffect, zc._effectClasses);
const Hx = {
    _maskEffect: null,
    _maskOptions: { inverse: !1 },
    _filterEffect: null,
    effects: [],
    _markStructureAsChanged() {
      const r = this.renderGroup || this.parentRenderGroup;
      r && (r.structureDidChange = !0);
    },
    addEffect(r) {
      this.effects.indexOf(r) === -1 &&
        (this.effects.push(r),
        this.effects.sort((i, o) => i.priority - o.priority),
        this._markStructureAsChanged(),
        this._updateIsSimple());
    },
    removeEffect(r) {
      const e = this.effects.indexOf(r);
      e !== -1 &&
        (this.effects.splice(e, 1),
        this._markStructureAsChanged(),
        this._updateIsSimple());
    },
    set mask(r) {
      const e = this._maskEffect;
      e?.mask !== r &&
        (e &&
          (this.removeEffect(e),
          zc.returnMaskEffect(e),
          (this._maskEffect = null)),
        r != null &&
          ((this._maskEffect = zc.getMaskEffect(r)),
          this.addEffect(this._maskEffect)));
    },
    get mask() {
      return this._maskEffect?.mask;
    },
    setMask(r) {
      (this._maskOptions = { ...this._maskOptions, ...r }),
        r.mask && (this.mask = r.mask),
        this._markStructureAsChanged();
    },
    set filters(r) {
      !Array.isArray(r) && r && (r = [r]);
      const e = this._filterEffect || (this._filterEffect = new vm());
      r = r;
      const i = r?.length > 0,
        o = e.filters?.length > 0,
        l = i !== o;
      (r = Array.isArray(r) ? r.slice(0) : r),
        (e.filters = Object.freeze(r)),
        l &&
          (i
            ? this.addEffect(e)
            : (this.removeEffect(e), (e.filters = r ?? null)));
    },
    get filters() {
      return this._filterEffect?.filters;
    },
    set filterArea(r) {
      this._filterEffect || (this._filterEffect = new vm()),
        (this._filterEffect.filterArea = r);
    },
    get filterArea() {
      return this._filterEffect?.filterArea;
    },
  },
  qx = {
    label: null,
    get name() {
      return (
        zr(
          Pi,
          "Container.name property has been removed, use Container.label instead"
        ),
        this.label
      );
    },
    set name(r) {
      zr(
        Pi,
        "Container.name property has been removed, use Container.label instead"
      ),
        (this.label = r);
    },
    getChildByName(r, e = !1) {
      return this.getChildByLabel(r, e);
    },
    getChildByLabel(r, e = !1) {
      const i = this.children;
      for (let o = 0; o < i.length; o++) {
        const l = i[o];
        if (l.label === r || (r instanceof RegExp && r.test(l.label))) return l;
      }
      if (e)
        for (let o = 0; o < i.length; o++) {
          const c = i[o].getChildByLabel(r, !0);
          if (c) return c;
        }
      return null;
    },
    getChildrenByLabel(r, e = !1, i = []) {
      const o = this.children;
      for (let l = 0; l < o.length; l++) {
        const c = o[l];
        (c.label === r || (r instanceof RegExp && r.test(c.label))) &&
          i.push(c);
      }
      if (e)
        for (let l = 0; l < o.length; l++) o[l].getChildrenByLabel(r, !0, i);
      return i;
    },
  },
  Ct = new rf(Ve),
  $r = new rf(wn),
  Vx = new Ve(),
  Gx = {
    getFastGlobalBounds(r, e) {
      e || (e = new wn()),
        e.clear(),
        this._getGlobalBoundsRecursive(!!r, e, this.parentRenderLayer),
        e.isValid || e.set(0, 0, 0, 0);
      const i = this.renderGroup || this.parentRenderGroup;
      return e.applyMatrix(i.worldTransform), e;
    },
    _getGlobalBoundsRecursive(r, e, i) {
      let o = e;
      if (
        (r && this.parentRenderLayer && this.parentRenderLayer !== i) ||
        this.localDisplayStatus !== 7 ||
        !this.measurable
      )
        return;
      const l = !!this.effects.length;
      if (((this.renderGroup || l) && (o = $r.get().clear()), this.boundsArea))
        e.addRect(this.boundsArea, this.worldTransform);
      else {
        if (this.renderPipeId) {
          const f = this.bounds;
          o.addFrame(f.minX, f.minY, f.maxX, f.maxY, this.groupTransform);
        }
        const c = this.children;
        for (let f = 0; f < c.length; f++)
          c[f]._getGlobalBoundsRecursive(r, o, i);
      }
      if (l) {
        let c = !1;
        const f = this.renderGroup || this.parentRenderGroup;
        for (let d = 0; d < this.effects.length; d++)
          this.effects[d].addBounds &&
            (c || ((c = !0), o.applyMatrix(f.worldTransform)),
            this.effects[d].addBounds(o, !0));
        c &&
          (o.applyMatrix(f.worldTransform.copyTo(Vx).invert()),
          e.addBounds(o, this.relativeGroupTransform)),
          e.addBounds(o),
          $r.return(o);
      } else
        this.renderGroup &&
          (e.addBounds(o, this.relativeGroupTransform), $r.return(o));
    },
  };
function yg(r, e, i) {
  i.clear();
  let o, l;
  return (
    r.parent
      ? e
        ? (o = r.parent.worldTransform)
        : ((l = Ct.get().identity()), (o = nf(r, l)))
      : (o = Ve.IDENTITY),
    gg(r, i, o, e),
    l && Ct.return(l),
    i.isValid || i.set(0, 0, 0, 0),
    i
  );
}
function gg(r, e, i, o) {
  if (!r.visible || !r.measurable) return;
  let l;
  o
    ? (l = r.worldTransform)
    : (r.updateLocalTransform(),
      (l = Ct.get()),
      l.appendFrom(r.localTransform, i));
  const c = e,
    f = !!r.effects.length;
  if ((f && (e = $r.get().clear()), r.boundsArea)) e.addRect(r.boundsArea, l);
  else {
    r.bounds && ((e.matrix = l), e.addBounds(r.bounds));
    for (let d = 0; d < r.children.length; d++) gg(r.children[d], e, l, o);
  }
  if (f) {
    for (let d = 0; d < r.effects.length; d++) r.effects[d].addBounds?.(e);
    c.addBounds(e, Ve.IDENTITY), $r.return(e);
  }
  o || Ct.return(l);
}
function nf(r, e) {
  const i = r.parent;
  return (
    i && (nf(i, e), i.updateLocalTransform(), e.append(i.localTransform)), e
  );
}
function Wx(r, e) {
  if (r === 16777215 || !e) return e;
  if (e === 16777215 || !r) return r;
  const i = (r >> 16) & 255,
    o = (r >> 8) & 255,
    l = r & 255,
    c = (e >> 16) & 255,
    f = (e >> 8) & 255,
    d = e & 255,
    m = ((i * c) / 255) | 0,
    p = ((o * f) / 255) | 0,
    g = ((l * d) / 255) | 0;
  return (m << 16) + (p << 8) + g;
}
const _m = 16777215;
function wm(r, e) {
  return r === _m ? e : e === _m ? r : Wx(r, e);
}
function la(r) {
  return ((r & 255) << 16) + (r & 65280) + ((r >> 16) & 255);
}
const Xx = {
  getGlobalAlpha(r) {
    if (r)
      return this.renderGroup
        ? this.renderGroup.worldAlpha
        : this.parentRenderGroup
        ? this.parentRenderGroup.worldAlpha * this.alpha
        : this.alpha;
    let e = this.alpha,
      i = this.parent;
    for (; i; ) (e *= i.alpha), (i = i.parent);
    return e;
  },
  getGlobalTransform(r, e) {
    if (e) return r.copyFrom(this.worldTransform);
    this.updateLocalTransform();
    const i = nf(this, Ct.get().identity());
    return r.appendFrom(this.localTransform, i), Ct.return(i), r;
  },
  getGlobalTint(r) {
    if (r)
      return this.renderGroup
        ? la(this.renderGroup.worldColor)
        : this.parentRenderGroup
        ? la(wm(this.localColor, this.parentRenderGroup.worldColor))
        : this.tint;
    let e = this.localColor,
      i = this.parent;
    for (; i; ) (e = wm(e, i.localColor)), (i = i.parent);
    return la(e);
  },
};
function vg(r, e, i) {
  return (
    e.clear(),
    i || (i = Ve.IDENTITY),
    _g(r, e, i, r, !0),
    e.isValid || e.set(0, 0, 0, 0),
    e
  );
}
function _g(r, e, i, o, l) {
  let c;
  if (l) (c = Ct.get()), (c = i.copyTo(c));
  else {
    if (!r.visible || !r.measurable) return;
    r.updateLocalTransform();
    const m = r.localTransform;
    (c = Ct.get()), c.appendFrom(m, i);
  }
  const f = e,
    d = !!r.effects.length;
  if ((d && (e = $r.get().clear()), r.boundsArea)) e.addRect(r.boundsArea, c);
  else {
    r.renderPipeId && ((e.matrix = c), e.addBounds(r.bounds));
    const m = r.children;
    for (let p = 0; p < m.length; p++) _g(m[p], e, c, o, !1);
  }
  if (d) {
    for (let m = 0; m < r.effects.length; m++)
      r.effects[m].addLocalBounds?.(e, o);
    f.addBounds(e, Ve.IDENTITY), $r.return(e);
  }
  Ct.return(c);
}
function wg(r, e) {
  const i = r.children;
  for (let o = 0; o < i.length; o++) {
    const l = i[o],
      c = l.uid,
      f =
        ((l._didViewChangeTick & 65535) << 16) |
        (l._didContainerChangeTick & 65535),
      d = e.index;
    (e.data[d] !== c || e.data[d + 1] !== f) &&
      ((e.data[e.index] = c), (e.data[e.index + 1] = f), (e.didChange = !0)),
      (e.index = d + 2),
      l.children.length && wg(l, e);
  }
  return e.didChange;
}
const Yx = new Ve(),
  Qx = {
    _localBoundsCacheId: -1,
    _localBoundsCacheData: null,
    _setWidth(r, e) {
      const i = Math.sign(this.scale.x) || 1;
      e !== 0 ? (this.scale.x = (r / e) * i) : (this.scale.x = i);
    },
    _setHeight(r, e) {
      const i = Math.sign(this.scale.y) || 1;
      e !== 0 ? (this.scale.y = (r / e) * i) : (this.scale.y = i);
    },
    getLocalBounds() {
      this._localBoundsCacheData ||
        (this._localBoundsCacheData = {
          data: [],
          index: 1,
          didChange: !1,
          localBounds: new wn(),
        });
      const r = this._localBoundsCacheData;
      return (
        (r.index = 1),
        (r.didChange = !1),
        r.data[0] !== this._didViewChangeTick &&
          ((r.didChange = !0), (r.data[0] = this._didViewChangeTick)),
        wg(this, r),
        r.didChange && vg(this, r.localBounds, Yx),
        r.localBounds
      );
    },
    getBounds(r, e) {
      return yg(this, r, e || new wn());
    },
  },
  Kx = {
    _onRender: null,
    set onRender(r) {
      const e = this.renderGroup || this.parentRenderGroup;
      if (!r) {
        this._onRender && e?.removeOnRender(this), (this._onRender = null);
        return;
      }
      this._onRender || e?.addOnRender(this), (this._onRender = r);
    },
    get onRender() {
      return this._onRender;
    },
  },
  Jx = {
    _zIndex: 0,
    sortDirty: !1,
    sortableChildren: !1,
    get zIndex() {
      return this._zIndex;
    },
    set zIndex(r) {
      this._zIndex !== r && ((this._zIndex = r), this.depthOfChildModified());
    },
    depthOfChildModified() {
      this.parent &&
        ((this.parent.sortableChildren = !0), (this.parent.sortDirty = !0)),
        this.parentRenderGroup &&
          (this.parentRenderGroup.structureDidChange = !0);
    },
    sortChildren() {
      this.sortDirty && ((this.sortDirty = !1), this.children.sort(Zx));
    },
  };
function Zx(r, e) {
  return r._zIndex - e._zIndex;
}
const eS = {
  getGlobalPosition(r = new Er(), e = !1) {
    return (
      this.parent
        ? this.parent.toGlobal(this._position, r, e)
        : ((r.x = this._position.x), (r.y = this._position.y)),
      r
    );
  },
  toGlobal(r, e, i = !1) {
    const o = this.getGlobalTransform(Ct.get(), i);
    return (e = o.apply(r, e)), Ct.return(o), e;
  },
  toLocal(r, e, i, o) {
    e && (r = e.toGlobal(r, i, o));
    const l = this.getGlobalTransform(Ct.get(), o);
    return (i = l.applyInverse(r, i)), Ct.return(l), i;
  },
};
class tS {
  constructor() {
    (this.uid = gn("instructionSet")),
      (this.instructions = []),
      (this.instructionSize = 0),
      (this.renderables = []),
      (this.gcTick = 0);
  }
  reset() {
    this.instructionSize = 0;
  }
  add(e) {
    this.instructions[this.instructionSize++] = e;
  }
  log() {
    (this.instructions.length = this.instructionSize),
      console.table(this.instructions, ["type", "action"]);
  }
}
let rS = 0;
class nS {
  constructor(e) {
    (this._poolKeyHash = Object.create(null)),
      (this._texturePool = {}),
      (this.textureOptions = e || {}),
      (this.enableFullScreen = !1),
      (this.textureStyle = new cg(this.textureOptions));
  }
  createTexture(e, i, o) {
    const l = new fr({
      ...this.textureOptions,
      width: e,
      height: i,
      resolution: 1,
      antialias: o,
      autoGarbageCollect: !1,
    });
    return new tt({ source: l, label: `texturePool_${rS++}` });
  }
  getOptimalTexture(e, i, o = 1, l) {
    let c = Math.ceil(e * o - 1e-6),
      f = Math.ceil(i * o - 1e-6);
    (c = sm(c)), (f = sm(f));
    const d = (c << 17) + (f << 1) + (l ? 1 : 0);
    this._texturePool[d] || (this._texturePool[d] = []);
    let m = this._texturePool[d].pop();
    return (
      m || (m = this.createTexture(c, f, l)),
      (m.source._resolution = o),
      (m.source.width = c / o),
      (m.source.height = f / o),
      (m.source.pixelWidth = c),
      (m.source.pixelHeight = f),
      (m.frame.x = 0),
      (m.frame.y = 0),
      (m.frame.width = e),
      (m.frame.height = i),
      m.updateUvs(),
      (this._poolKeyHash[m.uid] = d),
      m
    );
  }
  getSameSizeTexture(e, i = !1) {
    const o = e.source;
    return this.getOptimalTexture(e.width, e.height, o._resolution, i);
  }
  returnTexture(e, i = !1) {
    const o = this._poolKeyHash[e.uid];
    i && (e.source.style = this.textureStyle), this._texturePool[o].push(e);
  }
  clear(e) {
    if (((e = e !== !1), e))
      for (const i in this._texturePool) {
        const o = this._texturePool[i];
        if (o) for (let l = 0; l < o.length; l++) o[l].destroy(!0);
      }
    this._texturePool = {};
  }
}
const iS = new nS();
class sS {
  constructor() {
    (this.renderPipeId = "renderGroup"),
      (this.root = null),
      (this.canBundle = !1),
      (this.renderGroupParent = null),
      (this.renderGroupChildren = []),
      (this.worldTransform = new Ve()),
      (this.worldColorAlpha = 4294967295),
      (this.worldColor = 16777215),
      (this.worldAlpha = 1),
      (this.childrenToUpdate = Object.create(null)),
      (this.updateTick = 0),
      (this.gcTick = 0),
      (this.childrenRenderablesToUpdate = { list: [], index: 0 }),
      (this.structureDidChange = !0),
      (this.instructionSet = new tS()),
      (this._onRenderContainers = []),
      (this.textureNeedsUpdate = !0),
      (this.isCachedAsTexture = !1),
      (this._matrixDirty = 7);
  }
  init(e) {
    (this.root = e), e._onRender && this.addOnRender(e), (e.didChange = !0);
    const i = e.children;
    for (let o = 0; o < i.length; o++) {
      const l = i[o];
      (l._updateFlags = 15), this.addChild(l);
    }
  }
  enableCacheAsTexture(e = {}) {
    (this.textureOptions = e),
      (this.isCachedAsTexture = !0),
      (this.textureNeedsUpdate = !0);
  }
  disableCacheAsTexture() {
    (this.isCachedAsTexture = !1),
      this.texture && (iS.returnTexture(this.texture), (this.texture = null));
  }
  updateCacheTexture() {
    this.textureNeedsUpdate = !0;
  }
  reset() {
    this.renderGroupChildren.length = 0;
    for (const e in this.childrenToUpdate) {
      const i = this.childrenToUpdate[e];
      i.list.fill(null), (i.index = 0);
    }
    (this.childrenRenderablesToUpdate.index = 0),
      this.childrenRenderablesToUpdate.list.fill(null),
      (this.root = null),
      (this.updateTick = 0),
      (this.structureDidChange = !0),
      (this._onRenderContainers.length = 0),
      (this.renderGroupParent = null),
      this.disableCacheAsTexture();
  }
  get localTransform() {
    return this.root.localTransform;
  }
  addRenderGroupChild(e) {
    e.renderGroupParent && e.renderGroupParent._removeRenderGroupChild(e),
      (e.renderGroupParent = this),
      this.renderGroupChildren.push(e);
  }
  _removeRenderGroupChild(e) {
    const i = this.renderGroupChildren.indexOf(e);
    i > -1 && this.renderGroupChildren.splice(i, 1),
      (e.renderGroupParent = null);
  }
  addChild(e) {
    if (
      ((this.structureDidChange = !0),
      (e.parentRenderGroup = this),
      (e.updateTick = -1),
      e.parent === this.root
        ? (e.relativeRenderGroupDepth = 1)
        : (e.relativeRenderGroupDepth = e.parent.relativeRenderGroupDepth + 1),
      (e.didChange = !0),
      this.onChildUpdate(e),
      e.renderGroup)
    ) {
      this.addRenderGroupChild(e.renderGroup);
      return;
    }
    e._onRender && this.addOnRender(e);
    const i = e.children;
    for (let o = 0; o < i.length; o++) this.addChild(i[o]);
  }
  removeChild(e) {
    if (
      ((this.structureDidChange = !0),
      e._onRender && (e.renderGroup || this.removeOnRender(e)),
      (e.parentRenderGroup = null),
      e.renderGroup)
    ) {
      this._removeRenderGroupChild(e.renderGroup);
      return;
    }
    const i = e.children;
    for (let o = 0; o < i.length; o++) this.removeChild(i[o]);
  }
  removeChildren(e) {
    for (let i = 0; i < e.length; i++) this.removeChild(e[i]);
  }
  onChildUpdate(e) {
    let i = this.childrenToUpdate[e.relativeRenderGroupDepth];
    i ||
      (i = this.childrenToUpdate[e.relativeRenderGroupDepth] =
        { index: 0, list: [] }),
      (i.list[i.index++] = e);
  }
  updateRenderable(e) {
    e.globalDisplayStatus < 7 ||
      (this.instructionSet.renderPipes[e.renderPipeId].updateRenderable(e),
      (e.didViewUpdate = !1));
  }
  onChildViewUpdate(e) {
    this.childrenRenderablesToUpdate.list[
      this.childrenRenderablesToUpdate.index++
    ] = e;
  }
  get isRenderable() {
    return this.root.localDisplayStatus === 7 && this.worldAlpha > 0;
  }
  addOnRender(e) {
    this._onRenderContainers.push(e);
  }
  removeOnRender(e) {
    this._onRenderContainers.splice(this._onRenderContainers.indexOf(e), 1);
  }
  runOnRender(e) {
    for (let i = 0; i < this._onRenderContainers.length; i++)
      this._onRenderContainers[i]._onRender(e);
  }
  destroy() {
    this.disableCacheAsTexture(),
      (this.renderGroupParent = null),
      (this.root = null),
      (this.childrenRenderablesToUpdate = null),
      (this.childrenToUpdate = null),
      (this.renderGroupChildren = null),
      (this._onRenderContainers = null),
      (this.instructionSet = null);
  }
  getChildren(e = []) {
    const i = this.root.children;
    for (let o = 0; o < i.length; o++) this._getChildren(i[o], e);
    return e;
  }
  _getChildren(e, i = []) {
    if ((i.push(e), e.renderGroup)) return i;
    const o = e.children;
    for (let l = 0; l < o.length; l++) this._getChildren(o[l], i);
    return i;
  }
  invalidateMatrices() {
    this._matrixDirty = 7;
  }
  get inverseWorldTransform() {
    return (this._matrixDirty & 1) === 0
      ? this._inverseWorldTransform
      : ((this._matrixDirty &= -2),
        this._inverseWorldTransform || (this._inverseWorldTransform = new Ve()),
        this._inverseWorldTransform.copyFrom(this.worldTransform).invert());
  }
  get textureOffsetInverseTransform() {
    return (this._matrixDirty & 2) === 0
      ? this._textureOffsetInverseTransform
      : ((this._matrixDirty &= -3),
        this._textureOffsetInverseTransform ||
          (this._textureOffsetInverseTransform = new Ve()),
        this._textureOffsetInverseTransform
          .copyFrom(this.inverseWorldTransform)
          .translate(-this._textureBounds.x, -this._textureBounds.y));
  }
  get inverseParentTextureTransform() {
    if ((this._matrixDirty & 4) === 0)
      return this._inverseParentTextureTransform;
    this._matrixDirty &= -5;
    const e = this._parentCacheAsTextureRenderGroup;
    return e
      ? (this._inverseParentTextureTransform ||
          (this._inverseParentTextureTransform = new Ve()),
        this._inverseParentTextureTransform
          .copyFrom(this.worldTransform)
          .prepend(e.inverseWorldTransform)
          .translate(-e._textureBounds.x, -e._textureBounds.y))
      : this.worldTransform;
  }
  get cacheToLocalTransform() {
    return this._parentCacheAsTextureRenderGroup
      ? this._parentCacheAsTextureRenderGroup.textureOffsetInverseTransform
      : null;
  }
}
function oS(r, e, i = {}) {
  for (const o in e) !i[o] && e[o] !== void 0 && (r[o] = e[o]);
}
const mc = new gt(null),
  Zo = new gt(null),
  yc = new gt(null, 1, 1),
  ea = new gt(null),
  xm = 1,
  aS = 2,
  gc = 4;
class Fs extends qr {
  constructor(e = {}) {
    super(),
      (this.uid = gn("renderable")),
      (this._updateFlags = 15),
      (this.renderGroup = null),
      (this.parentRenderGroup = null),
      (this.parentRenderGroupIndex = 0),
      (this.didChange = !1),
      (this.didViewUpdate = !1),
      (this.relativeRenderGroupDepth = 0),
      (this.children = []),
      (this.parent = null),
      (this.includeInBuild = !0),
      (this.measurable = !0),
      (this.isSimple = !0),
      (this.updateTick = -1),
      (this.localTransform = new Ve()),
      (this.relativeGroupTransform = new Ve()),
      (this.groupTransform = this.relativeGroupTransform),
      (this.destroyed = !1),
      (this._position = new gt(this, 0, 0)),
      (this._scale = yc),
      (this._pivot = Zo),
      (this._origin = ea),
      (this._skew = mc),
      (this._cx = 1),
      (this._sx = 0),
      (this._cy = 0),
      (this._sy = 1),
      (this._rotation = 0),
      (this.localColor = 16777215),
      (this.localAlpha = 1),
      (this.groupAlpha = 1),
      (this.groupColor = 16777215),
      (this.groupColorAlpha = 4294967295),
      (this.localBlendMode = "inherit"),
      (this.groupBlendMode = "normal"),
      (this.localDisplayStatus = 7),
      (this.globalDisplayStatus = 7),
      (this._didContainerChangeTick = 0),
      (this._didViewChangeTick = 0),
      (this._didLocalTransformChangeId = -1),
      (this.effects = []),
      oS(this, e, { children: !0, parent: !0, effects: !0 }),
      e.children?.forEach((i) => this.addChild(i)),
      e.parent?.addChild(this);
  }
  static mixin(e) {
    zr(
      "8.8.0",
      "Container.mixin is deprecated, please use extensions.mixin instead."
    ),
      xn.mixin(Fs, e);
  }
  set _didChangeId(e) {
    (this._didViewChangeTick = (e >> 12) & 4095),
      (this._didContainerChangeTick = e & 4095);
  }
  get _didChangeId() {
    return (
      (this._didContainerChangeTick & 4095) |
      ((this._didViewChangeTick & 4095) << 12)
    );
  }
  addChild(...e) {
    if (
      (this.allowChildren ||
        zr(
          Pi,
          "addChild: Only Containers will be allowed to add children in v8.0.0"
        ),
      e.length > 1)
    ) {
      for (let l = 0; l < e.length; l++) this.addChild(e[l]);
      return e[0];
    }
    const i = e[0],
      o = this.renderGroup || this.parentRenderGroup;
    return i.parent === this
      ? (this.children.splice(this.children.indexOf(i), 1),
        this.children.push(i),
        o && (o.structureDidChange = !0),
        i)
      : (i.parent && i.parent.removeChild(i),
        this.children.push(i),
        this.sortableChildren && (this.sortDirty = !0),
        (i.parent = this),
        (i.didChange = !0),
        (i._updateFlags = 15),
        o && o.addChild(i),
        this.emit("childAdded", i, this, this.children.length - 1),
        i.emit("added", this),
        this._didViewChangeTick++,
        i._zIndex !== 0 && i.depthOfChildModified(),
        i);
  }
  removeChild(...e) {
    if (e.length > 1) {
      for (let l = 0; l < e.length; l++) this.removeChild(e[l]);
      return e[0];
    }
    const i = e[0],
      o = this.children.indexOf(i);
    return (
      o > -1 &&
        (this._didViewChangeTick++,
        this.children.splice(o, 1),
        this.renderGroup
          ? this.renderGroup.removeChild(i)
          : this.parentRenderGroup && this.parentRenderGroup.removeChild(i),
        i.parentRenderLayer && i.parentRenderLayer.detach(i),
        (i.parent = null),
        this.emit("childRemoved", i, this, o),
        i.emit("removed", this)),
      i
    );
  }
  _onUpdate(e) {
    e && e === this._skew && this._updateSkew(),
      this._didContainerChangeTick++,
      !this.didChange &&
        ((this.didChange = !0),
        this.parentRenderGroup && this.parentRenderGroup.onChildUpdate(this));
  }
  set isRenderGroup(e) {
    !!this.renderGroup !== e &&
      (e ? this.enableRenderGroup() : this.disableRenderGroup());
  }
  get isRenderGroup() {
    return !!this.renderGroup;
  }
  enableRenderGroup() {
    if (this.renderGroup) return;
    const e = this.parentRenderGroup;
    e?.removeChild(this),
      (this.renderGroup = pa.get(sS, this)),
      (this.groupTransform = Ve.IDENTITY),
      e?.addChild(this),
      this._updateIsSimple();
  }
  disableRenderGroup() {
    if (!this.renderGroup) return;
    const e = this.parentRenderGroup;
    e?.removeChild(this),
      pa.return(this.renderGroup),
      (this.renderGroup = null),
      (this.groupTransform = this.relativeGroupTransform),
      e?.addChild(this),
      this._updateIsSimple();
  }
  _updateIsSimple() {
    this.isSimple = !this.renderGroup && this.effects.length === 0;
  }
  get worldTransform() {
    return (
      this._worldTransform || (this._worldTransform = new Ve()),
      this.renderGroup
        ? this._worldTransform.copyFrom(this.renderGroup.worldTransform)
        : this.parentRenderGroup &&
          this._worldTransform.appendFrom(
            this.relativeGroupTransform,
            this.parentRenderGroup.worldTransform
          ),
      this._worldTransform
    );
  }
  get x() {
    return this._position.x;
  }
  set x(e) {
    this._position.x = e;
  }
  get y() {
    return this._position.y;
  }
  set y(e) {
    this._position.y = e;
  }
  get position() {
    return this._position;
  }
  set position(e) {
    this._position.copyFrom(e);
  }
  get rotation() {
    return this._rotation;
  }
  set rotation(e) {
    this._rotation !== e && ((this._rotation = e), this._onUpdate(this._skew));
  }
  get angle() {
    return this.rotation * gx;
  }
  set angle(e) {
    this.rotation = e * vx;
  }
  get pivot() {
    return (
      this._pivot === Zo && (this._pivot = new gt(this, 0, 0)), this._pivot
    );
  }
  set pivot(e) {
    this._pivot === Zo &&
      ((this._pivot = new gt(this, 0, 0)),
      this._origin !== ea &&
        vn(
          "Setting both a pivot and origin on a Container is not recommended. This can lead to unexpected behavior if not handled carefully."
        )),
      typeof e == "number" ? this._pivot.set(e) : this._pivot.copyFrom(e);
  }
  get skew() {
    return this._skew === mc && (this._skew = new gt(this, 0, 0)), this._skew;
  }
  set skew(e) {
    this._skew === mc && (this._skew = new gt(this, 0, 0)),
      this._skew.copyFrom(e);
  }
  get scale() {
    return (
      this._scale === yc && (this._scale = new gt(this, 1, 1)), this._scale
    );
  }
  set scale(e) {
    this._scale === yc && (this._scale = new gt(this, 0, 0)),
      typeof e == "string" && (e = parseFloat(e)),
      typeof e == "number" ? this._scale.set(e) : this._scale.copyFrom(e);
  }
  get origin() {
    return (
      this._origin === ea && (this._origin = new gt(this, 0, 0)), this._origin
    );
  }
  set origin(e) {
    this._origin === ea &&
      ((this._origin = new gt(this, 0, 0)),
      this._pivot !== Zo &&
        vn(
          "Setting both a pivot and origin on a Container is not recommended. This can lead to unexpected behavior if not handled carefully."
        )),
      typeof e == "number" ? this._origin.set(e) : this._origin.copyFrom(e);
  }
  get width() {
    return Math.abs(this.scale.x * this.getLocalBounds().width);
  }
  set width(e) {
    const i = this.getLocalBounds().width;
    this._setWidth(e, i);
  }
  get height() {
    return Math.abs(this.scale.y * this.getLocalBounds().height);
  }
  set height(e) {
    const i = this.getLocalBounds().height;
    this._setHeight(e, i);
  }
  getSize(e) {
    e || (e = {});
    const i = this.getLocalBounds();
    return (
      (e.width = Math.abs(this.scale.x * i.width)),
      (e.height = Math.abs(this.scale.y * i.height)),
      e
    );
  }
  setSize(e, i) {
    const o = this.getLocalBounds();
    typeof e == "object"
      ? ((i = e.height ?? e.width), (e = e.width))
      : i ?? (i = e),
      e !== void 0 && this._setWidth(e, o.width),
      i !== void 0 && this._setHeight(i, o.height);
  }
  _updateSkew() {
    const e = this._rotation,
      i = this._skew;
    (this._cx = Math.cos(e + i._y)),
      (this._sx = Math.sin(e + i._y)),
      (this._cy = -Math.sin(e - i._x)),
      (this._sy = Math.cos(e - i._x));
  }
  updateTransform(e) {
    return (
      this.position.set(
        typeof e.x == "number" ? e.x : this.position.x,
        typeof e.y == "number" ? e.y : this.position.y
      ),
      this.scale.set(
        typeof e.scaleX == "number" ? e.scaleX || 1 : this.scale.x,
        typeof e.scaleY == "number" ? e.scaleY || 1 : this.scale.y
      ),
      (this.rotation =
        typeof e.rotation == "number" ? e.rotation : this.rotation),
      this.skew.set(
        typeof e.skewX == "number" ? e.skewX : this.skew.x,
        typeof e.skewY == "number" ? e.skewY : this.skew.y
      ),
      this.pivot.set(
        typeof e.pivotX == "number" ? e.pivotX : this.pivot.x,
        typeof e.pivotY == "number" ? e.pivotY : this.pivot.y
      ),
      this.origin.set(
        typeof e.originX == "number" ? e.originX : this.origin.x,
        typeof e.originY == "number" ? e.originY : this.origin.y
      ),
      this
    );
  }
  setFromMatrix(e) {
    e.decompose(this);
  }
  updateLocalTransform() {
    const e = this._didContainerChangeTick;
    if (this._didLocalTransformChangeId === e) return;
    this._didLocalTransformChangeId = e;
    const i = this.localTransform,
      o = this._scale,
      l = this._pivot,
      c = this._origin,
      f = this._position,
      d = o._x,
      m = o._y,
      p = l._x,
      g = l._y,
      v = -c._x,
      x = -c._y;
    (i.a = this._cx * d),
      (i.b = this._sx * d),
      (i.c = this._cy * m),
      (i.d = this._sy * m),
      (i.tx = f._x - (p * i.a + g * i.c) + (v * i.a + x * i.c) - v * d),
      (i.ty = f._y - (p * i.b + g * i.d) + (v * i.b + x * i.d) - x * m);
  }
  set alpha(e) {
    e !== this.localAlpha &&
      ((this.localAlpha = e), (this._updateFlags |= xm), this._onUpdate());
  }
  get alpha() {
    return this.localAlpha;
  }
  set tint(e) {
    const o = Fx.shared.setValue(e ?? 16777215).toBgrNumber();
    o !== this.localColor &&
      ((this.localColor = o), (this._updateFlags |= xm), this._onUpdate());
  }
  get tint() {
    return la(this.localColor);
  }
  set blendMode(e) {
    this.localBlendMode !== e &&
      (this.parentRenderGroup &&
        (this.parentRenderGroup.structureDidChange = !0),
      (this._updateFlags |= aS),
      (this.localBlendMode = e),
      this._onUpdate());
  }
  get blendMode() {
    return this.localBlendMode;
  }
  get visible() {
    return !!(this.localDisplayStatus & 2);
  }
  set visible(e) {
    const i = e ? 2 : 0;
    (this.localDisplayStatus & 2) !== i &&
      (this.parentRenderGroup &&
        (this.parentRenderGroup.structureDidChange = !0),
      (this._updateFlags |= gc),
      (this.localDisplayStatus ^= 2),
      this._onUpdate());
  }
  get culled() {
    return !(this.localDisplayStatus & 4);
  }
  set culled(e) {
    const i = e ? 0 : 4;
    (this.localDisplayStatus & 4) !== i &&
      (this.parentRenderGroup &&
        (this.parentRenderGroup.structureDidChange = !0),
      (this._updateFlags |= gc),
      (this.localDisplayStatus ^= 4),
      this._onUpdate());
  }
  get renderable() {
    return !!(this.localDisplayStatus & 1);
  }
  set renderable(e) {
    const i = e ? 1 : 0;
    (this.localDisplayStatus & 1) !== i &&
      ((this._updateFlags |= gc),
      (this.localDisplayStatus ^= 1),
      this.parentRenderGroup &&
        (this.parentRenderGroup.structureDidChange = !0),
      this._onUpdate());
  }
  get isRenderable() {
    return this.localDisplayStatus === 7 && this.groupAlpha > 0;
  }
  destroy(e = !1) {
    if (this.destroyed) return;
    this.destroyed = !0;
    let i;
    if (
      (this.children.length &&
        (i = this.removeChildren(0, this.children.length)),
      this.removeFromParent(),
      (this.parent = null),
      (this._maskEffect = null),
      (this._filterEffect = null),
      (this.effects = null),
      (this._position = null),
      (this._scale = null),
      (this._pivot = null),
      (this._origin = null),
      (this._skew = null),
      this.emit("destroyed", this),
      this.removeAllListeners(),
      (typeof e == "boolean" ? e : e?.children) && i)
    )
      for (let l = 0; l < i.length; ++l) i[l].destroy(e);
    this.renderGroup?.destroy(), (this.renderGroup = null);
  }
}
xn.mixin(Fs, jx, Gx, eS, Kx, Qx, Hx, qx, Jx, Nx, Bx, Xx, $x);
class lS extends Fs {
  constructor(e) {
    super(e),
      (this.canBundle = !0),
      (this.allowChildren = !1),
      (this._roundPixels = 0),
      (this._lastUsed = -1),
      (this._gpuData = Object.create(null)),
      (this._bounds = new wn(0, 1, 0, 0)),
      (this._boundsDirty = !0);
  }
  get bounds() {
    return this._boundsDirty
      ? (this.updateBounds(), (this._boundsDirty = !1), this._bounds)
      : this._bounds;
  }
  get roundPixels() {
    return !!this._roundPixels;
  }
  set roundPixels(e) {
    this._roundPixels = e ? 1 : 0;
  }
  containsPoint(e) {
    const i = this.bounds,
      { x: o, y: l } = e;
    return o >= i.minX && o <= i.maxX && l >= i.minY && l <= i.maxY;
  }
  onViewUpdate() {
    if (
      (this._didViewChangeTick++, (this._boundsDirty = !0), this.didViewUpdate)
    )
      return;
    this.didViewUpdate = !0;
    const e = this.renderGroup || this.parentRenderGroup;
    e && e.onChildViewUpdate(this);
  }
  destroy(e) {
    super.destroy(e), (this._bounds = null);
    for (const i in this._gpuData) this._gpuData[i].destroy?.();
    this._gpuData = null;
  }
  collectRenderablesSimple(e, i, o) {
    const { renderPipes: l } = i;
    l.blendMode.setBlendMode(this, this.groupBlendMode, e),
      l[this.renderPipeId].addRenderable(this, e),
      (this.didViewUpdate = !1);
    const f = this.children,
      d = f.length;
    for (let m = 0; m < d; m++) f[m].collectRenderables(e, i, o);
  }
}
class Rs extends lS {
  constructor(e = tt.EMPTY) {
    e instanceof tt && (e = { texture: e });
    const {
      texture: i = tt.EMPTY,
      anchor: o,
      roundPixels: l,
      width: c,
      height: f,
      ...d
    } = e;
    super({ label: "Sprite", ...d }),
      (this.renderPipeId = "sprite"),
      (this.batched = !0),
      (this._visualBounds = { minX: 0, maxX: 1, minY: 0, maxY: 0 }),
      (this._anchor = new gt({
        _onUpdate: () => {
          this.onViewUpdate();
        },
      })),
      o
        ? (this.anchor = o)
        : i.defaultAnchor && (this.anchor = i.defaultAnchor),
      (this.texture = i),
      (this.allowChildren = !1),
      (this.roundPixels = l ?? !1),
      c !== void 0 && (this.width = c),
      f !== void 0 && (this.height = f);
  }
  static from(e, i = !1) {
    return e instanceof tt ? new Rs(e) : new Rs(tt.from(e, i));
  }
  set texture(e) {
    e || (e = tt.EMPTY);
    const i = this._texture;
    i !== e &&
      (i && i.dynamic && i.off("update", this.onViewUpdate, this),
      e.dynamic && e.on("update", this.onViewUpdate, this),
      (this._texture = e),
      this._width && this._setWidth(this._width, this._texture.orig.width),
      this._height && this._setHeight(this._height, this._texture.orig.height),
      this.onViewUpdate());
  }
  get texture() {
    return this._texture;
  }
  get visualBounds() {
    return (
      Ax(this._visualBounds, this._anchor, this._texture), this._visualBounds
    );
  }
  get sourceBounds() {
    return (
      zr(
        "8.6.1",
        "Sprite.sourceBounds is deprecated, use visualBounds instead."
      ),
      this.visualBounds
    );
  }
  updateBounds() {
    const e = this._anchor,
      i = this._texture,
      o = this._bounds,
      { width: l, height: c } = i.orig;
    (o.minX = -e._x * l),
      (o.maxX = o.minX + l),
      (o.minY = -e._y * c),
      (o.maxY = o.minY + c);
  }
  destroy(e = !1) {
    if ((super.destroy(e), typeof e == "boolean" ? e : e?.texture)) {
      const o = typeof e == "boolean" ? e : e?.textureSource;
      this._texture.destroy(o);
    }
    (this._texture = null),
      (this._visualBounds = null),
      (this._bounds = null),
      (this._anchor = null),
      (this._gpuData = null);
  }
  get anchor() {
    return this._anchor;
  }
  set anchor(e) {
    typeof e == "number" ? this._anchor.set(e) : this._anchor.copyFrom(e);
  }
  get width() {
    return Math.abs(this.scale.x) * this._texture.orig.width;
  }
  set width(e) {
    this._setWidth(e, this._texture.orig.width), (this._width = e);
  }
  get height() {
    return Math.abs(this.scale.y) * this._texture.orig.height;
  }
  set height(e) {
    this._setHeight(e, this._texture.orig.height), (this._height = e);
  }
  getSize(e) {
    return (
      e || (e = {}),
      (e.width = Math.abs(this.scale.x) * this._texture.orig.width),
      (e.height = Math.abs(this.scale.y) * this._texture.orig.height),
      e
    );
  }
  setSize(e, i) {
    typeof e == "object"
      ? ((i = e.height ?? e.width), (e = e.width))
      : i ?? (i = e),
      e !== void 0 && this._setWidth(e, this._texture.orig.width),
      i !== void 0 && this._setHeight(i, this._texture.orig.height);
  }
}
const uS = new wn();
function xg(r, e, i) {
  const o = uS;
  (r.measurable = !0), yg(r, i, o), e.addBoundsMask(o), (r.measurable = !1);
}
function Sg(r, e, i) {
  const o = $r.get();
  r.measurable = !0;
  const l = Ct.get().identity(),
    c = Eg(r, i, l);
  vg(r, o, c),
    (r.measurable = !1),
    e.addBoundsMask(o),
    Ct.return(l),
    $r.return(o);
}
function Eg(r, e, i) {
  return r
    ? (r !== e &&
        (Eg(r.parent, e, i),
        r.updateLocalTransform(),
        i.append(r.localTransform)),
      i)
    : (vn("Mask bounds, renderable is not inside the root container"), i);
}
class Pg {
  constructor(e) {
    (this.priority = 0),
      (this.inverse = !1),
      (this.pipe = "alphaMask"),
      e?.mask && this.init(e.mask);
  }
  init(e) {
    (this.mask = e),
      (this.renderMaskToTexture = !(e instanceof Rs)),
      (this.mask.renderable = this.renderMaskToTexture),
      (this.mask.includeInBuild = !this.renderMaskToTexture),
      (this.mask.measurable = !1);
  }
  reset() {
    (this.mask.measurable = !0), (this.mask = null);
  }
  addBounds(e, i) {
    this.inverse || xg(this.mask, e, i);
  }
  addLocalBounds(e, i) {
    Sg(this.mask, e, i);
  }
  containsPoint(e, i) {
    const o = this.mask;
    return i(o, e);
  }
  destroy() {
    this.reset();
  }
  static test(e) {
    return e instanceof Rs;
  }
}
Pg.extension = ft.MaskEffect;
class Ag {
  constructor(e) {
    (this.priority = 0),
      (this.pipe = "colorMask"),
      e?.mask && this.init(e.mask);
  }
  init(e) {
    this.mask = e;
  }
  destroy() {}
  static test(e) {
    return typeof e == "number";
  }
}
Ag.extension = ft.MaskEffect;
class Cg {
  constructor(e) {
    (this.priority = 0),
      (this.pipe = "stencilMask"),
      e?.mask && this.init(e.mask);
  }
  init(e) {
    (this.mask = e),
      (this.mask.includeInBuild = !1),
      (this.mask.measurable = !1);
  }
  reset() {
    (this.mask.measurable = !0),
      (this.mask.includeInBuild = !0),
      (this.mask = null);
  }
  addBounds(e, i) {
    xg(this.mask, e, i);
  }
  addLocalBounds(e, i) {
    Sg(this.mask, e, i);
  }
  containsPoint(e, i) {
    const o = this.mask;
    return i(o, e);
  }
  destroy() {
    this.reset();
  }
  static test(e) {
    return e instanceof Fs;
  }
}
Cg.extension = ft.MaskEffect;
const cS = {
  createCanvas: (r, e) => {
    const i = document.createElement("canvas");
    return (i.width = r), (i.height = e), i;
  },
  getCanvasRenderingContext2D: () => CanvasRenderingContext2D,
  getWebGLRenderingContext: () => WebGLRenderingContext,
  getNavigator: () => navigator,
  getBaseUrl: () => document.baseURI ?? window.location.href,
  getFontFaceSet: () => document.fonts,
  fetch: (r, e) => fetch(r, e),
  parseXML: (r) => new DOMParser().parseFromString(r, "text/xml"),
};
let Sm = cS;
const sf = {
  get() {
    return Sm;
  },
  set(r) {
    Sm = r;
  },
};
class kg extends fr {
  constructor(e) {
    e.resource || (e.resource = sf.get().createCanvas()),
      e.width ||
        ((e.width = e.resource.width),
        e.autoDensity || (e.width /= e.resolution)),
      e.height ||
        ((e.height = e.resource.height),
        e.autoDensity || (e.height /= e.resolution)),
      super(e),
      (this.uploadMethodId = "image"),
      (this.autoDensity = e.autoDensity),
      this.resizeCanvas(),
      (this.transparent = !!e.transparent);
  }
  resizeCanvas() {
    this.autoDensity &&
      "style" in this.resource &&
      ((this.resource.style.width = `${this.width}px`),
      (this.resource.style.height = `${this.height}px`)),
      (this.resource.width !== this.pixelWidth ||
        this.resource.height !== this.pixelHeight) &&
        ((this.resource.width = this.pixelWidth),
        (this.resource.height = this.pixelHeight));
  }
  resize(e = this.width, i = this.height, o = this._resolution) {
    const l = super.resize(e, i, o);
    return l && this.resizeCanvas(), l;
  }
  static test(e) {
    return (
      (globalThis.HTMLCanvasElement && e instanceof HTMLCanvasElement) ||
      (globalThis.OffscreenCanvas && e instanceof OffscreenCanvas)
    );
  }
  get context2D() {
    return (
      this._context2D || (this._context2D = this.resource.getContext("2d"))
    );
  }
}
kg.extension = ft.TextureSource;
class Rg extends fr {
  constructor(e) {
    super(e), (this.uploadMethodId = "image"), (this.autoGarbageCollect = !0);
  }
  static test(e) {
    return (
      (globalThis.HTMLImageElement && e instanceof HTMLImageElement) ||
      (typeof ImageBitmap < "u" && e instanceof ImageBitmap) ||
      (globalThis.VideoFrame && e instanceof VideoFrame)
    );
  }
}
Rg.extension = ft.TextureSource;
var Hc = ((r) => (
  (r[(r.INTERACTION = 50)] = "INTERACTION"),
  (r[(r.HIGH = 25)] = "HIGH"),
  (r[(r.NORMAL = 0)] = "NORMAL"),
  (r[(r.LOW = -25)] = "LOW"),
  (r[(r.UTILITY = -50)] = "UTILITY"),
  r
))(Hc || {});
class vc {
  constructor(e, i = null, o = 0, l = !1) {
    (this.next = null),
      (this.previous = null),
      (this._destroyed = !1),
      (this._fn = e),
      (this._context = i),
      (this.priority = o),
      (this._once = l);
  }
  match(e, i = null) {
    return this._fn === e && this._context === i;
  }
  emit(e) {
    this._fn && (this._context ? this._fn.call(this._context, e) : this._fn(e));
    const i = this.next;
    return (
      this._once && this.destroy(!0), this._destroyed && (this.next = null), i
    );
  }
  connect(e) {
    (this.previous = e),
      e.next && (e.next.previous = this),
      (this.next = e.next),
      (e.next = this);
  }
  destroy(e = !1) {
    (this._destroyed = !0),
      (this._fn = null),
      (this._context = null),
      this.previous && (this.previous.next = this.next),
      this.next && (this.next.previous = this.previous);
    const i = this.next;
    return (this.next = e ? null : i), (this.previous = null), i;
  }
}
const bg = class jt {
  constructor() {
    (this.autoStart = !1),
      (this.deltaTime = 1),
      (this.lastTime = -1),
      (this.speed = 1),
      (this.started = !1),
      (this._requestId = null),
      (this._maxElapsedMS = 100),
      (this._minElapsedMS = 0),
      (this._protected = !1),
      (this._lastFrame = -1),
      (this._head = new vc(null, null, 1 / 0)),
      (this.deltaMS = 1 / jt.targetFPMS),
      (this.elapsedMS = 1 / jt.targetFPMS),
      (this._tick = (e) => {
        (this._requestId = null),
          this.started &&
            (this.update(e),
            this.started &&
              this._requestId === null &&
              this._head.next &&
              (this._requestId = requestAnimationFrame(this._tick)));
      });
  }
  _requestIfNeeded() {
    this._requestId === null &&
      this._head.next &&
      ((this.lastTime = performance.now()),
      (this._lastFrame = this.lastTime),
      (this._requestId = requestAnimationFrame(this._tick)));
  }
  _cancelIfNeeded() {
    this._requestId !== null &&
      (cancelAnimationFrame(this._requestId), (this._requestId = null));
  }
  _startIfPossible() {
    this.started ? this._requestIfNeeded() : this.autoStart && this.start();
  }
  add(e, i, o = Hc.NORMAL) {
    return this._addListener(new vc(e, i, o));
  }
  addOnce(e, i, o = Hc.NORMAL) {
    return this._addListener(new vc(e, i, o, !0));
  }
  _addListener(e) {
    let i = this._head.next,
      o = this._head;
    if (!i) e.connect(o);
    else {
      for (; i; ) {
        if (e.priority > i.priority) {
          e.connect(o);
          break;
        }
        (o = i), (i = i.next);
      }
      e.previous || e.connect(o);
    }
    return this._startIfPossible(), this;
  }
  remove(e, i) {
    let o = this._head.next;
    for (; o; ) o.match(e, i) ? (o = o.destroy()) : (o = o.next);
    return this._head.next || this._cancelIfNeeded(), this;
  }
  get count() {
    if (!this._head) return 0;
    let e = 0,
      i = this._head;
    for (; (i = i.next); ) e++;
    return e;
  }
  start() {
    this.started || ((this.started = !0), this._requestIfNeeded());
  }
  stop() {
    this.started && ((this.started = !1), this._cancelIfNeeded());
  }
  destroy() {
    if (!this._protected) {
      this.stop();
      let e = this._head.next;
      for (; e; ) e = e.destroy(!0);
      this._head.destroy(), (this._head = null);
    }
  }
  update(e = performance.now()) {
    let i;
    if (e > this.lastTime) {
      if (
        ((i = this.elapsedMS = e - this.lastTime),
        i > this._maxElapsedMS && (i = this._maxElapsedMS),
        (i *= this.speed),
        this._minElapsedMS)
      ) {
        const c = (e - this._lastFrame) | 0;
        if (c < this._minElapsedMS) return;
        this._lastFrame = e - (c % this._minElapsedMS);
      }
      (this.deltaMS = i), (this.deltaTime = this.deltaMS * jt.targetFPMS);
      const o = this._head;
      let l = o.next;
      for (; l; ) l = l.emit(this);
      o.next || this._cancelIfNeeded();
    } else this.deltaTime = this.deltaMS = this.elapsedMS = 0;
    this.lastTime = e;
  }
  get FPS() {
    return 1e3 / this.elapsedMS;
  }
  get minFPS() {
    return 1e3 / this._maxElapsedMS;
  }
  set minFPS(e) {
    const i = Math.min(this.maxFPS, e),
      o = Math.min(Math.max(0, i) / 1e3, jt.targetFPMS);
    this._maxElapsedMS = 1 / o;
  }
  get maxFPS() {
    return this._minElapsedMS ? Math.round(1e3 / this._minElapsedMS) : 0;
  }
  set maxFPS(e) {
    if (e === 0) this._minElapsedMS = 0;
    else {
      const i = Math.max(this.minFPS, e);
      this._minElapsedMS = 1 / (i / 1e3);
    }
  }
  static get shared() {
    if (!jt._shared) {
      const e = (jt._shared = new jt());
      (e.autoStart = !0), (e._protected = !0);
    }
    return jt._shared;
  }
  static get system() {
    if (!jt._system) {
      const e = (jt._system = new jt());
      (e.autoStart = !0), (e._protected = !0);
    }
    return jt._system;
  }
};
bg.targetFPMS = 0.06;
let jr = bg,
  _c;
async function fS() {
  return (
    _c ??
      (_c = (async () => {
        const e = document.createElement("canvas").getContext("webgl");
        if (!e) return "premultiply-alpha-on-upload";
        const i = await new Promise((f) => {
          const d = document.createElement("video");
          (d.onloadeddata = () => f(d)),
            (d.onerror = () => f(null)),
            (d.autoplay = !1),
            (d.crossOrigin = "anonymous"),
            (d.preload = "auto"),
            (d.src =
              "data:video/webm;base64,GkXfo59ChoEBQveBAULygQRC84EIQoKEd2VibUKHgQJChYECGFOAZwEAAAAAAAHTEU2bdLpNu4tTq4QVSalmU6yBoU27i1OrhBZUrmtTrIHGTbuMU6uEElTDZ1OsggEXTbuMU6uEHFO7a1OsggG97AEAAAAAAABZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVSalmoCrXsYMPQkBNgIRMYXZmV0GETGF2ZkSJiEBEAAAAAAAAFlSua8yuAQAAAAAAAEPXgQFzxYgAAAAAAAAAAZyBACK1nIN1bmSIgQCGhVZfVlA5g4EBI+ODhAJiWgDglLCBArqBApqBAlPAgQFVsIRVuYEBElTDZ9Vzc9JjwItjxYgAAAAAAAAAAWfInEWjh0VOQ09ERVJEh49MYXZjIGxpYnZweC12cDlnyKJFo4hEVVJBVElPTkSHlDAwOjAwOjAwLjA0MDAwMDAwMAAAH0O2dcfngQCgwqGggQAAAIJJg0IAABAAFgA4JBwYSgAAICAAEb///4r+AAB1oZ2mm+6BAaWWgkmDQgAAEAAWADgkHBhKAAAgIABIQBxTu2uRu4+zgQC3iveBAfGCAXHwgQM="),
            d.load();
        });
        if (!i) return "premultiply-alpha-on-upload";
        const o = e.createTexture();
        e.bindTexture(e.TEXTURE_2D, o);
        const l = e.createFramebuffer();
        e.bindFramebuffer(e.FRAMEBUFFER, l),
          e.framebufferTexture2D(
            e.FRAMEBUFFER,
            e.COLOR_ATTACHMENT0,
            e.TEXTURE_2D,
            o,
            0
          ),
          e.pixelStorei(e.UNPACK_PREMULTIPLY_ALPHA_WEBGL, !1),
          e.pixelStorei(e.UNPACK_COLORSPACE_CONVERSION_WEBGL, e.NONE),
          e.texImage2D(e.TEXTURE_2D, 0, e.RGBA, e.RGBA, e.UNSIGNED_BYTE, i);
        const c = new Uint8Array(4);
        return (
          e.readPixels(0, 0, 1, 1, e.RGBA, e.UNSIGNED_BYTE, c),
          e.deleteFramebuffer(l),
          e.deleteTexture(o),
          e.getExtension("WEBGL_lose_context")?.loseContext(),
          c[0] <= c[3] ? "premultiplied-alpha" : "premultiply-alpha-on-upload"
        );
      })()),
    _c
  );
}
const ka = class Tg extends fr {
  constructor(e) {
    super(e),
      (this.isReady = !1),
      (this.uploadMethodId = "video"),
      (e = { ...Tg.defaultOptions, ...e }),
      (this._autoUpdate = !0),
      (this._isConnectedToTicker = !1),
      (this._updateFPS = e.updateFPS || 0),
      (this._msToNextUpdate = 0),
      (this.autoPlay = e.autoPlay !== !1),
      (this.alphaMode = e.alphaMode ?? "premultiply-alpha-on-upload"),
      (this._videoFrameRequestCallback =
        this._videoFrameRequestCallback.bind(this)),
      (this._videoFrameRequestCallbackHandle = null),
      (this._load = null),
      (this._resolve = null),
      (this._reject = null),
      (this._onCanPlay = this._onCanPlay.bind(this)),
      (this._onCanPlayThrough = this._onCanPlayThrough.bind(this)),
      (this._onError = this._onError.bind(this)),
      (this._onPlayStart = this._onPlayStart.bind(this)),
      (this._onPlayStop = this._onPlayStop.bind(this)),
      (this._onSeeked = this._onSeeked.bind(this)),
      e.autoLoad !== !1 && this.load();
  }
  updateFrame() {
    if (!this.destroyed) {
      if (this._updateFPS) {
        const e = jr.shared.elapsedMS * this.resource.playbackRate;
        this._msToNextUpdate = Math.floor(this._msToNextUpdate - e);
      }
      (!this._updateFPS || this._msToNextUpdate <= 0) &&
        (this._msToNextUpdate = this._updateFPS
          ? Math.floor(1e3 / this._updateFPS)
          : 0),
        this.isValid && this.update();
    }
  }
  _videoFrameRequestCallback() {
    this.updateFrame(),
      this.destroyed
        ? (this._videoFrameRequestCallbackHandle = null)
        : (this._videoFrameRequestCallbackHandle =
            this.resource.requestVideoFrameCallback(
              this._videoFrameRequestCallback
            ));
  }
  get isValid() {
    return !!this.resource.videoWidth && !!this.resource.videoHeight;
  }
  async load() {
    if (this._load) return this._load;
    const e = this.resource,
      i = this.options;
    return (
      (e.readyState === e.HAVE_ENOUGH_DATA ||
        e.readyState === e.HAVE_FUTURE_DATA) &&
        e.width &&
        e.height &&
        (e.complete = !0),
      e.addEventListener("play", this._onPlayStart),
      e.addEventListener("pause", this._onPlayStop),
      e.addEventListener("seeked", this._onSeeked),
      this._isSourceReady()
        ? this._mediaReady()
        : (i.preload || e.addEventListener("canplay", this._onCanPlay),
          e.addEventListener("canplaythrough", this._onCanPlayThrough),
          e.addEventListener("error", this._onError, !0)),
      (this.alphaMode = await fS()),
      (this._load = new Promise((o, l) => {
        this.isValid
          ? o(this)
          : ((this._resolve = o),
            (this._reject = l),
            i.preloadTimeoutMs !== void 0 &&
              (this._preloadTimeout = setTimeout(() => {
                this._onError(
                  new ErrorEvent(
                    `Preload exceeded timeout of ${i.preloadTimeoutMs}ms`
                  )
                );
              })),
            e.load());
      })),
      this._load
    );
  }
  _onError(e) {
    this.resource.removeEventListener("error", this._onError, !0),
      this.emit("error", e),
      this._reject &&
        (this._reject(e), (this._reject = null), (this._resolve = null));
  }
  _isSourcePlaying() {
    const e = this.resource;
    return !e.paused && !e.ended;
  }
  _isSourceReady() {
    return this.resource.readyState > 2;
  }
  _onPlayStart() {
    this.isValid || this._mediaReady(), this._configureAutoUpdate();
  }
  _onPlayStop() {
    this._configureAutoUpdate();
  }
  _onSeeked() {
    this._autoUpdate &&
      !this._isSourcePlaying() &&
      ((this._msToNextUpdate = 0),
      this.updateFrame(),
      (this._msToNextUpdate = 0));
  }
  _onCanPlay() {
    this.resource.removeEventListener("canplay", this._onCanPlay),
      this._mediaReady();
  }
  _onCanPlayThrough() {
    this.resource.removeEventListener("canplaythrough", this._onCanPlay),
      this._preloadTimeout &&
        (clearTimeout(this._preloadTimeout), (this._preloadTimeout = void 0)),
      this._mediaReady();
  }
  _mediaReady() {
    const e = this.resource;
    this.isValid &&
      ((this.isReady = !0), this.resize(e.videoWidth, e.videoHeight)),
      (this._msToNextUpdate = 0),
      this.updateFrame(),
      (this._msToNextUpdate = 0),
      this._resolve &&
        (this._resolve(this), (this._resolve = null), (this._reject = null)),
      this._isSourcePlaying()
        ? this._onPlayStart()
        : this.autoPlay && this.resource.play();
  }
  destroy() {
    this._configureAutoUpdate();
    const e = this.resource;
    e &&
      (e.removeEventListener("play", this._onPlayStart),
      e.removeEventListener("pause", this._onPlayStop),
      e.removeEventListener("seeked", this._onSeeked),
      e.removeEventListener("canplay", this._onCanPlay),
      e.removeEventListener("canplaythrough", this._onCanPlayThrough),
      e.removeEventListener("error", this._onError, !0),
      e.pause(),
      (e.src = ""),
      e.load()),
      super.destroy();
  }
  get autoUpdate() {
    return this._autoUpdate;
  }
  set autoUpdate(e) {
    e !== this._autoUpdate &&
      ((this._autoUpdate = e), this._configureAutoUpdate());
  }
  get updateFPS() {
    return this._updateFPS;
  }
  set updateFPS(e) {
    e !== this._updateFPS &&
      ((this._updateFPS = e), this._configureAutoUpdate());
  }
  _configureAutoUpdate() {
    this._autoUpdate && this._isSourcePlaying()
      ? !this._updateFPS && this.resource.requestVideoFrameCallback
        ? (this._isConnectedToTicker &&
            (jr.shared.remove(this.updateFrame, this),
            (this._isConnectedToTicker = !1),
            (this._msToNextUpdate = 0)),
          this._videoFrameRequestCallbackHandle === null &&
            (this._videoFrameRequestCallbackHandle =
              this.resource.requestVideoFrameCallback(
                this._videoFrameRequestCallback
              )))
        : (this._videoFrameRequestCallbackHandle !== null &&
            (this.resource.cancelVideoFrameCallback(
              this._videoFrameRequestCallbackHandle
            ),
            (this._videoFrameRequestCallbackHandle = null)),
          this._isConnectedToTicker ||
            (jr.shared.add(this.updateFrame, this),
            (this._isConnectedToTicker = !0),
            (this._msToNextUpdate = 0)))
      : (this._videoFrameRequestCallbackHandle !== null &&
          (this.resource.cancelVideoFrameCallback(
            this._videoFrameRequestCallbackHandle
          ),
          (this._videoFrameRequestCallbackHandle = null)),
        this._isConnectedToTicker &&
          (jr.shared.remove(this.updateFrame, this),
          (this._isConnectedToTicker = !1),
          (this._msToNextUpdate = 0)));
  }
  static test(e) {
    return globalThis.HTMLVideoElement && e instanceof HTMLVideoElement;
  }
};
ka.extension = ft.TextureSource;
ka.defaultOptions = {
  ...fr.defaultOptions,
  autoLoad: !0,
  autoPlay: !0,
  updateFPS: 0,
  crossorigin: !0,
  loop: !1,
  muted: !0,
  playsinline: !0,
  preload: !1,
};
ka.MIME_TYPES = { ogv: "video/ogg", mov: "video/quicktime", m4v: "video/mp4" };
let hS = ka;
const _i = (r, e, i = !1) => (
  Array.isArray(r) || (r = [r]),
  e ? r.map((o) => (typeof o == "string" || i ? e(o) : o)) : r
);
class dS {
  constructor() {
    (this._parsers = []),
      (this._cache = new Map()),
      (this._cacheMap = new Map());
  }
  reset() {
    this._cacheMap.clear(), this._cache.clear();
  }
  has(e) {
    return this._cache.has(e);
  }
  get(e) {
    const i = this._cache.get(e);
    return i || vn(`[Assets] Asset id ${e} was not found in the Cache`), i;
  }
  set(e, i) {
    const o = _i(e);
    let l;
    for (let m = 0; m < this.parsers.length; m++) {
      const p = this.parsers[m];
      if (p.test(i)) {
        l = p.getCacheableAssets(o, i);
        break;
      }
    }
    const c = new Map(Object.entries(l || {}));
    l ||
      o.forEach((m) => {
        c.set(m, i);
      });
    const f = [...c.keys()],
      d = { cacheKeys: f, keys: o };
    o.forEach((m) => {
      this._cacheMap.set(m, d);
    }),
      f.forEach((m) => {
        const p = l ? l[m] : i;
        this._cache.has(m) &&
          this._cache.get(m) !== p &&
          vn("[Cache] already has key:", m),
          this._cache.set(m, c.get(m));
      });
  }
  remove(e) {
    if (!this._cacheMap.has(e)) {
      vn(`[Assets] Asset id ${e} was not found in the Cache`);
      return;
    }
    const i = this._cacheMap.get(e);
    i.cacheKeys.forEach((l) => {
      this._cache.delete(l);
    }),
      i.keys.forEach((l) => {
        this._cacheMap.delete(l);
      });
  }
  get parsers() {
    return this._parsers;
  }
}
const wi = new dS(),
  qc = [];
xn.handleByList(ft.TextureSource, qc);
function Og(r = {}) {
  const e = r && r.resource,
    i = e ? r.resource : r,
    o = e ? r : { resource: r };
  for (let l = 0; l < qc.length; l++) {
    const c = qc[l];
    if (c.test(i)) return new c(o);
  }
  throw new Error(`Could not find a source type for resource: ${o.resource}`);
}
function pS(r = {}, e = !1) {
  const i = r && r.resource,
    o = i ? r.resource : r,
    l = i ? r : { resource: r };
  if (!e && wi.has(o)) return wi.get(o);
  const c = new tt({ source: Og(l) });
  return (
    c.on("destroy", () => {
      wi.has(o) && wi.remove(o);
    }),
    e || wi.set(o, c),
    c
  );
}
function mS(r, e = !1) {
  return typeof r == "string"
    ? wi.get(r)
    : r instanceof fr
    ? new tt({ source: r })
    : pS(r, e);
}
tt.from = mS;
fr.from = Og;
xn.add(Pg, Ag, Cg, hS, Rg, kg, tf);
var of = ((r) => (
  (r[(r.Low = 0)] = "Low"),
  (r[(r.Normal = 1)] = "Normal"),
  (r[(r.High = 2)] = "High"),
  r
))(of || {});
function ar(r) {
  if (typeof r != "string")
    throw new TypeError(`Path must be a string. Received ${JSON.stringify(r)}`);
}
function vs(r) {
  return r.split("?")[0].split("#")[0];
}
function yS(r) {
  return r.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function gS(r, e, i) {
  return r.replace(new RegExp(yS(e), "g"), i);
}
function vS(r, e) {
  let i = "",
    o = 0,
    l = -1,
    c = 0,
    f = -1;
  for (let d = 0; d <= r.length; ++d) {
    if (d < r.length) f = r.charCodeAt(d);
    else {
      if (f === 47) break;
      f = 47;
    }
    if (f === 47) {
      if (!(l === d - 1 || c === 1))
        if (l !== d - 1 && c === 2) {
          if (
            i.length < 2 ||
            o !== 2 ||
            i.charCodeAt(i.length - 1) !== 46 ||
            i.charCodeAt(i.length - 2) !== 46
          ) {
            if (i.length > 2) {
              const m = i.lastIndexOf("/");
              if (m !== i.length - 1) {
                m === -1
                  ? ((i = ""), (o = 0))
                  : ((i = i.slice(0, m)),
                    (o = i.length - 1 - i.lastIndexOf("/"))),
                  (l = d),
                  (c = 0);
                continue;
              }
            } else if (i.length === 2 || i.length === 1) {
              (i = ""), (o = 0), (l = d), (c = 0);
              continue;
            }
          }
        } else
          i.length > 0
            ? (i += `/${r.slice(l + 1, d)}`)
            : (i = r.slice(l + 1, d)),
            (o = d - l - 1);
      (l = d), (c = 0);
    } else f === 46 && c !== -1 ? ++c : (c = -1);
  }
  return i;
}
const Hr = {
  toPosix(r) {
    return gS(r, "\\", "/");
  },
  isUrl(r) {
    return /^https?:/.test(this.toPosix(r));
  },
  isDataUrl(r) {
    return /^data:([a-z]+\/[a-z0-9-+.]+(;[a-z0-9-.!#$%*+.{}|~`]+=[a-z0-9-.!#$%*+.{}()_|~`]+)*)?(;base64)?,([a-z0-9!$&',()*+;=\-._~:@\/?%\s<>]*?)$/i.test(
      r
    );
  },
  isBlobUrl(r) {
    return r.startsWith("blob:");
  },
  hasProtocol(r) {
    return /^[^/:]+:/.test(this.toPosix(r));
  },
  getProtocol(r) {
    ar(r), (r = this.toPosix(r));
    const e = /^file:\/\/\//.exec(r);
    if (e) return e[0];
    const i = /^[^/:]+:\/{0,2}/.exec(r);
    return i ? i[0] : "";
  },
  toAbsolute(r, e, i) {
    if ((ar(r), this.isDataUrl(r) || this.isBlobUrl(r))) return r;
    const o = vs(this.toPosix(e ?? sf.get().getBaseUrl())),
      l = vs(this.toPosix(i ?? this.rootname(o)));
    return (
      (r = this.toPosix(r)),
      r.startsWith("/")
        ? Hr.join(l, r.slice(1))
        : this.isAbsolute(r)
        ? r
        : this.join(o, r)
    );
  },
  normalize(r) {
    if ((ar(r), r.length === 0)) return ".";
    if (this.isDataUrl(r) || this.isBlobUrl(r)) return r;
    r = this.toPosix(r);
    let e = "";
    const i = r.startsWith("/");
    this.hasProtocol(r) && ((e = this.rootname(r)), (r = r.slice(e.length)));
    const o = r.endsWith("/");
    return (r = vS(r)), r.length > 0 && o && (r += "/"), i ? `/${r}` : e + r;
  },
  isAbsolute(r) {
    return (
      ar(r), (r = this.toPosix(r)), this.hasProtocol(r) ? !0 : r.startsWith("/")
    );
  },
  join(...r) {
    if (r.length === 0) return ".";
    let e;
    for (let i = 0; i < r.length; ++i) {
      const o = r[i];
      if ((ar(o), o.length > 0))
        if (e === void 0) e = o;
        else {
          const l = r[i - 1] ?? "";
          this.joinExtensions.includes(this.extname(l).toLowerCase())
            ? (e += `/../${o}`)
            : (e += `/${o}`);
        }
    }
    return e === void 0 ? "." : this.normalize(e);
  },
  dirname(r) {
    if ((ar(r), r.length === 0)) return ".";
    r = this.toPosix(r);
    let e = r.charCodeAt(0);
    const i = e === 47;
    let o = -1,
      l = !0;
    const c = this.getProtocol(r),
      f = r;
    r = r.slice(c.length);
    for (let d = r.length - 1; d >= 1; --d)
      if (((e = r.charCodeAt(d)), e === 47)) {
        if (!l) {
          o = d;
          break;
        }
      } else l = !1;
    return o === -1
      ? i
        ? "/"
        : this.isUrl(f)
        ? c + r
        : c
      : i && o === 1
      ? "//"
      : c + r.slice(0, o);
  },
  rootname(r) {
    ar(r), (r = this.toPosix(r));
    let e = "";
    if (
      (r.startsWith("/") ? (e = "/") : (e = this.getProtocol(r)), this.isUrl(r))
    ) {
      const i = r.indexOf("/", e.length);
      i !== -1 ? (e = r.slice(0, i)) : (e = r), e.endsWith("/") || (e += "/");
    }
    return e;
  },
  basename(r, e) {
    ar(r), e && ar(e), (r = vs(this.toPosix(r)));
    let i = 0,
      o = -1,
      l = !0,
      c;
    if (e !== void 0 && e.length > 0 && e.length <= r.length) {
      if (e.length === r.length && e === r) return "";
      let f = e.length - 1,
        d = -1;
      for (c = r.length - 1; c >= 0; --c) {
        const m = r.charCodeAt(c);
        if (m === 47) {
          if (!l) {
            i = c + 1;
            break;
          }
        } else
          d === -1 && ((l = !1), (d = c + 1)),
            f >= 0 &&
              (m === e.charCodeAt(f)
                ? --f === -1 && (o = c)
                : ((f = -1), (o = d)));
      }
      return i === o ? (o = d) : o === -1 && (o = r.length), r.slice(i, o);
    }
    for (c = r.length - 1; c >= 0; --c)
      if (r.charCodeAt(c) === 47) {
        if (!l) {
          i = c + 1;
          break;
        }
      } else o === -1 && ((l = !1), (o = c + 1));
    return o === -1 ? "" : r.slice(i, o);
  },
  extname(r) {
    ar(r), (r = vs(this.toPosix(r)));
    let e = -1,
      i = 0,
      o = -1,
      l = !0,
      c = 0;
    for (let f = r.length - 1; f >= 0; --f) {
      const d = r.charCodeAt(f);
      if (d === 47) {
        if (!l) {
          i = f + 1;
          break;
        }
        continue;
      }
      o === -1 && ((l = !1), (o = f + 1)),
        d === 46
          ? e === -1
            ? (e = f)
            : c !== 1 && (c = 1)
          : e !== -1 && (c = -1);
    }
    return e === -1 ||
      o === -1 ||
      c === 0 ||
      (c === 1 && e === o - 1 && e === i + 1)
      ? ""
      : r.slice(e, o);
  },
  parse(r) {
    ar(r);
    const e = { root: "", dir: "", base: "", ext: "", name: "" };
    if (r.length === 0) return e;
    r = vs(this.toPosix(r));
    let i = r.charCodeAt(0);
    const o = this.isAbsolute(r);
    let l;
    (e.root = this.rootname(r)), o || this.hasProtocol(r) ? (l = 1) : (l = 0);
    let c = -1,
      f = 0,
      d = -1,
      m = !0,
      p = r.length - 1,
      g = 0;
    for (; p >= l; --p) {
      if (((i = r.charCodeAt(p)), i === 47)) {
        if (!m) {
          f = p + 1;
          break;
        }
        continue;
      }
      d === -1 && ((m = !1), (d = p + 1)),
        i === 46
          ? c === -1
            ? (c = p)
            : g !== 1 && (g = 1)
          : c !== -1 && (g = -1);
    }
    return (
      c === -1 || d === -1 || g === 0 || (g === 1 && c === d - 1 && c === f + 1)
        ? d !== -1 &&
          (f === 0 && o
            ? (e.base = e.name = r.slice(1, d))
            : (e.base = e.name = r.slice(f, d)))
        : (f === 0 && o
            ? ((e.name = r.slice(1, c)), (e.base = r.slice(1, d)))
            : ((e.name = r.slice(f, c)), (e.base = r.slice(f, d))),
          (e.ext = r.slice(c, d))),
      (e.dir = this.dirname(r)),
      e
    );
  },
  sep: "/",
  delimiter: ":",
  joinExtensions: [".html"],
};
function Mg(r, e, i, o, l) {
  const c = e[i];
  for (let f = 0; f < c.length; f++) {
    const d = c[f];
    i < e.length - 1
      ? Mg(r.replace(o[i], d), e, i + 1, o, l)
      : l.push(r.replace(o[i], d));
  }
}
function _S(r) {
  const e = /\{(.*?)\}/g,
    i = r.match(e),
    o = [];
  if (i) {
    const l = [];
    i.forEach((c) => {
      const f = c.substring(1, c.length - 1).split(",");
      l.push(f);
    }),
      Mg(r, l, 0, i, o);
  } else o.push(r);
  return o;
}
const Em = (r) => !Array.isArray(r);
class Ig {
  constructor() {
    (this._defaultBundleIdentifierOptions = {
      connector: "-",
      createBundleAssetId: (e, i) => `${e}${this._bundleIdConnector}${i}`,
      extractAssetIdFromBundle: (e, i) =>
        i.replace(`${e}${this._bundleIdConnector}`, ""),
    }),
      (this._bundleIdConnector =
        this._defaultBundleIdentifierOptions.connector),
      (this._createBundleAssetId =
        this._defaultBundleIdentifierOptions.createBundleAssetId),
      (this._extractAssetIdFromBundle =
        this._defaultBundleIdentifierOptions.extractAssetIdFromBundle),
      (this._assetMap = {}),
      (this._preferredOrder = []),
      (this._parsers = []),
      (this._resolverHash = {}),
      (this._bundles = {});
  }
  setBundleIdentifier(e) {
    if (
      ((this._bundleIdConnector = e.connector ?? this._bundleIdConnector),
      (this._createBundleAssetId =
        e.createBundleAssetId ?? this._createBundleAssetId),
      (this._extractAssetIdFromBundle =
        e.extractAssetIdFromBundle ?? this._extractAssetIdFromBundle),
      this._extractAssetIdFromBundle(
        "foo",
        this._createBundleAssetId("foo", "bar")
      ) !== "bar")
    )
      throw new Error(
        "[Resolver] GenerateBundleAssetId are not working correctly"
      );
  }
  prefer(...e) {
    e.forEach((i) => {
      this._preferredOrder.push(i),
        i.priority || (i.priority = Object.keys(i.params));
    }),
      (this._resolverHash = {});
  }
  set basePath(e) {
    this._basePath = e;
  }
  get basePath() {
    return this._basePath;
  }
  set rootPath(e) {
    this._rootPath = e;
  }
  get rootPath() {
    return this._rootPath;
  }
  get parsers() {
    return this._parsers;
  }
  reset() {
    this.setBundleIdentifier(this._defaultBundleIdentifierOptions),
      (this._assetMap = {}),
      (this._preferredOrder = []),
      (this._resolverHash = {}),
      (this._rootPath = null),
      (this._basePath = null),
      (this._manifest = null),
      (this._bundles = {}),
      (this._defaultSearchParams = null);
  }
  setDefaultSearchParams(e) {
    if (typeof e == "string") this._defaultSearchParams = e;
    else {
      const i = e;
      this._defaultSearchParams = Object.keys(i)
        .map((o) => `${encodeURIComponent(o)}=${encodeURIComponent(i[o])}`)
        .join("&");
    }
  }
  getAlias(e) {
    const { alias: i, src: o } = e;
    return _i(
      i || o,
      (c) =>
        typeof c == "string"
          ? c
          : Array.isArray(c)
          ? c.map((f) => f?.src ?? f)
          : c?.src
          ? c.src
          : c,
      !0
    );
  }
  addManifest(e) {
    this._manifest &&
      vn("[Resolver] Manifest already exists, this will be overwritten"),
      (this._manifest = e),
      e.bundles.forEach((i) => {
        this.addBundle(i.name, i.assets);
      });
  }
  addBundle(e, i) {
    const o = [];
    let l = i;
    Array.isArray(i) ||
      (l = Object.entries(i).map(([c, f]) =>
        typeof f == "string" || Array.isArray(f)
          ? { alias: c, src: f }
          : { alias: c, ...f }
      )),
      l.forEach((c) => {
        const f = c.src,
          d = c.alias;
        let m;
        if (typeof d == "string") {
          const p = this._createBundleAssetId(e, d);
          o.push(p), (m = [d, p]);
        } else {
          const p = d.map((g) => this._createBundleAssetId(e, g));
          o.push(...p), (m = [...d, ...p]);
        }
        this.add({ ...c, alias: m, src: f });
      }),
      (this._bundles[e] = o);
  }
  add(e) {
    const i = [];
    Array.isArray(e) ? i.push(...e) : i.push(e);
    let o;
    (o = (c) => {
      this.hasKey(c) && vn(`[Resolver] already has key: ${c} overwriting`);
    }),
      _i(i).forEach((c) => {
        const { src: f } = c;
        let { data: d, format: m, loadParser: p } = c;
        const g = _i(f).map((w) =>
            typeof w == "string" ? _S(w) : Array.isArray(w) ? w : [w]
          ),
          v = this.getAlias(c);
        Array.isArray(v) ? v.forEach(o) : o(v);
        const x = [];
        g.forEach((w) => {
          w.forEach((E) => {
            let k = {};
            if (typeof E != "object") {
              k.src = E;
              for (let _ = 0; _ < this._parsers.length; _++) {
                const A = this._parsers[_];
                if (A.test(E)) {
                  k = A.parse(E);
                  break;
                }
              }
            } else
              (d = E.data ?? d),
                (m = E.format ?? m),
                (p = E.loadParser ?? p),
                (k = { ...k, ...E });
            if (!v)
              throw new Error(
                `[Resolver] alias is undefined for this asset: ${k.src}`
              );
            (k = this._buildResolvedAsset(k, {
              aliases: v,
              data: d,
              format: m,
              loadParser: p,
            })),
              x.push(k);
          });
        }),
          v.forEach((w) => {
            this._assetMap[w] = x;
          });
      });
  }
  resolveBundle(e) {
    const i = Em(e);
    e = _i(e);
    const o = {};
    return (
      e.forEach((l) => {
        const c = this._bundles[l];
        if (c) {
          const f = this.resolve(c),
            d = {};
          for (const m in f) {
            const p = f[m];
            d[this._extractAssetIdFromBundle(l, m)] = p;
          }
          o[l] = d;
        }
      }),
      i ? o[e[0]] : o
    );
  }
  resolveUrl(e) {
    const i = this.resolve(e);
    if (typeof e != "string") {
      const o = {};
      for (const l in i) o[l] = i[l].src;
      return o;
    }
    return i.src;
  }
  resolve(e) {
    const i = Em(e);
    e = _i(e);
    const o = {};
    return (
      e.forEach((l) => {
        if (!this._resolverHash[l])
          if (this._assetMap[l]) {
            let c = this._assetMap[l];
            const f = this._getPreferredOrder(c);
            f?.priority.forEach((d) => {
              f.params[d].forEach((m) => {
                const p = c.filter((g) => (g[d] ? g[d] === m : !1));
                p.length && (c = p);
              });
            }),
              (this._resolverHash[l] = c[0]);
          } else
            this._resolverHash[l] = this._buildResolvedAsset(
              { alias: [l], src: l },
              {}
            );
        o[l] = this._resolverHash[l];
      }),
      i ? o[e[0]] : o
    );
  }
  hasKey(e) {
    return !!this._assetMap[e];
  }
  hasBundle(e) {
    return !!this._bundles[e];
  }
  _getPreferredOrder(e) {
    for (let i = 0; i < e.length; i++) {
      const o = e[i],
        l = this._preferredOrder.find((c) =>
          c.params.format.includes(o.format)
        );
      if (l) return l;
    }
    return this._preferredOrder[0];
  }
  _appendDefaultSearchParams(e) {
    if (!this._defaultSearchParams) return e;
    const i = /\?/.test(e) ? "&" : "?";
    return `${e}${i}${this._defaultSearchParams}`;
  }
  _buildResolvedAsset(e, i) {
    const { aliases: o, data: l, loadParser: c, format: f } = i;
    return (
      (this._basePath || this._rootPath) &&
        (e.src = Hr.toAbsolute(e.src, this._basePath, this._rootPath)),
      (e.alias = o ?? e.alias ?? [e.src]),
      (e.src = this._appendDefaultSearchParams(e.src)),
      (e.data = { ...(l || {}), ...e.data }),
      (e.loadParser = c ?? e.loadParser),
      (e.format = f ?? e.format ?? wS(e.src)),
      e
    );
  }
}
Ig.RETINA_PREFIX = /@([0-9\.]+)x/;
function wS(r) {
  return r.split(".").pop().split("?").shift().split("#").shift();
}
const Pm = (r, e) => {
    const i = e.split("?")[1];
    return i && (r += `?${i}`), r;
  },
  Lg = class Es {
    constructor(e, i) {
      this.linkedSheets = [];
      let o = e;
      e?.source instanceof fr && (o = { texture: e, data: i });
      const { texture: l, data: c, cachePrefix: f = "" } = o;
      (this.cachePrefix = f),
        (this._texture = l instanceof tt ? l : null),
        (this.textureSource = l.source),
        (this.textures = {}),
        (this.animations = {}),
        (this.data = c);
      const d = parseFloat(c.meta.scale);
      d
        ? ((this.resolution = d), (l.source.resolution = this.resolution))
        : (this.resolution = l.source._resolution),
        (this._frames = this.data.frames),
        (this._frameKeys = Object.keys(this._frames)),
        (this._batchIndex = 0),
        (this._callback = null);
    }
    parse() {
      return new Promise((e) => {
        (this._callback = e),
          (this._batchIndex = 0),
          this._frameKeys.length <= Es.BATCH_SIZE
            ? (this._processFrames(0),
              this._processAnimations(),
              this._parseComplete())
            : this._nextBatch();
      });
    }
    _processFrames(e) {
      let i = e;
      const o = Es.BATCH_SIZE;
      for (; i - e < o && i < this._frameKeys.length; ) {
        const l = this._frameKeys[i],
          c = this._frames[l],
          f = c.frame;
        if (f) {
          let d = null,
            m = null;
          const p = c.trimmed !== !1 && c.sourceSize ? c.sourceSize : c.frame,
            g = new Pr(
              0,
              0,
              Math.floor(p.w) / this.resolution,
              Math.floor(p.h) / this.resolution
            );
          c.rotated
            ? (d = new Pr(
                Math.floor(f.x) / this.resolution,
                Math.floor(f.y) / this.resolution,
                Math.floor(f.h) / this.resolution,
                Math.floor(f.w) / this.resolution
              ))
            : (d = new Pr(
                Math.floor(f.x) / this.resolution,
                Math.floor(f.y) / this.resolution,
                Math.floor(f.w) / this.resolution,
                Math.floor(f.h) / this.resolution
              )),
            c.trimmed !== !1 &&
              c.spriteSourceSize &&
              (m = new Pr(
                Math.floor(c.spriteSourceSize.x) / this.resolution,
                Math.floor(c.spriteSourceSize.y) / this.resolution,
                Math.floor(f.w) / this.resolution,
                Math.floor(f.h) / this.resolution
              )),
            (this.textures[l] = new tt({
              source: this.textureSource,
              frame: d,
              orig: g,
              trim: m,
              rotate: c.rotated ? 2 : 0,
              defaultAnchor: c.anchor,
              defaultBorders: c.borders,
              label: l.toString(),
            }));
        }
        i++;
      }
    }
    _processAnimations() {
      const e = this.data.animations || {};
      for (const i in e) {
        this.animations[i] = [];
        for (let o = 0; o < e[i].length; o++) {
          const l = e[i][o];
          this.animations[i].push(this.textures[l]);
        }
      }
    }
    _parseComplete() {
      const e = this._callback;
      (this._callback = null),
        (this._batchIndex = 0),
        e.call(this, this.textures);
    }
    _nextBatch() {
      this._processFrames(this._batchIndex * Es.BATCH_SIZE),
        this._batchIndex++,
        setTimeout(() => {
          this._batchIndex * Es.BATCH_SIZE < this._frameKeys.length
            ? this._nextBatch()
            : (this._processAnimations(), this._parseComplete());
        }, 0);
    }
    destroy(e = !1) {
      for (const i in this.textures) this.textures[i].destroy();
      (this._frames = null),
        (this._frameKeys = null),
        (this.data = null),
        (this.textures = null),
        e && (this._texture?.destroy(), this.textureSource.destroy()),
        (this._texture = null),
        (this.textureSource = null),
        (this.linkedSheets = []);
    }
  };
Lg.BATCH_SIZE = 1e3;
let Am = Lg;
const xS = [
  "jpg",
  "png",
  "jpeg",
  "avif",
  "webp",
  "basis",
  "etc2",
  "bc7",
  "bc6h",
  "bc5",
  "bc4",
  "bc3",
  "bc2",
  "bc1",
  "eac",
  "astc",
];
function Fg(r, e, i) {
  const o = {};
  if (
    (r.forEach((l) => {
      o[l] = e;
    }),
    Object.keys(e.textures).forEach((l) => {
      o[`${e.cachePrefix}${l}`] = e.textures[l];
    }),
    !i)
  ) {
    const l = Hr.dirname(r[0]);
    e.linkedSheets.forEach((c, f) => {
      const d = Fg([`${l}/${e.data.meta.related_multi_packs[f]}`], c, !0);
      Object.assign(o, d);
    });
  }
  return o;
}
const SS = {
  extension: ft.Asset,
  cache: {
    test: (r) => r instanceof Am,
    getCacheableAssets: (r, e) => Fg(r, e, !1),
  },
  resolver: {
    extension: { type: ft.ResolveParser, name: "resolveSpritesheet" },
    test: (r) => {
      const i = r.split("?")[0].split("."),
        o = i.pop(),
        l = i.pop();
      return o === "json" && xS.includes(l);
    },
    parse: (r) => {
      const e = r.split(".");
      return {
        resolution: parseFloat(Ig.RETINA_PREFIX.exec(r)?.[1] ?? "1"),
        format: e[e.length - 2],
        src: r,
      };
    },
  },
  loader: {
    name: "spritesheetLoader",
    extension: {
      type: ft.LoadParser,
      priority: of.Normal,
      name: "spritesheetLoader",
    },
    async testParse(r, e) {
      return Hr.extname(e.src).toLowerCase() === ".json" && !!r.frames;
    },
    async parse(r, e, i) {
      const {
        texture: o,
        imageFilename: l,
        textureOptions: c,
        cachePrefix: f,
      } = e?.data ?? {};
      let d = Hr.dirname(e.src);
      d && d.lastIndexOf("/") !== d.length - 1 && (d += "/");
      let m;
      if (o instanceof tt) m = o;
      else {
        const v = Pm(d + (l ?? r.meta.image), e.src);
        m = (await i.load([{ src: v, data: c }]))[v];
      }
      const p = new Am({ texture: m.source, data: r, cachePrefix: f });
      await p.parse();
      const g = r?.meta?.related_multi_packs;
      if (Array.isArray(g)) {
        const v = [];
        for (const w of g) {
          if (typeof w != "string") continue;
          let E = d + w;
          e.data?.ignoreMultiPack ||
            ((E = Pm(E, e.src)),
            v.push(
              i.load({
                src: E,
                data: { textureOptions: c, ignoreMultiPack: !0 },
              })
            ));
        }
        const x = await Promise.all(v);
        (p.linkedSheets = x),
          x.forEach((w) => {
            w.linkedSheets = [p].concat(p.linkedSheets.filter((E) => E !== w));
          });
      }
      return p;
    },
    async unload(r, e, i) {
      await i.unload(r.textureSource._sourceOrigin), r.destroy(!1);
    },
  },
};
xn.add(SS);
xn.add(hx, dx);
let Ng;
function ES(r) {
  return (Ng = r), r;
}
function bs() {
  return Ng;
}
class Vc {
  static setParamValue(e, i) {
    if (e.setValueAtTime) {
      const o = bs().context;
      e.setValueAtTime(i, o.audioContext.currentTime);
    } else e.value = i;
    return i;
  }
}
class PS extends qr {
  constructor() {
    super(...arguments),
      (this.speed = 1),
      (this.muted = !1),
      (this.volume = 1),
      (this.paused = !1);
  }
  refresh() {
    this.emit("refresh");
  }
  refreshPaused() {
    this.emit("refreshPaused");
  }
  get filters() {
    return console.warn("HTML Audio does not support filters"), null;
  }
  set filters(e) {
    console.warn("HTML Audio does not support filters");
  }
  get audioContext() {
    return console.warn("HTML Audio does not support audioContext"), null;
  }
  toggleMute() {
    return (this.muted = !this.muted), this.refresh(), this.muted;
  }
  togglePause() {
    return (this.paused = !this.paused), this.refreshPaused(), this.paused;
  }
  destroy() {
    this.removeAllListeners();
  }
}
let AS = 0;
const Gc = class extends qr {
  constructor(r) {
    super(), (this.id = AS++), this.init(r);
  }
  set(r, e) {
    if (this[r] === void 0)
      throw new Error(`Property with name ${r} does not exist.`);
    switch (r) {
      case "speed":
        this.speed = e;
        break;
      case "volume":
        this.volume = e;
        break;
      case "paused":
        this.paused = e;
        break;
      case "loop":
        this.loop = e;
        break;
      case "muted":
        this.muted = e;
        break;
    }
    return this;
  }
  get progress() {
    const { currentTime: r } = this._source;
    return r / this._duration;
  }
  get paused() {
    return this._paused;
  }
  set paused(r) {
    (this._paused = r), this.refreshPaused();
  }
  _onPlay() {
    this._playing = !0;
  }
  _onPause() {
    this._playing = !1;
  }
  init(r) {
    (this._playing = !1), (this._duration = r.source.duration);
    const e = (this._source = r.source.cloneNode(!1));
    (e.src = r.parent.url),
      (e.onplay = this._onPlay.bind(this)),
      (e.onpause = this._onPause.bind(this)),
      r.context.on("refresh", this.refresh, this),
      r.context.on("refreshPaused", this.refreshPaused, this),
      (this._media = r);
  }
  _internalStop() {
    this._source &&
      this._playing &&
      ((this._source.onended = null), this._source.pause());
  }
  stop() {
    this._internalStop(), this._source && this.emit("stop");
  }
  get speed() {
    return this._speed;
  }
  set speed(r) {
    (this._speed = r), this.refresh();
  }
  get volume() {
    return this._volume;
  }
  set volume(r) {
    (this._volume = r), this.refresh();
  }
  get loop() {
    return this._loop;
  }
  set loop(r) {
    (this._loop = r), this.refresh();
  }
  get muted() {
    return this._muted;
  }
  set muted(r) {
    (this._muted = r), this.refresh();
  }
  get filters() {
    return console.warn("HTML Audio does not support filters"), null;
  }
  set filters(r) {
    console.warn("HTML Audio does not support filters");
  }
  refresh() {
    const r = this._media.context,
      e = this._media.parent;
    this._source.loop = this._loop || e.loop;
    const i = r.volume * (r.muted ? 0 : 1),
      o = e.volume * (e.muted ? 0 : 1),
      l = this._volume * (this._muted ? 0 : 1);
    (this._source.volume = l * i * o),
      (this._source.playbackRate = this._speed * r.speed * e.speed);
  }
  refreshPaused() {
    const r = this._media.context,
      e = this._media.parent,
      i = this._paused || e.paused || r.paused;
    i !== this._pausedReal &&
      ((this._pausedReal = i),
      i
        ? (this._internalStop(), this.emit("paused"))
        : (this.emit("resumed"),
          this.play({
            start: this._source.currentTime,
            end: this._end,
            volume: this._volume,
            speed: this._speed,
            loop: this._loop,
          })),
      this.emit("pause", i));
  }
  play(r) {
    const { start: e, end: i, speed: o, loop: l, volume: c, muted: f } = r;
    i && console.assert(i > e, "End time is before start time"),
      (this._speed = o),
      (this._volume = c),
      (this._loop = !!l),
      (this._muted = f),
      this.refresh(),
      this.loop &&
        i !== null &&
        (console.warn('Looping not support when specifying an "end" time'),
        (this.loop = !1)),
      (this._start = e),
      (this._end = i || this._duration),
      (this._start = Math.max(0, this._start - Gc.PADDING)),
      (this._end = Math.min(this._end + Gc.PADDING, this._duration)),
      (this._source.onloadedmetadata = () => {
        this._source &&
          ((this._source.currentTime = e),
          (this._source.onloadedmetadata = null),
          this.emit("progress", e / this._duration, this._duration),
          jr.shared.add(this._onUpdate, this));
      }),
      (this._source.onended = this._onComplete.bind(this)),
      this._source.play(),
      this.emit("start");
  }
  _onUpdate() {
    this.emit("progress", this.progress, this._duration),
      this._source.currentTime >= this._end &&
        !this._source.loop &&
        this._onComplete();
  }
  _onComplete() {
    jr.shared.remove(this._onUpdate, this),
      this._internalStop(),
      this.emit("progress", 1, this._duration),
      this.emit("end", this);
  }
  destroy() {
    jr.shared.remove(this._onUpdate, this), this.removeAllListeners();
    const r = this._source;
    r &&
      ((r.onended = null),
      (r.onplay = null),
      (r.onpause = null),
      this._internalStop()),
      (this._source = null),
      (this._speed = 1),
      (this._volume = 1),
      (this._loop = !1),
      (this._end = null),
      (this._start = 0),
      (this._duration = 0),
      (this._playing = !1),
      (this._pausedReal = !1),
      (this._paused = !1),
      (this._muted = !1),
      this._media &&
        (this._media.context.off("refresh", this.refresh, this),
        this._media.context.off("refreshPaused", this.refreshPaused, this),
        (this._media = null));
  }
  toString() {
    return `[HTMLAudioInstance id=${this.id}]`;
  }
};
let Dg = Gc;
Dg.PADDING = 0.1;
class CS extends qr {
  init(e) {
    (this.parent = e),
      (this._source = e.options.source || new Audio()),
      e.url && (this._source.src = e.url);
  }
  create() {
    return new Dg(this);
  }
  get isPlayable() {
    return !!this._source && this._source.readyState === 4;
  }
  get duration() {
    return this._source.duration;
  }
  get context() {
    return this.parent.context;
  }
  get filters() {
    return null;
  }
  set filters(e) {
    console.warn("HTML Audio does not support filters");
  }
  destroy() {
    this.removeAllListeners(),
      (this.parent = null),
      this._source &&
        ((this._source.src = ""), this._source.load(), (this._source = null));
  }
  get source() {
    return this._source;
  }
  load(e) {
    const i = this._source,
      o = this.parent;
    if (i.readyState === 4) {
      o.isLoaded = !0;
      const m = o.autoPlayStart();
      e &&
        setTimeout(() => {
          e(null, o, m);
        }, 0);
      return;
    }
    if (!o.url) {
      e(new Error("sound.url or sound.source must be set"));
      return;
    }
    i.src = o.url;
    const l = () => {
        d(), (o.isLoaded = !0);
        const m = o.autoPlayStart();
        e && e(null, o, m);
      },
      c = () => {
        d(), e && e(new Error("Sound loading has been aborted"));
      },
      f = () => {
        d();
        const m = `Failed to load audio element (code: ${i.error.code})`;
        e ? e(new Error(m)) : console.error(m);
      },
      d = () => {
        i.removeEventListener("canplaythrough", l),
          i.removeEventListener("load", l),
          i.removeEventListener("abort", c),
          i.removeEventListener("error", f);
      };
    i.addEventListener("canplaythrough", l, !1),
      i.addEventListener("load", l, !1),
      i.addEventListener("abort", c, !1),
      i.addEventListener("error", f, !1),
      i.load();
  }
}
class kS {
  constructor(e, i) {
    (this.parent = e),
      Object.assign(this, i),
      (this.duration = this.end - this.start),
      console.assert(this.duration > 0, "End time must be after start time");
  }
  play(e) {
    return this.parent.play({
      complete: e,
      speed: this.speed || this.parent.speed,
      end: this.end,
      start: this.start,
      loop: this.loop,
    });
  }
  destroy() {
    this.parent = null;
  }
}
const ma = [
    "ogg",
    "oga",
    "opus",
    "m4a",
    "mp3",
    "mpeg",
    "wav",
    "aiff",
    "wma",
    "mid",
    "caf",
  ],
  RS = ["audio/mpeg", "audio/ogg"],
  ya = {};
function bS(r) {
  const e = {
      m4a: "audio/mp4",
      oga: "audio/ogg",
      opus: 'audio/ogg; codecs="opus"',
      caf: 'audio/x-caf; codecs="opus"',
    },
    i = document.createElement("audio"),
    o = {},
    l = /^no$/;
  ma.forEach((c) => {
    const f = i.canPlayType(`audio/${c}`).replace(l, ""),
      d = e[c] ? i.canPlayType(e[c]).replace(l, "") : "";
    o[c] = !!f || !!d;
  }),
    Object.assign(ya, o);
}
bS();
let TS = 0;
class OS extends qr {
  constructor(e) {
    super(),
      (this.id = TS++),
      (this._media = null),
      (this._paused = !1),
      (this._muted = !1),
      (this._elapsed = 0),
      this.init(e);
  }
  set(e, i) {
    if (this[e] === void 0)
      throw new Error(`Property with name ${e} does not exist.`);
    switch (e) {
      case "speed":
        this.speed = i;
        break;
      case "volume":
        this.volume = i;
        break;
      case "muted":
        this.muted = i;
        break;
      case "loop":
        this.loop = i;
        break;
      case "paused":
        this.paused = i;
        break;
    }
    return this;
  }
  stop() {
    this._source && (this._internalStop(), this.emit("stop"));
  }
  get speed() {
    return this._speed;
  }
  set speed(e) {
    (this._speed = e), this.refresh(), this._update(!0);
  }
  get volume() {
    return this._volume;
  }
  set volume(e) {
    (this._volume = e), this.refresh();
  }
  get muted() {
    return this._muted;
  }
  set muted(e) {
    (this._muted = e), this.refresh();
  }
  get loop() {
    return this._loop;
  }
  set loop(e) {
    (this._loop = e), this.refresh();
  }
  get filters() {
    return this._filters;
  }
  set filters(e) {
    this._filters &&
      (this._filters?.filter((i) => i).forEach((i) => i.disconnect()),
      (this._filters = null),
      this._source.connect(this._gain)),
      (this._filters = e?.length ? e.slice(0) : null),
      this.refresh();
  }
  refresh() {
    if (!this._source) return;
    const e = this._media.context,
      i = this._media.parent;
    this._source.loop = this._loop || i.loop;
    const o = e.volume * (e.muted ? 0 : 1),
      l = i.volume * (i.muted ? 0 : 1),
      c = this._volume * (this._muted ? 0 : 1);
    Vc.setParamValue(this._gain.gain, c * l * o),
      Vc.setParamValue(
        this._source.playbackRate,
        this._speed * i.speed * e.speed
      ),
      this.applyFilters();
  }
  applyFilters() {
    if (this._filters?.length) {
      this._source.disconnect();
      let e = this._source;
      this._filters.forEach((i) => {
        e.connect(i.destination), (e = i);
      }),
        e.connect(this._gain);
    }
  }
  refreshPaused() {
    const e = this._media.context,
      i = this._media.parent,
      o = this._paused || i.paused || e.paused;
    o !== this._pausedReal &&
      ((this._pausedReal = o),
      o
        ? (this._internalStop(), this.emit("paused"))
        : (this.emit("resumed"),
          this.play({
            start: this._elapsed % this._duration,
            end: this._end,
            speed: this._speed,
            loop: this._loop,
            volume: this._volume,
          })),
      this.emit("pause", o));
  }
  play(e) {
    const {
      start: i,
      end: o,
      speed: l,
      loop: c,
      volume: f,
      muted: d,
      filters: m,
    } = e;
    o && console.assert(o > i, "End time is before start time"),
      (this._paused = !1);
    const { source: p, gain: g } = this._media.nodes.cloneBufferSource();
    (this._source = p),
      (this._gain = g),
      (this._speed = l),
      (this._volume = f),
      (this._loop = !!c),
      (this._muted = d),
      (this._filters = m),
      this.refresh();
    const v = this._source.buffer.duration;
    (this._duration = v),
      (this._end = o),
      (this._lastUpdate = this._now()),
      (this._elapsed = i),
      (this._source.onended = this._onComplete.bind(this)),
      this._loop
        ? ((this._source.loopEnd = o),
          (this._source.loopStart = i),
          this._source.start(0, i))
        : o
        ? this._source.start(0, i, o - i)
        : this._source.start(0, i),
      this.emit("start"),
      this._update(!0),
      this.enableTicker(!0);
  }
  enableTicker(e) {
    jr.shared.remove(this._updateListener, this),
      e && jr.shared.add(this._updateListener, this);
  }
  get progress() {
    return this._progress;
  }
  get paused() {
    return this._paused;
  }
  set paused(e) {
    (this._paused = e), this.refreshPaused();
  }
  destroy() {
    this.removeAllListeners(),
      this._internalStop(),
      this._gain && (this._gain.disconnect(), (this._gain = null)),
      this._media &&
        (this._media.context.events.off("refresh", this.refresh, this),
        this._media.context.events.off(
          "refreshPaused",
          this.refreshPaused,
          this
        ),
        (this._media = null)),
      this._filters?.forEach((e) => e.disconnect()),
      (this._filters = null),
      (this._end = null),
      (this._speed = 1),
      (this._volume = 1),
      (this._loop = !1),
      (this._elapsed = 0),
      (this._duration = 0),
      (this._paused = !1),
      (this._muted = !1),
      (this._pausedReal = !1);
  }
  toString() {
    return `[WebAudioInstance id=${this.id}]`;
  }
  _now() {
    return this._media.context.audioContext.currentTime;
  }
  _updateListener() {
    this._update();
  }
  _update(e = !1) {
    if (this._source) {
      const i = this._now(),
        o = i - this._lastUpdate;
      if (o > 0 || e) {
        const l = this._source.playbackRate.value;
        (this._elapsed += o * l), (this._lastUpdate = i);
        const c = this._duration;
        let f;
        if (this._source.loopStart) {
          const d = this._source.loopEnd - this._source.loopStart;
          f = (this._source.loopStart + (this._elapsed % d)) / c;
        } else f = (this._elapsed % c) / c;
        (this._progress = f), this.emit("progress", this._progress, c);
      }
    }
  }
  init(e) {
    (this._media = e),
      e.context.events.on("refresh", this.refresh, this),
      e.context.events.on("refreshPaused", this.refreshPaused, this);
  }
  _internalStop() {
    if (this._source) {
      this.enableTicker(!1),
        (this._source.onended = null),
        this._source.stop(0),
        this._source.disconnect();
      try {
        this._source.buffer = null;
      } catch (e) {
        console.warn("Failed to set AudioBufferSourceNode.buffer to null:", e);
      }
      this._source = null;
    }
  }
  _onComplete() {
    if (this._source) {
      this.enableTicker(!1),
        (this._source.onended = null),
        this._source.disconnect();
      try {
        this._source.buffer = null;
      } catch (e) {
        console.warn("Failed to set AudioBufferSourceNode.buffer to null:", e);
      }
    }
    (this._source = null),
      (this._progress = 1),
      this.emit("progress", 1, this._duration),
      this.emit("end", this);
  }
}
class Bg {
  constructor(e, i) {
    (this._output = i), (this._input = e);
  }
  get destination() {
    return this._input;
  }
  get filters() {
    return this._filters;
  }
  set filters(e) {
    if (
      (this._filters &&
        (this._filters.forEach((i) => {
          i && i.disconnect();
        }),
        (this._filters = null),
        this._input.connect(this._output)),
      e && e.length)
    ) {
      (this._filters = e.slice(0)), this._input.disconnect();
      let i = null;
      e.forEach((o) => {
        i === null
          ? this._input.connect(o.destination)
          : i.connect(o.destination),
          (i = o);
      }),
        i.connect(this._output);
    }
  }
  destroy() {
    (this.filters = null), (this._input = null), (this._output = null);
  }
}
const Ug = class extends Bg {
  constructor(r) {
    const e = r.audioContext,
      i = e.createBufferSource(),
      o = e.createGain(),
      l = e.createAnalyser();
    i.connect(l),
      l.connect(o),
      o.connect(r.destination),
      super(l, o),
      (this.context = r),
      (this.bufferSource = i),
      (this.gain = o),
      (this.analyser = l);
  }
  get script() {
    return (
      this._script ||
        ((this._script = this.context.audioContext.createScriptProcessor(
          Ug.BUFFER_SIZE
        )),
        this._script.connect(this.context.destination)),
      this._script
    );
  }
  destroy() {
    super.destroy(),
      this.bufferSource.disconnect(),
      this._script && this._script.disconnect(),
      this.gain.disconnect(),
      this.analyser.disconnect(),
      (this.bufferSource = null),
      (this._script = null),
      (this.gain = null),
      (this.analyser = null),
      (this.context = null);
  }
  cloneBufferSource() {
    const r = this.bufferSource,
      e = this.context.audioContext.createBufferSource();
    (e.buffer = r.buffer),
      Vc.setParamValue(e.playbackRate, r.playbackRate.value),
      (e.loop = r.loop);
    const i = this.context.audioContext.createGain();
    return e.connect(i), i.connect(this.destination), { source: e, gain: i };
  }
  get bufferSize() {
    return this.script.bufferSize;
  }
};
let jg = Ug;
jg.BUFFER_SIZE = 0;
class MS {
  init(e) {
    (this.parent = e),
      (this._nodes = new jg(this.context)),
      (this._source = this._nodes.bufferSource),
      (this.source = e.options.source);
  }
  destroy() {
    (this.parent = null), this._nodes.destroy(), (this._nodes = null);
    try {
      this._source.buffer = null;
    } catch (e) {
      console.warn("Failed to set AudioBufferSourceNode.buffer to null:", e);
    }
    (this._source = null), (this.source = null);
  }
  create() {
    return new OS(this);
  }
  get context() {
    return this.parent.context;
  }
  get isPlayable() {
    return !!this._source && !!this._source.buffer;
  }
  get filters() {
    return this._nodes.filters;
  }
  set filters(e) {
    this._nodes.filters = e;
  }
  get duration() {
    return (
      console.assert(this.isPlayable, "Sound not yet playable, no duration"),
      this._source.buffer.duration
    );
  }
  get buffer() {
    return this._source.buffer;
  }
  set buffer(e) {
    this._source.buffer = e;
  }
  get nodes() {
    return this._nodes;
  }
  load(e) {
    this.source
      ? this._decode(this.source, e)
      : this.parent.url
      ? this._loadUrl(e)
      : e
      ? e(new Error("sound.url or sound.source must be set"))
      : console.error("sound.url or sound.source must be set");
  }
  async _loadUrl(e) {
    const i = this.parent.url,
      o = await sf.get().fetch(i);
    this._decode(await o.arrayBuffer(), e);
  }
  _decode(e, i) {
    const o = (l, c) => {
      if (l) i && i(l);
      else {
        (this.parent.isLoaded = !0), (this.buffer = c);
        const f = this.parent.autoPlayStart();
        i && i(null, this.parent, f);
      }
    };
    e instanceof AudioBuffer ? o(null, e) : this.parent.context.decode(e, o);
  }
}
const xi = class {
  static from(r) {
    let e = {};
    typeof r == "string"
      ? (e.url = r)
      : r instanceof ArrayBuffer ||
        r instanceof AudioBuffer ||
        r instanceof HTMLAudioElement
      ? (e.source = r)
      : Array.isArray(r)
      ? (e.url = r)
      : (e = r),
      (e = {
        autoPlay: !1,
        singleInstance: !1,
        url: null,
        source: null,
        preload: !1,
        volume: 1,
        speed: 1,
        complete: null,
        loaded: null,
        loop: !1,
        ...e,
      }),
      Object.freeze(e);
    const i = bs().useLegacy ? new CS() : new MS();
    return new xi(i, e);
  }
  constructor(r, e) {
    (this.media = r),
      (this.options = e),
      (this._instances = []),
      (this._sprites = {}),
      this.media.init(this);
    const i = e.complete;
    (this._autoPlayOptions = i ? { complete: i } : null),
      (this.isLoaded = !1),
      (this._preloadQueue = null),
      (this.isPlaying = !1),
      (this.autoPlay = e.autoPlay),
      (this.singleInstance = e.singleInstance),
      (this.preload = e.preload || this.autoPlay),
      (this.url = Array.isArray(e.url) ? this.preferUrl(e.url) : e.url),
      (this.speed = e.speed),
      (this.volume = e.volume),
      (this.loop = e.loop),
      e.sprites && this.addSprites(e.sprites),
      this.preload && this._preload(e.loaded);
  }
  preferUrl(r) {
    const [e] = r
      .map((i) => ({ url: i, ext: Hr.extname(i).slice(1) }))
      .filter(({ ext: i }) => ya[i])
      .sort((i, o) => ma.indexOf(i.ext) - ma.indexOf(o.ext));
    if (!e) throw new Error("No supported file type found");
    return e.url;
  }
  get context() {
    return bs().context;
  }
  pause() {
    return (this.isPlaying = !1), (this.paused = !0), this;
  }
  resume() {
    return (
      (this.isPlaying = this._instances.length > 0), (this.paused = !1), this
    );
  }
  get paused() {
    return this._paused;
  }
  set paused(r) {
    (this._paused = r), this.refreshPaused();
  }
  get speed() {
    return this._speed;
  }
  set speed(r) {
    (this._speed = r), this.refresh();
  }
  get filters() {
    return this.media.filters;
  }
  set filters(r) {
    this.media.filters = r;
  }
  addSprites(r, e) {
    if (typeof r == "object") {
      const o = {};
      for (const l in r) o[l] = this.addSprites(l, r[l]);
      return o;
    }
    console.assert(!this._sprites[r], `Alias ${r} is already taken`);
    const i = new kS(this, e);
    return (this._sprites[r] = i), i;
  }
  destroy() {
    this._removeInstances(),
      this.removeSprites(),
      this.media.destroy(),
      (this.media = null),
      (this._sprites = null),
      (this._instances = null);
  }
  removeSprites(r) {
    if (r) {
      const e = this._sprites[r];
      e !== void 0 && (e.destroy(), delete this._sprites[r]);
    } else for (const e in this._sprites) this.removeSprites(e);
    return this;
  }
  get isPlayable() {
    return this.isLoaded && this.media && this.media.isPlayable;
  }
  stop() {
    if (!this.isPlayable)
      return (this.autoPlay = !1), (this._autoPlayOptions = null), this;
    this.isPlaying = !1;
    for (let r = this._instances.length - 1; r >= 0; r--)
      this._instances[r].stop();
    return this;
  }
  play(r, e) {
    let i;
    if (
      (typeof r == "string"
        ? (i = { sprite: r, loop: this.loop, complete: e })
        : typeof r == "function"
        ? ((i = {}), (i.complete = r))
        : (i = r),
      (i = {
        complete: null,
        loaded: null,
        sprite: null,
        end: null,
        start: 0,
        volume: 1,
        speed: 1,
        muted: !1,
        loop: !1,
        ...(i || {}),
      }),
      i.sprite)
    ) {
      const l = i.sprite;
      console.assert(!!this._sprites[l], `Alias ${l} is not available`);
      const c = this._sprites[l];
      (i.start = c.start + (i.start || 0)),
        (i.end = c.end),
        (i.speed = c.speed || 1),
        (i.loop = c.loop || i.loop),
        delete i.sprite;
    }
    if ((i.offset && (i.start = i.offset), !this.isLoaded))
      return this._preloadQueue
        ? new Promise((l) => {
            this._preloadQueue.push(() => {
              l(this.play(i));
            });
          })
        : ((this._preloadQueue = []),
          (this.autoPlay = !0),
          (this._autoPlayOptions = i),
          new Promise((l, c) => {
            this._preload((f, d, m) => {
              this._preloadQueue.forEach((p) => p()),
                (this._preloadQueue = null),
                f ? c(f) : (i.loaded && i.loaded(f, d, m), l(m));
            });
          }));
    (this.singleInstance || i.singleInstance) && this._removeInstances();
    const o = this._createInstance();
    return (
      this._instances.push(o),
      (this.isPlaying = !0),
      o.once("end", () => {
        i.complete && i.complete(this), this._onComplete(o);
      }),
      o.once("stop", () => {
        this._onComplete(o);
      }),
      o.play(i),
      o
    );
  }
  refresh() {
    const r = this._instances.length;
    for (let e = 0; e < r; e++) this._instances[e].refresh();
  }
  refreshPaused() {
    const r = this._instances.length;
    for (let e = 0; e < r; e++) this._instances[e].refreshPaused();
  }
  get volume() {
    return this._volume;
  }
  set volume(r) {
    (this._volume = r), this.refresh();
  }
  get muted() {
    return this._muted;
  }
  set muted(r) {
    (this._muted = r), this.refresh();
  }
  get loop() {
    return this._loop;
  }
  set loop(r) {
    (this._loop = r), this.refresh();
  }
  _preload(r) {
    this.media.load(r);
  }
  get instances() {
    return this._instances;
  }
  get sprites() {
    return this._sprites;
  }
  get duration() {
    return this.media.duration;
  }
  autoPlayStart() {
    let r;
    return this.autoPlay && (r = this.play(this._autoPlayOptions)), r;
  }
  _removeInstances() {
    for (let r = this._instances.length - 1; r >= 0; r--)
      this._poolInstance(this._instances[r]);
    this._instances.length = 0;
  }
  _onComplete(r) {
    if (this._instances) {
      const e = this._instances.indexOf(r);
      e > -1 && this._instances.splice(e, 1),
        (this.isPlaying = this._instances.length > 0);
    }
    this._poolInstance(r);
  }
  _createInstance() {
    if (xi._pool.length > 0) {
      const r = xi._pool.pop();
      return r.init(this.media), r;
    }
    return this.media.create();
  }
  _poolInstance(r) {
    r.destroy(), xi._pool.indexOf(r) < 0 && xi._pool.push(r);
  }
};
let ga = xi;
ga._pool = [];
class Ts extends Bg {
  constructor() {
    const e = window,
      i = new Ts.AudioContext(),
      o = i.createDynamicsCompressor(),
      l = i.createAnalyser();
    l.connect(o),
      o.connect(i.destination),
      super(l, o),
      (this.autoPause = !0),
      (this._ctx = i),
      (this._offlineCtx = new Ts.OfflineAudioContext(
        1,
        2,
        e.OfflineAudioContext
          ? Math.max(8e3, Math.min(96e3, i.sampleRate))
          : 44100
      )),
      (this.compressor = o),
      (this.analyser = l),
      (this.events = new qr()),
      (this.volume = 1),
      (this.speed = 1),
      (this.muted = !1),
      (this.paused = !1),
      (this._locked =
        i.state === "suspended" &&
        ("ontouchstart" in globalThis || "onclick" in globalThis)),
      this._locked &&
        (this._unlock(),
        (this._unlock = this._unlock.bind(this)),
        document.addEventListener("mousedown", this._unlock, !0),
        document.addEventListener("touchstart", this._unlock, !0),
        document.addEventListener("touchend", this._unlock, !0)),
      (this.onFocus = this.onFocus.bind(this)),
      (this.onBlur = this.onBlur.bind(this)),
      globalThis.addEventListener("focus", this.onFocus),
      globalThis.addEventListener("blur", this.onBlur);
  }
  onFocus() {
    if (!this.autoPause) return;
    const e = this._ctx.state;
    (e === "suspended" || e === "interrupted" || !this._locked) &&
      ((this.paused = this._pausedOnBlur), this.refreshPaused());
  }
  onBlur() {
    this.autoPause &&
      (this._locked ||
        ((this._pausedOnBlur = this._paused),
        (this.paused = !0),
        this.refreshPaused()));
  }
  _unlock() {
    this._locked &&
      (this.playEmptySound(),
      this._ctx.state === "running" &&
        (document.removeEventListener("mousedown", this._unlock, !0),
        document.removeEventListener("touchend", this._unlock, !0),
        document.removeEventListener("touchstart", this._unlock, !0),
        (this._locked = !1)));
  }
  playEmptySound() {
    const e = this._ctx.createBufferSource();
    (e.buffer = this._ctx.createBuffer(1, 1, 22050)),
      e.connect(this._ctx.destination),
      e.start(0, 0, 0),
      e.context.state === "suspended" && e.context.resume();
  }
  static get AudioContext() {
    const e = window;
    return e.AudioContext || e.webkitAudioContext || null;
  }
  static get OfflineAudioContext() {
    const e = window;
    return e.OfflineAudioContext || e.webkitOfflineAudioContext || null;
  }
  destroy() {
    super.destroy();
    const e = this._ctx;
    typeof e.close < "u" && e.close(),
      globalThis.removeEventListener("focus", this.onFocus),
      globalThis.removeEventListener("blur", this.onBlur),
      this.events.removeAllListeners(),
      this.analyser.disconnect(),
      this.compressor.disconnect(),
      (this.analyser = null),
      (this.compressor = null),
      (this.events = null),
      (this._offlineCtx = null),
      (this._ctx = null);
  }
  get audioContext() {
    return this._ctx;
  }
  get offlineContext() {
    return this._offlineCtx;
  }
  set paused(e) {
    e && this._ctx.state === "running"
      ? this._ctx.suspend()
      : !e && this._ctx.state === "suspended" && this._ctx.resume(),
      (this._paused = e);
  }
  get paused() {
    return this._paused;
  }
  refresh() {
    this.events.emit("refresh");
  }
  refreshPaused() {
    this.events.emit("refreshPaused");
  }
  toggleMute() {
    return (this.muted = !this.muted), this.refresh(), this.muted;
  }
  togglePause() {
    return (this.paused = !this.paused), this.refreshPaused(), this._paused;
  }
  decode(e, i) {
    const o = (c) => {
        i(new Error(c?.message || "Unable to decode file"));
      },
      l = this._offlineCtx.decodeAudioData(
        e,
        (c) => {
          i(null, c);
        },
        o
      );
    l && l.catch(o);
  }
}
class IS {
  constructor() {
    this.init();
  }
  init() {
    return (
      this.supported && (this._webAudioContext = new Ts()),
      (this._htmlAudioContext = new PS()),
      (this._sounds = {}),
      (this.useLegacy = !this.supported),
      this
    );
  }
  get context() {
    return this._context;
  }
  get filtersAll() {
    return this.useLegacy ? [] : this._context.filters;
  }
  set filtersAll(e) {
    this.useLegacy || (this._context.filters = e);
  }
  get supported() {
    return Ts.AudioContext !== null;
  }
  add(e, i) {
    if (typeof e == "object") {
      const c = {};
      for (const f in e) {
        const d = this._getOptions(e[f], i);
        c[f] = this.add(f, d);
      }
      return c;
    }
    if (
      (console.assert(
        !this._sounds[e],
        `Sound with alias ${e} already exists.`
      ),
      i instanceof ga)
    )
      return (this._sounds[e] = i), i;
    const o = this._getOptions(i),
      l = ga.from(o);
    return (this._sounds[e] = l), l;
  }
  _getOptions(e, i) {
    let o;
    return (
      typeof e == "string"
        ? (o = { url: e })
        : Array.isArray(e)
        ? (o = { url: e })
        : e instanceof ArrayBuffer ||
          e instanceof AudioBuffer ||
          e instanceof HTMLAudioElement
        ? (o = { source: e })
        : (o = e),
      (o = { ...o, ...(i || {}) }),
      o
    );
  }
  get useLegacy() {
    return this._useLegacy;
  }
  set useLegacy(e) {
    (this._useLegacy = e),
      (this._context =
        !e && this.supported ? this._webAudioContext : this._htmlAudioContext);
  }
  get disableAutoPause() {
    return !this._webAudioContext.autoPause;
  }
  set disableAutoPause(e) {
    this._webAudioContext.autoPause = !e;
  }
  remove(e) {
    return (
      this.exists(e, !0),
      this._sounds[e].destroy(),
      delete this._sounds[e],
      this
    );
  }
  get volumeAll() {
    return this._context.volume;
  }
  set volumeAll(e) {
    (this._context.volume = e), this._context.refresh();
  }
  get speedAll() {
    return this._context.speed;
  }
  set speedAll(e) {
    (this._context.speed = e), this._context.refresh();
  }
  togglePauseAll() {
    return this._context.togglePause();
  }
  pauseAll() {
    return (this._context.paused = !0), this._context.refreshPaused(), this;
  }
  resumeAll() {
    return (this._context.paused = !1), this._context.refreshPaused(), this;
  }
  toggleMuteAll() {
    return this._context.toggleMute();
  }
  muteAll() {
    return (this._context.muted = !0), this._context.refresh(), this;
  }
  unmuteAll() {
    return (this._context.muted = !1), this._context.refresh(), this;
  }
  removeAll() {
    for (const e in this._sounds)
      this._sounds[e].destroy(), delete this._sounds[e];
    return this;
  }
  stopAll() {
    for (const e in this._sounds) this._sounds[e].stop();
    return this;
  }
  exists(e, i = !1) {
    const o = !!this._sounds[e];
    return i && console.assert(o, `No sound matching alias '${e}'.`), o;
  }
  isPlaying() {
    for (const e in this._sounds) if (this._sounds[e].isPlaying) return !0;
    return !1;
  }
  find(e) {
    return this.exists(e, !0), this._sounds[e];
  }
  play(e, i) {
    return this.find(e).play(i);
  }
  stop(e) {
    return this.find(e).stop();
  }
  pause(e) {
    return this.find(e).pause();
  }
  resume(e) {
    return this.find(e).resume();
  }
  volume(e, i) {
    const o = this.find(e);
    return i !== void 0 && (o.volume = i), o.volume;
  }
  speed(e, i) {
    const o = this.find(e);
    return i !== void 0 && (o.speed = i), o.speed;
  }
  duration(e) {
    return this.find(e).duration;
  }
  close() {
    return (
      this.removeAll(),
      (this._sounds = null),
      this._webAudioContext &&
        (this._webAudioContext.destroy(), (this._webAudioContext = null)),
      this._htmlAudioContext &&
        (this._htmlAudioContext.destroy(), (this._htmlAudioContext = null)),
      (this._context = null),
      this
    );
  }
}
const Cm = (r) => {
    const e = r.src;
    let i = r?.alias?.[0];
    return (!i || r.src === i) && (i = Hr.basename(e, Hr.extname(e))), i;
  },
  LS = {
    extension: ft.Asset,
    detection: {
      test: async () => !0,
      add: async (r) => [...r, ...ma.filter((e) => ya[e])],
      remove: async (r) => r.filter((e) => r.includes(e)),
    },
    loader: {
      name: "sound",
      extension: { type: [ft.LoadParser], priority: of.High },
      test(r) {
        const e = Hr.extname(r).slice(1);
        return !!ya[e] || RS.some((i) => r.startsWith(`data:${i}`));
      },
      async load(r, e) {
        const i = await new Promise((o, l) =>
          ga.from({
            ...e.data,
            url: r,
            preload: !0,
            loaded(c, f) {
              c ? l(c) : o(f), e.data?.loaded?.(c, f);
            },
          })
        );
        return bs().add(Cm(e), i), i;
      },
      async unload(r, e) {
        bs().remove(Cm(e));
      },
    },
  };
xn.add(LS);
ES(new IS());
var ta = {},
  wc = { exports: {} },
  It = {},
  xc = { exports: {} },
  Sc = {};
/**
 * @license React
 * scheduler.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */ var km;
function FS() {
  return (
    km ||
      ((km = 1),
      (function (r) {
        function e(D, J) {
          var X = D.length;
          D.push(J);
          e: for (; 0 < X; ) {
            var R = (X - 1) >>> 1,
              B = D[R];
            if (0 < l(B, J)) (D[R] = J), (D[X] = B), (X = R);
            else break e;
          }
        }
        function i(D) {
          return D.length === 0 ? null : D[0];
        }
        function o(D) {
          if (D.length === 0) return null;
          var J = D[0],
            X = D.pop();
          if (X !== J) {
            D[0] = X;
            e: for (var R = 0, B = D.length, le = B >>> 1; R < le; ) {
              var he = 2 * (R + 1) - 1,
                W = D[he],
                re = he + 1,
                Y = D[re];
              if (0 > l(W, X))
                re < B && 0 > l(Y, W)
                  ? ((D[R] = Y), (D[re] = X), (R = re))
                  : ((D[R] = W), (D[he] = X), (R = he));
              else if (re < B && 0 > l(Y, X)) (D[R] = Y), (D[re] = X), (R = re);
              else break e;
            }
          }
          return J;
        }
        function l(D, J) {
          var X = D.sortIndex - J.sortIndex;
          return X !== 0 ? X : D.id - J.id;
        }
        if (
          typeof performance == "object" &&
          typeof performance.now == "function"
        ) {
          var c = performance;
          r.unstable_now = function () {
            return c.now();
          };
        } else {
          var f = Date,
            d = f.now();
          r.unstable_now = function () {
            return f.now() - d;
          };
        }
        var m = [],
          p = [],
          g = 1,
          v = null,
          x = 3,
          w = !1,
          E = !1,
          k = !1,
          _ = typeof setTimeout == "function" ? setTimeout : null,
          A = typeof clearTimeout == "function" ? clearTimeout : null,
          b = typeof setImmediate < "u" ? setImmediate : null;
        typeof navigator < "u" &&
          navigator.scheduling !== void 0 &&
          navigator.scheduling.isInputPending !== void 0 &&
          navigator.scheduling.isInputPending.bind(navigator.scheduling);
        function N(D) {
          for (var J = i(p); J !== null; ) {
            if (J.callback === null) o(p);
            else if (J.startTime <= D)
              o(p), (J.sortIndex = J.expirationTime), e(m, J);
            else break;
            J = i(p);
          }
        }
        function U(D) {
          if (((k = !1), N(D), !E))
            if (i(m) !== null) (E = !0), be(z);
            else {
              var J = i(p);
              J !== null && Se(U, J.startTime - D);
            }
        }
        function z(D, J) {
          (E = !1), k && ((k = !1), A(Q), (Q = -1)), (w = !0);
          var X = x;
          try {
            for (
              N(J), v = i(m);
              v !== null && (!(v.expirationTime > J) || (D && !xe()));

            ) {
              var R = v.callback;
              if (typeof R == "function") {
                (v.callback = null), (x = v.priorityLevel);
                var B = R(v.expirationTime <= J);
                (J = r.unstable_now()),
                  typeof B == "function"
                    ? (v.callback = B)
                    : v === i(m) && o(m),
                  N(J);
              } else o(m);
              v = i(m);
            }
            if (v !== null) var le = !0;
            else {
              var he = i(p);
              he !== null && Se(U, he.startTime - J), (le = !1);
            }
            return le;
          } finally {
            (v = null), (x = X), (w = !1);
          }
        }
        var H = !1,
          G = null,
          Q = -1,
          me = 5,
          ae = -1;
        function xe() {
          return !(r.unstable_now() - ae < me);
        }
        function te() {
          if (G !== null) {
            var D = r.unstable_now();
            ae = D;
            var J = !0;
            try {
              J = G(!0, D);
            } finally {
              J ? _e() : ((H = !1), (G = null));
            }
          } else H = !1;
        }
        var _e;
        if (typeof b == "function")
          _e = function () {
            b(te);
          };
        else if (typeof MessageChannel < "u") {
          var Ae = new MessageChannel(),
            ke = Ae.port2;
          (Ae.port1.onmessage = te),
            (_e = function () {
              ke.postMessage(null);
            });
        } else
          _e = function () {
            _(te, 0);
          };
        function be(D) {
          (G = D), H || ((H = !0), _e());
        }
        function Se(D, J) {
          Q = _(function () {
            D(r.unstable_now());
          }, J);
        }
        (r.unstable_IdlePriority = 5),
          (r.unstable_ImmediatePriority = 1),
          (r.unstable_LowPriority = 4),
          (r.unstable_NormalPriority = 3),
          (r.unstable_Profiling = null),
          (r.unstable_UserBlockingPriority = 2),
          (r.unstable_cancelCallback = function (D) {
            D.callback = null;
          }),
          (r.unstable_continueExecution = function () {
            E || w || ((E = !0), be(z));
          }),
          (r.unstable_forceFrameRate = function (D) {
            0 > D || 125 < D
              ? console.error(
                  "forceFrameRate takes a positive int between 0 and 125, forcing frame rates higher than 125 fps is not supported"
                )
              : (me = 0 < D ? Math.floor(1e3 / D) : 5);
          }),
          (r.unstable_getCurrentPriorityLevel = function () {
            return x;
          }),
          (r.unstable_getFirstCallbackNode = function () {
            return i(m);
          }),
          (r.unstable_next = function (D) {
            switch (x) {
              case 1:
              case 2:
              case 3:
                var J = 3;
                break;
              default:
                J = x;
            }
            var X = x;
            x = J;
            try {
              return D();
            } finally {
              x = X;
            }
          }),
          (r.unstable_pauseExecution = function () {}),
          (r.unstable_requestPaint = function () {}),
          (r.unstable_runWithPriority = function (D, J) {
            switch (D) {
              case 1:
              case 2:
              case 3:
              case 4:
              case 5:
                break;
              default:
                D = 3;
            }
            var X = x;
            x = D;
            try {
              return J();
            } finally {
              x = X;
            }
          }),
          (r.unstable_scheduleCallback = function (D, J, X) {
            var R = r.unstable_now();
            switch (
              (typeof X == "object" && X !== null
                ? ((X = X.delay),
                  (X = typeof X == "number" && 0 < X ? R + X : R))
                : (X = R),
              D)
            ) {
              case 1:
                var B = -1;
                break;
              case 2:
                B = 250;
                break;
              case 5:
                B = 1073741823;
                break;
              case 4:
                B = 1e4;
                break;
              default:
                B = 5e3;
            }
            return (
              (B = X + B),
              (D = {
                id: g++,
                callback: J,
                priorityLevel: D,
                startTime: X,
                expirationTime: B,
                sortIndex: -1,
              }),
              X > R
                ? ((D.sortIndex = X),
                  e(p, D),
                  i(m) === null &&
                    D === i(p) &&
                    (k ? (A(Q), (Q = -1)) : (k = !0), Se(U, X - R)))
                : ((D.sortIndex = B), e(m, D), E || w || ((E = !0), be(z))),
              D
            );
          }),
          (r.unstable_shouldYield = xe),
          (r.unstable_wrapCallback = function (D) {
            var J = x;
            return function () {
              var X = x;
              x = J;
              try {
                return D.apply(this, arguments);
              } finally {
                x = X;
              }
            };
          });
      })(Sc)),
    Sc
  );
}
var Rm;
function NS() {
  return Rm || ((Rm = 1), (xc.exports = FS())), xc.exports;
}
/**
 * @license React
 * react-dom.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */ var bm;
function DS() {
  if (bm) return It;
  bm = 1;
  var r = Wc(),
    e = NS();
  function i(t) {
    for (
      var n = "https://reactjs.org/docs/error-decoder.html?invariant=" + t,
        s = 1;
      s < arguments.length;
      s++
    )
      n += "&args[]=" + encodeURIComponent(arguments[s]);
    return (
      "Minified React error #" +
      t +
      "; visit " +
      n +
      " for the full message or use the non-minified dev environment for full errors and additional helpful warnings."
    );
  }
  var o = new Set(),
    l = {};
  function c(t, n) {
    f(t, n), f(t + "Capture", n);
  }
  function f(t, n) {
    for (l[t] = n, t = 0; t < n.length; t++) o.add(n[t]);
  }
  var d = !(
      typeof window > "u" ||
      typeof window.document > "u" ||
      typeof window.document.createElement > "u"
    ),
    m = Object.prototype.hasOwnProperty,
    p =
      /^[:A-Z_a-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD][:A-Z_a-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\-.0-9\u00B7\u0300-\u036F\u203F-\u2040]*$/,
    g = {},
    v = {};
  function x(t) {
    return m.call(v, t)
      ? !0
      : m.call(g, t)
      ? !1
      : p.test(t)
      ? (v[t] = !0)
      : ((g[t] = !0), !1);
  }
  function w(t, n, s, a) {
    if (s !== null && s.type === 0) return !1;
    switch (typeof n) {
      case "function":
      case "symbol":
        return !0;
      case "boolean":
        return a
          ? !1
          : s !== null
          ? !s.acceptsBooleans
          : ((t = t.toLowerCase().slice(0, 5)), t !== "data-" && t !== "aria-");
      default:
        return !1;
    }
  }
  function E(t, n, s, a) {
    if (n === null || typeof n > "u" || w(t, n, s, a)) return !0;
    if (a) return !1;
    if (s !== null)
      switch (s.type) {
        case 3:
          return !n;
        case 4:
          return n === !1;
        case 5:
          return isNaN(n);
        case 6:
          return isNaN(n) || 1 > n;
      }
    return !1;
  }
  function k(t, n, s, a, u, h, y) {
    (this.acceptsBooleans = n === 2 || n === 3 || n === 4),
      (this.attributeName = a),
      (this.attributeNamespace = u),
      (this.mustUseProperty = s),
      (this.propertyName = t),
      (this.type = n),
      (this.sanitizeURL = h),
      (this.removeEmptyString = y);
  }
  var _ = {};
  "children dangerouslySetInnerHTML defaultValue defaultChecked innerHTML suppressContentEditableWarning suppressHydrationWarning style"
    .split(" ")
    .forEach(function (t) {
      _[t] = new k(t, 0, !1, t, null, !1, !1);
    }),
    [
      ["acceptCharset", "accept-charset"],
      ["className", "class"],
      ["htmlFor", "for"],
      ["httpEquiv", "http-equiv"],
    ].forEach(function (t) {
      var n = t[0];
      _[n] = new k(n, 1, !1, t[1], null, !1, !1);
    }),
    ["contentEditable", "draggable", "spellCheck", "value"].forEach(function (
      t
    ) {
      _[t] = new k(t, 2, !1, t.toLowerCase(), null, !1, !1);
    }),
    [
      "autoReverse",
      "externalResourcesRequired",
      "focusable",
      "preserveAlpha",
    ].forEach(function (t) {
      _[t] = new k(t, 2, !1, t, null, !1, !1);
    }),
    "allowFullScreen async autoFocus autoPlay controls default defer disabled disablePictureInPicture disableRemotePlayback formNoValidate hidden loop noModule noValidate open playsInline readOnly required reversed scoped seamless itemScope"
      .split(" ")
      .forEach(function (t) {
        _[t] = new k(t, 3, !1, t.toLowerCase(), null, !1, !1);
      }),
    ["checked", "multiple", "muted", "selected"].forEach(function (t) {
      _[t] = new k(t, 3, !0, t, null, !1, !1);
    }),
    ["capture", "download"].forEach(function (t) {
      _[t] = new k(t, 4, !1, t, null, !1, !1);
    }),
    ["cols", "rows", "size", "span"].forEach(function (t) {
      _[t] = new k(t, 6, !1, t, null, !1, !1);
    }),
    ["rowSpan", "start"].forEach(function (t) {
      _[t] = new k(t, 5, !1, t.toLowerCase(), null, !1, !1);
    });
  var A = /[\-:]([a-z])/g;
  function b(t) {
    return t[1].toUpperCase();
  }
  "accent-height alignment-baseline arabic-form baseline-shift cap-height clip-path clip-rule color-interpolation color-interpolation-filters color-profile color-rendering dominant-baseline enable-background fill-opacity fill-rule flood-color flood-opacity font-family font-size font-size-adjust font-stretch font-style font-variant font-weight glyph-name glyph-orientation-horizontal glyph-orientation-vertical horiz-adv-x horiz-origin-x image-rendering letter-spacing lighting-color marker-end marker-mid marker-start overline-position overline-thickness paint-order panose-1 pointer-events rendering-intent shape-rendering stop-color stop-opacity strikethrough-position strikethrough-thickness stroke-dasharray stroke-dashoffset stroke-linecap stroke-linejoin stroke-miterlimit stroke-opacity stroke-width text-anchor text-decoration text-rendering underline-position underline-thickness unicode-bidi unicode-range units-per-em v-alphabetic v-hanging v-ideographic v-mathematical vector-effect vert-adv-y vert-origin-x vert-origin-y word-spacing writing-mode xmlns:xlink x-height"
    .split(" ")
    .forEach(function (t) {
      var n = t.replace(A, b);
      _[n] = new k(n, 1, !1, t, null, !1, !1);
    }),
    "xlink:actuate xlink:arcrole xlink:role xlink:show xlink:title xlink:type"
      .split(" ")
      .forEach(function (t) {
        var n = t.replace(A, b);
        _[n] = new k(n, 1, !1, t, "http://www.w3.org/1999/xlink", !1, !1);
      }),
    ["xml:base", "xml:lang", "xml:space"].forEach(function (t) {
      var n = t.replace(A, b);
      _[n] = new k(n, 1, !1, t, "http://www.w3.org/XML/1998/namespace", !1, !1);
    }),
    ["tabIndex", "crossOrigin"].forEach(function (t) {
      _[t] = new k(t, 1, !1, t.toLowerCase(), null, !1, !1);
    }),
    (_.xlinkHref = new k(
      "xlinkHref",
      1,
      !1,
      "xlink:href",
      "http://www.w3.org/1999/xlink",
      !0,
      !1
    )),
    ["src", "href", "action", "formAction"].forEach(function (t) {
      _[t] = new k(t, 1, !1, t.toLowerCase(), null, !0, !0);
    });
  function N(t, n, s, a) {
    var u = _.hasOwnProperty(n) ? _[n] : null;
    (u !== null
      ? u.type !== 0
      : a ||
        !(2 < n.length) ||
        (n[0] !== "o" && n[0] !== "O") ||
        (n[1] !== "n" && n[1] !== "N")) &&
      (E(n, s, u, a) && (s = null),
      a || u === null
        ? x(n) &&
          (s === null ? t.removeAttribute(n) : t.setAttribute(n, "" + s))
        : u.mustUseProperty
        ? (t[u.propertyName] = s === null ? (u.type === 3 ? !1 : "") : s)
        : ((n = u.attributeName),
          (a = u.attributeNamespace),
          s === null
            ? t.removeAttribute(n)
            : ((u = u.type),
              (s = u === 3 || (u === 4 && s === !0) ? "" : "" + s),
              a ? t.setAttributeNS(a, n, s) : t.setAttribute(n, s))));
  }
  var U = r.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED,
    z = Symbol.for("react.element"),
    H = Symbol.for("react.portal"),
    G = Symbol.for("react.fragment"),
    Q = Symbol.for("react.strict_mode"),
    me = Symbol.for("react.profiler"),
    ae = Symbol.for("react.provider"),
    xe = Symbol.for("react.context"),
    te = Symbol.for("react.forward_ref"),
    _e = Symbol.for("react.suspense"),
    Ae = Symbol.for("react.suspense_list"),
    ke = Symbol.for("react.memo"),
    be = Symbol.for("react.lazy"),
    Se = Symbol.for("react.offscreen"),
    D = Symbol.iterator;
  function J(t) {
    return t === null || typeof t != "object"
      ? null
      : ((t = (D && t[D]) || t["@@iterator"]),
        typeof t == "function" ? t : null);
  }
  var X = Object.assign,
    R;
  function B(t) {
    if (R === void 0)
      try {
        throw Error();
      } catch (s) {
        var n = s.stack.trim().match(/\n( *(at )?)/);
        R = (n && n[1]) || "";
      }
    return (
      `
` +
      R +
      t
    );
  }
  var le = !1;
  function he(t, n) {
    if (!t || le) return "";
    le = !0;
    var s = Error.prepareStackTrace;
    Error.prepareStackTrace = void 0;
    try {
      if (n)
        if (
          ((n = function () {
            throw Error();
          }),
          Object.defineProperty(n.prototype, "props", {
            set: function () {
              throw Error();
            },
          }),
          typeof Reflect == "object" && Reflect.construct)
        ) {
          try {
            Reflect.construct(n, []);
          } catch (I) {
            var a = I;
          }
          Reflect.construct(t, [], n);
        } else {
          try {
            n.call();
          } catch (I) {
            a = I;
          }
          t.call(n.prototype);
        }
      else {
        try {
          throw Error();
        } catch (I) {
          a = I;
        }
        t();
      }
    } catch (I) {
      if (I && a && typeof I.stack == "string") {
        for (
          var u = I.stack.split(`
`),
            h = a.stack.split(`
`),
            y = u.length - 1,
            S = h.length - 1;
          1 <= y && 0 <= S && u[y] !== h[S];

        )
          S--;
        for (; 1 <= y && 0 <= S; y--, S--)
          if (u[y] !== h[S]) {
            if (y !== 1 || S !== 1)
              do
                if ((y--, S--, 0 > S || u[y] !== h[S])) {
                  var P =
                    `
` + u[y].replace(" at new ", " at ");
                  return (
                    t.displayName &&
                      P.includes("<anonymous>") &&
                      (P = P.replace("<anonymous>", t.displayName)),
                    P
                  );
                }
              while (1 <= y && 0 <= S);
            break;
          }
      }
    } finally {
      (le = !1), (Error.prepareStackTrace = s);
    }
    return (t = t ? t.displayName || t.name : "") ? B(t) : "";
  }
  function W(t) {
    switch (t.tag) {
      case 5:
        return B(t.type);
      case 16:
        return B("Lazy");
      case 13:
        return B("Suspense");
      case 19:
        return B("SuspenseList");
      case 0:
      case 2:
      case 15:
        return (t = he(t.type, !1)), t;
      case 11:
        return (t = he(t.type.render, !1)), t;
      case 1:
        return (t = he(t.type, !0)), t;
      default:
        return "";
    }
  }
  function re(t) {
    if (t == null) return null;
    if (typeof t == "function") return t.displayName || t.name || null;
    if (typeof t == "string") return t;
    switch (t) {
      case G:
        return "Fragment";
      case H:
        return "Portal";
      case me:
        return "Profiler";
      case Q:
        return "StrictMode";
      case _e:
        return "Suspense";
      case Ae:
        return "SuspenseList";
    }
    if (typeof t == "object")
      switch (t.$$typeof) {
        case xe:
          return (t.displayName || "Context") + ".Consumer";
        case ae:
          return (t._context.displayName || "Context") + ".Provider";
        case te:
          var n = t.render;
          return (
            (t = t.displayName),
            t ||
              ((t = n.displayName || n.name || ""),
              (t = t !== "" ? "ForwardRef(" + t + ")" : "ForwardRef")),
            t
          );
        case ke:
          return (
            (n = t.displayName || null), n !== null ? n : re(t.type) || "Memo"
          );
        case be:
          (n = t._payload), (t = t._init);
          try {
            return re(t(n));
          } catch {}
      }
    return null;
  }
  function Y(t) {
    var n = t.type;
    switch (t.tag) {
      case 24:
        return "Cache";
      case 9:
        return (n.displayName || "Context") + ".Consumer";
      case 10:
        return (n._context.displayName || "Context") + ".Provider";
      case 18:
        return "DehydratedFragment";
      case 11:
        return (
          (t = n.render),
          (t = t.displayName || t.name || ""),
          n.displayName || (t !== "" ? "ForwardRef(" + t + ")" : "ForwardRef")
        );
      case 7:
        return "Fragment";
      case 5:
        return n;
      case 4:
        return "Portal";
      case 3:
        return "Root";
      case 6:
        return "Text";
      case 16:
        return re(n);
      case 8:
        return n === Q ? "StrictMode" : "Mode";
      case 22:
        return "Offscreen";
      case 12:
        return "Profiler";
      case 21:
        return "Scope";
      case 13:
        return "Suspense";
      case 19:
        return "SuspenseList";
      case 25:
        return "TracingMarker";
      case 1:
      case 0:
      case 17:
      case 2:
      case 14:
      case 15:
        if (typeof n == "function") return n.displayName || n.name || null;
        if (typeof n == "string") return n;
    }
    return null;
  }
  function ue(t) {
    switch (typeof t) {
      case "boolean":
      case "number":
      case "string":
      case "undefined":
        return t;
      case "object":
        return t;
      default:
        return "";
    }
  }
  function ne(t) {
    var n = t.type;
    return (
      (t = t.nodeName) &&
      t.toLowerCase() === "input" &&
      (n === "checkbox" || n === "radio")
    );
  }
  function de(t) {
    var n = ne(t) ? "checked" : "value",
      s = Object.getOwnPropertyDescriptor(t.constructor.prototype, n),
      a = "" + t[n];
    if (
      !t.hasOwnProperty(n) &&
      typeof s < "u" &&
      typeof s.get == "function" &&
      typeof s.set == "function"
    ) {
      var u = s.get,
        h = s.set;
      return (
        Object.defineProperty(t, n, {
          configurable: !0,
          get: function () {
            return u.call(this);
          },
          set: function (y) {
            (a = "" + y), h.call(this, y);
          },
        }),
        Object.defineProperty(t, n, { enumerable: s.enumerable }),
        {
          getValue: function () {
            return a;
          },
          setValue: function (y) {
            a = "" + y;
          },
          stopTracking: function () {
            (t._valueTracker = null), delete t[n];
          },
        }
      );
    }
  }
  function ve(t) {
    t._valueTracker || (t._valueTracker = de(t));
  }
  function Ie(t) {
    if (!t) return !1;
    var n = t._valueTracker;
    if (!n) return !0;
    var s = n.getValue(),
      a = "";
    return (
      t && (a = ne(t) ? (t.checked ? "true" : "false") : t.value),
      (t = a),
      t !== s ? (n.setValue(t), !0) : !1
    );
  }
  function Ue(t) {
    if (
      ((t = t || (typeof document < "u" ? document : void 0)), typeof t > "u")
    )
      return null;
    try {
      return t.activeElement || t.body;
    } catch {
      return t.body;
    }
  }
  function Ye(t, n) {
    var s = n.checked;
    return X({}, n, {
      defaultChecked: void 0,
      defaultValue: void 0,
      value: void 0,
      checked: s ?? t._wrapperState.initialChecked,
    });
  }
  function _t(t, n) {
    var s = n.defaultValue == null ? "" : n.defaultValue,
      a = n.checked != null ? n.checked : n.defaultChecked;
    (s = ue(n.value != null ? n.value : s)),
      (t._wrapperState = {
        initialChecked: a,
        initialValue: s,
        controlled:
          n.type === "checkbox" || n.type === "radio"
            ? n.checked != null
            : n.value != null,
      });
  }
  function Ke(t, n) {
    (n = n.checked), n != null && N(t, "checked", n, !1);
  }
  function rt(t, n) {
    Ke(t, n);
    var s = ue(n.value),
      a = n.type;
    if (s != null)
      a === "number"
        ? ((s === 0 && t.value === "") || t.value != s) && (t.value = "" + s)
        : t.value !== "" + s && (t.value = "" + s);
    else if (a === "submit" || a === "reset") {
      t.removeAttribute("value");
      return;
    }
    n.hasOwnProperty("value")
      ? hr(t, n.type, s)
      : n.hasOwnProperty("defaultValue") && hr(t, n.type, ue(n.defaultValue)),
      n.checked == null &&
        n.defaultChecked != null &&
        (t.defaultChecked = !!n.defaultChecked);
  }
  function wt(t, n, s) {
    if (n.hasOwnProperty("value") || n.hasOwnProperty("defaultValue")) {
      var a = n.type;
      if (
        !(
          (a !== "submit" && a !== "reset") ||
          (n.value !== void 0 && n.value !== null)
        )
      )
        return;
      (n = "" + t._wrapperState.initialValue),
        s || n === t.value || (t.value = n),
        (t.defaultValue = n);
    }
    (s = t.name),
      s !== "" && (t.name = ""),
      (t.defaultChecked = !!t._wrapperState.initialChecked),
      s !== "" && (t.name = s);
  }
  function hr(t, n, s) {
    (n !== "number" || Ue(t.ownerDocument) !== t) &&
      (s == null
        ? (t.defaultValue = "" + t._wrapperState.initialValue)
        : t.defaultValue !== "" + s && (t.defaultValue = "" + s));
  }
  var kt = Array.isArray;
  function nt(t, n, s, a) {
    if (((t = t.options), n)) {
      n = {};
      for (var u = 0; u < s.length; u++) n["$" + s[u]] = !0;
      for (s = 0; s < t.length; s++)
        (u = n.hasOwnProperty("$" + t[s].value)),
          t[s].selected !== u && (t[s].selected = u),
          u && a && (t[s].defaultSelected = !0);
    } else {
      for (s = "" + ue(s), n = null, u = 0; u < t.length; u++) {
        if (t[u].value === s) {
          (t[u].selected = !0), a && (t[u].defaultSelected = !0);
          return;
        }
        n !== null || t[u].disabled || (n = t[u]);
      }
      n !== null && (n.selected = !0);
    }
  }
  function dr(t, n) {
    if (n.dangerouslySetInnerHTML != null) throw Error(i(91));
    return X({}, n, {
      value: void 0,
      defaultValue: void 0,
      children: "" + t._wrapperState.initialValue,
    });
  }
  function Ar(t, n) {
    var s = n.value;
    if (s == null) {
      if (((s = n.children), (n = n.defaultValue), s != null)) {
        if (n != null) throw Error(i(92));
        if (kt(s)) {
          if (1 < s.length) throw Error(i(93));
          s = s[0];
        }
        n = s;
      }
      n == null && (n = ""), (s = n);
    }
    t._wrapperState = { initialValue: ue(s) };
  }
  function Cr(t, n) {
    var s = ue(n.value),
      a = ue(n.defaultValue);
    s != null &&
      ((s = "" + s),
      s !== t.value && (t.value = s),
      n.defaultValue == null && t.defaultValue !== s && (t.defaultValue = s)),
      a != null && (t.defaultValue = "" + a);
  }
  function Ns(t) {
    var n = t.textContent;
    n === t._wrapperState.initialValue &&
      n !== "" &&
      n !== null &&
      (t.value = n);
  }
  function Ds(t) {
    switch (t) {
      case "svg":
        return "http://www.w3.org/2000/svg";
      case "math":
        return "http://www.w3.org/1998/Math/MathML";
      default:
        return "http://www.w3.org/1999/xhtml";
    }
  }
  function qn(t, n) {
    return t == null || t === "http://www.w3.org/1999/xhtml"
      ? Ds(n)
      : t === "http://www.w3.org/2000/svg" && n === "foreignObject"
      ? "http://www.w3.org/1999/xhtml"
      : t;
  }
  var Vn,
    Vr = (function (t) {
      return typeof MSApp < "u" && MSApp.execUnsafeLocalFunction
        ? function (n, s, a, u) {
            MSApp.execUnsafeLocalFunction(function () {
              return t(n, s, a, u);
            });
          }
        : t;
    })(function (t, n) {
      if (t.namespaceURI !== "http://www.w3.org/2000/svg" || "innerHTML" in t)
        t.innerHTML = n;
      else {
        for (
          Vn = Vn || document.createElement("div"),
            Vn.innerHTML = "<svg>" + n.valueOf().toString() + "</svg>",
            n = Vn.firstChild;
          t.firstChild;

        )
          t.removeChild(t.firstChild);
        for (; n.firstChild; ) t.appendChild(n.firstChild);
      }
    });
  function kr(t, n) {
    if (n) {
      var s = t.firstChild;
      if (s && s === t.lastChild && s.nodeType === 3) {
        s.nodeValue = n;
        return;
      }
    }
    t.textContent = n;
  }
  var Gr = {
      animationIterationCount: !0,
      aspectRatio: !0,
      borderImageOutset: !0,
      borderImageSlice: !0,
      borderImageWidth: !0,
      boxFlex: !0,
      boxFlexGroup: !0,
      boxOrdinalGroup: !0,
      columnCount: !0,
      columns: !0,
      flex: !0,
      flexGrow: !0,
      flexPositive: !0,
      flexShrink: !0,
      flexNegative: !0,
      flexOrder: !0,
      gridArea: !0,
      gridRow: !0,
      gridRowEnd: !0,
      gridRowSpan: !0,
      gridRowStart: !0,
      gridColumn: !0,
      gridColumnEnd: !0,
      gridColumnSpan: !0,
      gridColumnStart: !0,
      fontWeight: !0,
      lineClamp: !0,
      lineHeight: !0,
      opacity: !0,
      order: !0,
      orphans: !0,
      tabSize: !0,
      widows: !0,
      zIndex: !0,
      zoom: !0,
      fillOpacity: !0,
      floodOpacity: !0,
      stopOpacity: !0,
      strokeDasharray: !0,
      strokeDashoffset: !0,
      strokeMiterlimit: !0,
      strokeOpacity: !0,
      strokeWidth: !0,
    },
    Ra = ["Webkit", "ms", "Moz", "O"];
  Object.keys(Gr).forEach(function (t) {
    Ra.forEach(function (n) {
      (n = n + t.charAt(0).toUpperCase() + t.substring(1)), (Gr[n] = Gr[t]);
    });
  });
  function Bs(t, n, s) {
    return n == null || typeof n == "boolean" || n === ""
      ? ""
      : s || typeof n != "number" || n === 0 || (Gr.hasOwnProperty(t) && Gr[t])
      ? ("" + n).trim()
      : n + "px";
  }
  function Gn(t, n) {
    t = t.style;
    for (var s in n)
      if (n.hasOwnProperty(s)) {
        var a = s.indexOf("--") === 0,
          u = Bs(s, n[s], a);
        s === "float" && (s = "cssFloat"), a ? t.setProperty(s, u) : (t[s] = u);
      }
  }
  var Wn = X(
    { menuitem: !0 },
    {
      area: !0,
      base: !0,
      br: !0,
      col: !0,
      embed: !0,
      hr: !0,
      img: !0,
      input: !0,
      keygen: !0,
      link: !0,
      meta: !0,
      param: !0,
      source: !0,
      track: !0,
      wbr: !0,
    }
  );
  function M(t, n) {
    if (n) {
      if (Wn[t] && (n.children != null || n.dangerouslySetInnerHTML != null))
        throw Error(i(137, t));
      if (n.dangerouslySetInnerHTML != null) {
        if (n.children != null) throw Error(i(60));
        if (
          typeof n.dangerouslySetInnerHTML != "object" ||
          !("__html" in n.dangerouslySetInnerHTML)
        )
          throw Error(i(61));
      }
      if (n.style != null && typeof n.style != "object") throw Error(i(62));
    }
  }
  function L(t, n) {
    if (t.indexOf("-") === -1) return typeof n.is == "string";
    switch (t) {
      case "annotation-xml":
      case "color-profile":
      case "font-face":
      case "font-face-src":
      case "font-face-uri":
      case "font-face-format":
      case "font-face-name":
      case "missing-glyph":
        return !1;
      default:
        return !0;
    }
  }
  var Ce = null;
  function Me(t) {
    return (
      (t = t.target || t.srcElement || window),
      t.correspondingUseElement && (t = t.correspondingUseElement),
      t.nodeType === 3 ? t.parentNode : t
    );
  }
  var Le = null,
    ge = null,
    xt = null;
  function pr(t) {
    if ((t = Zi(t))) {
      if (typeof Le != "function") throw Error(i(280));
      var n = t.stateNode;
      n && ((n = uo(n)), Le(t.stateNode, t.type, n));
    }
  }
  function ht(t) {
    ge ? (xt ? xt.push(t) : (xt = [t])) : (ge = t);
  }
  function Kt() {
    if (ge) {
      var t = ge,
        n = xt;
      if (((xt = ge = null), pr(t), n)) for (t = 0; t < n.length; t++) pr(n[t]);
    }
  }
  function Xn(t, n) {
    return t(n);
  }
  function Rr() {}
  var St = !1;
  function bi(t, n, s) {
    if (St) return t(n, s);
    St = !0;
    try {
      return Xn(t, n, s);
    } finally {
      (St = !1), (ge !== null || xt !== null) && (Rr(), Kt());
    }
  }
  function Wr(t, n) {
    var s = t.stateNode;
    if (s === null) return null;
    var a = uo(s);
    if (a === null) return null;
    s = a[n];
    e: switch (n) {
      case "onClick":
      case "onClickCapture":
      case "onDoubleClick":
      case "onDoubleClickCapture":
      case "onMouseDown":
      case "onMouseDownCapture":
      case "onMouseMove":
      case "onMouseMoveCapture":
      case "onMouseUp":
      case "onMouseUpCapture":
      case "onMouseEnter":
        (a = !a.disabled) ||
          ((t = t.type),
          (a = !(
            t === "button" ||
            t === "input" ||
            t === "select" ||
            t === "textarea"
          ))),
          (t = !a);
        break e;
      default:
        t = !1;
    }
    if (t) return null;
    if (s && typeof s != "function") throw Error(i(231, n, typeof s));
    return s;
  }
  var Yn = !1;
  if (d)
    try {
      var Jt = {};
      Object.defineProperty(Jt, "passive", {
        get: function () {
          Yn = !0;
        },
      }),
        window.addEventListener("test", Jt, Jt),
        window.removeEventListener("test", Jt, Jt);
    } catch {
      Yn = !1;
    }
  function Ti(t, n, s, a, u, h, y, S, P) {
    var I = Array.prototype.slice.call(arguments, 3);
    try {
      n.apply(s, I);
    } catch ($) {
      this.onError($);
    }
  }
  var mr = !1,
    Xr = null,
    Yr = !1,
    Qn = null,
    Us = {
      onError: function (t) {
        (mr = !0), (Xr = t);
      },
    };
  function Oi(t, n, s, a, u, h, y, S, P) {
    (mr = !1), (Xr = null), Ti.apply(Us, arguments);
  }
  function js(t, n, s, a, u, h, y, S, P) {
    if ((Oi.apply(this, arguments), mr)) {
      if (mr) {
        var I = Xr;
        (mr = !1), (Xr = null);
      } else throw Error(i(198));
      Yr || ((Yr = !0), (Qn = I));
    }
  }
  function Zt(t) {
    var n = t,
      s = t;
    if (t.alternate) for (; n.return; ) n = n.return;
    else {
      t = n;
      do (n = t), (n.flags & 4098) !== 0 && (s = n.return), (t = n.return);
      while (t);
    }
    return n.tag === 3 ? s : null;
  }
  function Mi(t) {
    if (t.tag === 13) {
      var n = t.memoizedState;
      if (
        (n === null && ((t = t.alternate), t !== null && (n = t.memoizedState)),
        n !== null)
      )
        return n.dehydrated;
    }
    return null;
  }
  function $s(t) {
    if (Zt(t) !== t) throw Error(i(188));
  }
  function Ii(t) {
    var n = t.alternate;
    if (!n) {
      if (((n = Zt(t)), n === null)) throw Error(i(188));
      return n !== t ? null : t;
    }
    for (var s = t, a = n; ; ) {
      var u = s.return;
      if (u === null) break;
      var h = u.alternate;
      if (h === null) {
        if (((a = u.return), a !== null)) {
          s = a;
          continue;
        }
        break;
      }
      if (u.child === h.child) {
        for (h = u.child; h; ) {
          if (h === s) return $s(u), t;
          if (h === a) return $s(u), n;
          h = h.sibling;
        }
        throw Error(i(188));
      }
      if (s.return !== a.return) (s = u), (a = h);
      else {
        for (var y = !1, S = u.child; S; ) {
          if (S === s) {
            (y = !0), (s = u), (a = h);
            break;
          }
          if (S === a) {
            (y = !0), (a = u), (s = h);
            break;
          }
          S = S.sibling;
        }
        if (!y) {
          for (S = h.child; S; ) {
            if (S === s) {
              (y = !0), (s = h), (a = u);
              break;
            }
            if (S === a) {
              (y = !0), (a = h), (s = u);
              break;
            }
            S = S.sibling;
          }
          if (!y) throw Error(i(189));
        }
      }
      if (s.alternate !== a) throw Error(i(190));
    }
    if (s.tag !== 3) throw Error(i(188));
    return s.stateNode.current === s ? t : n;
  }
  function br(t) {
    return (t = Ii(t)), t !== null ? Sn(t) : null;
  }
  function Sn(t) {
    if (t.tag === 5 || t.tag === 6) return t;
    for (t = t.child; t !== null; ) {
      var n = Sn(t);
      if (n !== null) return n;
      t = t.sibling;
    }
    return null;
  }
  var zs = e.unstable_scheduleCallback,
    Li = e.unstable_cancelCallback,
    $g = e.unstable_shouldYield,
    zg = e.unstable_requestPaint,
    We = e.unstable_now,
    Hg = e.unstable_getCurrentPriorityLevel,
    ba = e.unstable_ImmediatePriority,
    af = e.unstable_UserBlockingPriority,
    Hs = e.unstable_NormalPriority,
    qg = e.unstable_LowPriority,
    lf = e.unstable_IdlePriority,
    qs = null,
    yr = null;
  function Vg(t) {
    if (yr && typeof yr.onCommitFiberRoot == "function")
      try {
        yr.onCommitFiberRoot(qs, t, void 0, (t.current.flags & 128) === 128);
      } catch {}
  }
  var er = Math.clz32 ? Math.clz32 : Xg,
    Gg = Math.log,
    Wg = Math.LN2;
  function Xg(t) {
    return (t >>>= 0), t === 0 ? 32 : (31 - ((Gg(t) / Wg) | 0)) | 0;
  }
  var Vs = 64,
    Gs = 4194304;
  function Fi(t) {
    switch (t & -t) {
      case 1:
        return 1;
      case 2:
        return 2;
      case 4:
        return 4;
      case 8:
        return 8;
      case 16:
        return 16;
      case 32:
        return 32;
      case 64:
      case 128:
      case 256:
      case 512:
      case 1024:
      case 2048:
      case 4096:
      case 8192:
      case 16384:
      case 32768:
      case 65536:
      case 131072:
      case 262144:
      case 524288:
      case 1048576:
      case 2097152:
        return t & 4194240;
      case 4194304:
      case 8388608:
      case 16777216:
      case 33554432:
      case 67108864:
        return t & 130023424;
      case 134217728:
        return 134217728;
      case 268435456:
        return 268435456;
      case 536870912:
        return 536870912;
      case 1073741824:
        return 1073741824;
      default:
        return t;
    }
  }
  function Ws(t, n) {
    var s = t.pendingLanes;
    if (s === 0) return 0;
    var a = 0,
      u = t.suspendedLanes,
      h = t.pingedLanes,
      y = s & 268435455;
    if (y !== 0) {
      var S = y & ~u;
      S !== 0 ? (a = Fi(S)) : ((h &= y), h !== 0 && (a = Fi(h)));
    } else (y = s & ~u), y !== 0 ? (a = Fi(y)) : h !== 0 && (a = Fi(h));
    if (a === 0) return 0;
    if (
      n !== 0 &&
      n !== a &&
      (n & u) === 0 &&
      ((u = a & -a), (h = n & -n), u >= h || (u === 16 && (h & 4194240) !== 0))
    )
      return n;
    if (((a & 4) !== 0 && (a |= s & 16), (n = t.entangledLanes), n !== 0))
      for (t = t.entanglements, n &= a; 0 < n; )
        (s = 31 - er(n)), (u = 1 << s), (a |= t[s]), (n &= ~u);
    return a;
  }
  function Yg(t, n) {
    switch (t) {
      case 1:
      case 2:
      case 4:
        return n + 250;
      case 8:
      case 16:
      case 32:
      case 64:
      case 128:
      case 256:
      case 512:
      case 1024:
      case 2048:
      case 4096:
      case 8192:
      case 16384:
      case 32768:
      case 65536:
      case 131072:
      case 262144:
      case 524288:
      case 1048576:
      case 2097152:
        return n + 5e3;
      case 4194304:
      case 8388608:
      case 16777216:
      case 33554432:
      case 67108864:
        return -1;
      case 134217728:
      case 268435456:
      case 536870912:
      case 1073741824:
        return -1;
      default:
        return -1;
    }
  }
  function Qg(t, n) {
    for (
      var s = t.suspendedLanes,
        a = t.pingedLanes,
        u = t.expirationTimes,
        h = t.pendingLanes;
      0 < h;

    ) {
      var y = 31 - er(h),
        S = 1 << y,
        P = u[y];
      P === -1
        ? ((S & s) === 0 || (S & a) !== 0) && (u[y] = Yg(S, n))
        : P <= n && (t.expiredLanes |= S),
        (h &= ~S);
    }
  }
  function Ta(t) {
    return (
      (t = t.pendingLanes & -1073741825),
      t !== 0 ? t : t & 1073741824 ? 1073741824 : 0
    );
  }
  function uf() {
    var t = Vs;
    return (Vs <<= 1), (Vs & 4194240) === 0 && (Vs = 64), t;
  }
  function Oa(t) {
    for (var n = [], s = 0; 31 > s; s++) n.push(t);
    return n;
  }
  function Ni(t, n, s) {
    (t.pendingLanes |= n),
      n !== 536870912 && ((t.suspendedLanes = 0), (t.pingedLanes = 0)),
      (t = t.eventTimes),
      (n = 31 - er(n)),
      (t[n] = s);
  }
  function Kg(t, n) {
    var s = t.pendingLanes & ~n;
    (t.pendingLanes = n),
      (t.suspendedLanes = 0),
      (t.pingedLanes = 0),
      (t.expiredLanes &= n),
      (t.mutableReadLanes &= n),
      (t.entangledLanes &= n),
      (n = t.entanglements);
    var a = t.eventTimes;
    for (t = t.expirationTimes; 0 < s; ) {
      var u = 31 - er(s),
        h = 1 << u;
      (n[u] = 0), (a[u] = -1), (t[u] = -1), (s &= ~h);
    }
  }
  function Ma(t, n) {
    var s = (t.entangledLanes |= n);
    for (t = t.entanglements; s; ) {
      var a = 31 - er(s),
        u = 1 << a;
      (u & n) | (t[a] & n) && (t[a] |= n), (s &= ~u);
    }
  }
  var Fe = 0;
  function cf(t) {
    return (
      (t &= -t),
      1 < t ? (4 < t ? ((t & 268435455) !== 0 ? 16 : 536870912) : 4) : 1
    );
  }
  var ff,
    Ia,
    hf,
    df,
    pf,
    La = !1,
    Xs = [],
    Qr = null,
    Kr = null,
    Jr = null,
    Di = new Map(),
    Bi = new Map(),
    Zr = [],
    Jg =
      "mousedown mouseup touchcancel touchend touchstart auxclick dblclick pointercancel pointerdown pointerup dragend dragstart drop compositionend compositionstart keydown keypress keyup input textInput copy cut paste click change contextmenu reset submit".split(
        " "
      );
  function mf(t, n) {
    switch (t) {
      case "focusin":
      case "focusout":
        Qr = null;
        break;
      case "dragenter":
      case "dragleave":
        Kr = null;
        break;
      case "mouseover":
      case "mouseout":
        Jr = null;
        break;
      case "pointerover":
      case "pointerout":
        Di.delete(n.pointerId);
        break;
      case "gotpointercapture":
      case "lostpointercapture":
        Bi.delete(n.pointerId);
    }
  }
  function Ui(t, n, s, a, u, h) {
    return t === null || t.nativeEvent !== h
      ? ((t = {
          blockedOn: n,
          domEventName: s,
          eventSystemFlags: a,
          nativeEvent: h,
          targetContainers: [u],
        }),
        n !== null && ((n = Zi(n)), n !== null && Ia(n)),
        t)
      : ((t.eventSystemFlags |= a),
        (n = t.targetContainers),
        u !== null && n.indexOf(u) === -1 && n.push(u),
        t);
  }
  function Zg(t, n, s, a, u) {
    switch (n) {
      case "focusin":
        return (Qr = Ui(Qr, t, n, s, a, u)), !0;
      case "dragenter":
        return (Kr = Ui(Kr, t, n, s, a, u)), !0;
      case "mouseover":
        return (Jr = Ui(Jr, t, n, s, a, u)), !0;
      case "pointerover":
        var h = u.pointerId;
        return Di.set(h, Ui(Di.get(h) || null, t, n, s, a, u)), !0;
      case "gotpointercapture":
        return (
          (h = u.pointerId), Bi.set(h, Ui(Bi.get(h) || null, t, n, s, a, u)), !0
        );
    }
    return !1;
  }
  function yf(t) {
    var n = En(t.target);
    if (n !== null) {
      var s = Zt(n);
      if (s !== null) {
        if (((n = s.tag), n === 13)) {
          if (((n = Mi(s)), n !== null)) {
            (t.blockedOn = n),
              pf(t.priority, function () {
                hf(s);
              });
            return;
          }
        } else if (n === 3 && s.stateNode.current.memoizedState.isDehydrated) {
          t.blockedOn = s.tag === 3 ? s.stateNode.containerInfo : null;
          return;
        }
      }
    }
    t.blockedOn = null;
  }
  function Ys(t) {
    if (t.blockedOn !== null) return !1;
    for (var n = t.targetContainers; 0 < n.length; ) {
      var s = Na(t.domEventName, t.eventSystemFlags, n[0], t.nativeEvent);
      if (s === null) {
        s = t.nativeEvent;
        var a = new s.constructor(s.type, s);
        (Ce = a), s.target.dispatchEvent(a), (Ce = null);
      } else return (n = Zi(s)), n !== null && Ia(n), (t.blockedOn = s), !1;
      n.shift();
    }
    return !0;
  }
  function gf(t, n, s) {
    Ys(t) && s.delete(n);
  }
  function ev() {
    (La = !1),
      Qr !== null && Ys(Qr) && (Qr = null),
      Kr !== null && Ys(Kr) && (Kr = null),
      Jr !== null && Ys(Jr) && (Jr = null),
      Di.forEach(gf),
      Bi.forEach(gf);
  }
  function ji(t, n) {
    t.blockedOn === n &&
      ((t.blockedOn = null),
      La ||
        ((La = !0),
        e.unstable_scheduleCallback(e.unstable_NormalPriority, ev)));
  }
  function $i(t) {
    function n(u) {
      return ji(u, t);
    }
    if (0 < Xs.length) {
      ji(Xs[0], t);
      for (var s = 1; s < Xs.length; s++) {
        var a = Xs[s];
        a.blockedOn === t && (a.blockedOn = null);
      }
    }
    for (
      Qr !== null && ji(Qr, t),
        Kr !== null && ji(Kr, t),
        Jr !== null && ji(Jr, t),
        Di.forEach(n),
        Bi.forEach(n),
        s = 0;
      s < Zr.length;
      s++
    )
      (a = Zr[s]), a.blockedOn === t && (a.blockedOn = null);
    for (; 0 < Zr.length && ((s = Zr[0]), s.blockedOn === null); )
      yf(s), s.blockedOn === null && Zr.shift();
  }
  var Kn = U.ReactCurrentBatchConfig,
    Qs = !0;
  function tv(t, n, s, a) {
    var u = Fe,
      h = Kn.transition;
    Kn.transition = null;
    try {
      (Fe = 1), Fa(t, n, s, a);
    } finally {
      (Fe = u), (Kn.transition = h);
    }
  }
  function rv(t, n, s, a) {
    var u = Fe,
      h = Kn.transition;
    Kn.transition = null;
    try {
      (Fe = 4), Fa(t, n, s, a);
    } finally {
      (Fe = u), (Kn.transition = h);
    }
  }
  function Fa(t, n, s, a) {
    if (Qs) {
      var u = Na(t, n, s, a);
      if (u === null) Za(t, n, a, Ks, s), mf(t, a);
      else if (Zg(u, t, n, s, a)) a.stopPropagation();
      else if ((mf(t, a), n & 4 && -1 < Jg.indexOf(t))) {
        for (; u !== null; ) {
          var h = Zi(u);
          if (
            (h !== null && ff(h),
            (h = Na(t, n, s, a)),
            h === null && Za(t, n, a, Ks, s),
            h === u)
          )
            break;
          u = h;
        }
        u !== null && a.stopPropagation();
      } else Za(t, n, a, null, s);
    }
  }
  var Ks = null;
  function Na(t, n, s, a) {
    if (((Ks = null), (t = Me(a)), (t = En(t)), t !== null))
      if (((n = Zt(t)), n === null)) t = null;
      else if (((s = n.tag), s === 13)) {
        if (((t = Mi(n)), t !== null)) return t;
        t = null;
      } else if (s === 3) {
        if (n.stateNode.current.memoizedState.isDehydrated)
          return n.tag === 3 ? n.stateNode.containerInfo : null;
        t = null;
      } else n !== t && (t = null);
    return (Ks = t), null;
  }
  function vf(t) {
    switch (t) {
      case "cancel":
      case "click":
      case "close":
      case "contextmenu":
      case "copy":
      case "cut":
      case "auxclick":
      case "dblclick":
      case "dragend":
      case "dragstart":
      case "drop":
      case "focusin":
      case "focusout":
      case "input":
      case "invalid":
      case "keydown":
      case "keypress":
      case "keyup":
      case "mousedown":
      case "mouseup":
      case "paste":
      case "pause":
      case "play":
      case "pointercancel":
      case "pointerdown":
      case "pointerup":
      case "ratechange":
      case "reset":
      case "resize":
      case "seeked":
      case "submit":
      case "touchcancel":
      case "touchend":
      case "touchstart":
      case "volumechange":
      case "change":
      case "selectionchange":
      case "textInput":
      case "compositionstart":
      case "compositionend":
      case "compositionupdate":
      case "beforeblur":
      case "afterblur":
      case "beforeinput":
      case "blur":
      case "fullscreenchange":
      case "focus":
      case "hashchange":
      case "popstate":
      case "select":
      case "selectstart":
        return 1;
      case "drag":
      case "dragenter":
      case "dragexit":
      case "dragleave":
      case "dragover":
      case "mousemove":
      case "mouseout":
      case "mouseover":
      case "pointermove":
      case "pointerout":
      case "pointerover":
      case "scroll":
      case "toggle":
      case "touchmove":
      case "wheel":
      case "mouseenter":
      case "mouseleave":
      case "pointerenter":
      case "pointerleave":
        return 4;
      case "message":
        switch (Hg()) {
          case ba:
            return 1;
          case af:
            return 4;
          case Hs:
          case qg:
            return 16;
          case lf:
            return 536870912;
          default:
            return 16;
        }
      default:
        return 16;
    }
  }
  var en = null,
    Da = null,
    Js = null;
  function _f() {
    if (Js) return Js;
    var t,
      n = Da,
      s = n.length,
      a,
      u = "value" in en ? en.value : en.textContent,
      h = u.length;
    for (t = 0; t < s && n[t] === u[t]; t++);
    var y = s - t;
    for (a = 1; a <= y && n[s - a] === u[h - a]; a++);
    return (Js = u.slice(t, 1 < a ? 1 - a : void 0));
  }
  function Zs(t) {
    var n = t.keyCode;
    return (
      "charCode" in t
        ? ((t = t.charCode), t === 0 && n === 13 && (t = 13))
        : (t = n),
      t === 10 && (t = 13),
      32 <= t || t === 13 ? t : 0
    );
  }
  function eo() {
    return !0;
  }
  function wf() {
    return !1;
  }
  function Nt(t) {
    function n(s, a, u, h, y) {
      (this._reactName = s),
        (this._targetInst = u),
        (this.type = a),
        (this.nativeEvent = h),
        (this.target = y),
        (this.currentTarget = null);
      for (var S in t)
        t.hasOwnProperty(S) && ((s = t[S]), (this[S] = s ? s(h) : h[S]));
      return (
        (this.isDefaultPrevented = (
          h.defaultPrevented != null ? h.defaultPrevented : h.returnValue === !1
        )
          ? eo
          : wf),
        (this.isPropagationStopped = wf),
        this
      );
    }
    return (
      X(n.prototype, {
        preventDefault: function () {
          this.defaultPrevented = !0;
          var s = this.nativeEvent;
          s &&
            (s.preventDefault
              ? s.preventDefault()
              : typeof s.returnValue != "unknown" && (s.returnValue = !1),
            (this.isDefaultPrevented = eo));
        },
        stopPropagation: function () {
          var s = this.nativeEvent;
          s &&
            (s.stopPropagation
              ? s.stopPropagation()
              : typeof s.cancelBubble != "unknown" && (s.cancelBubble = !0),
            (this.isPropagationStopped = eo));
        },
        persist: function () {},
        isPersistent: eo,
      }),
      n
    );
  }
  var Jn = {
      eventPhase: 0,
      bubbles: 0,
      cancelable: 0,
      timeStamp: function (t) {
        return t.timeStamp || Date.now();
      },
      defaultPrevented: 0,
      isTrusted: 0,
    },
    Ba = Nt(Jn),
    zi = X({}, Jn, { view: 0, detail: 0 }),
    nv = Nt(zi),
    Ua,
    ja,
    Hi,
    to = X({}, zi, {
      screenX: 0,
      screenY: 0,
      clientX: 0,
      clientY: 0,
      pageX: 0,
      pageY: 0,
      ctrlKey: 0,
      shiftKey: 0,
      altKey: 0,
      metaKey: 0,
      getModifierState: za,
      button: 0,
      buttons: 0,
      relatedTarget: function (t) {
        return t.relatedTarget === void 0
          ? t.fromElement === t.srcElement
            ? t.toElement
            : t.fromElement
          : t.relatedTarget;
      },
      movementX: function (t) {
        return "movementX" in t
          ? t.movementX
          : (t !== Hi &&
              (Hi && t.type === "mousemove"
                ? ((Ua = t.screenX - Hi.screenX), (ja = t.screenY - Hi.screenY))
                : (ja = Ua = 0),
              (Hi = t)),
            Ua);
      },
      movementY: function (t) {
        return "movementY" in t ? t.movementY : ja;
      },
    }),
    xf = Nt(to),
    iv = X({}, to, { dataTransfer: 0 }),
    sv = Nt(iv),
    ov = X({}, zi, { relatedTarget: 0 }),
    $a = Nt(ov),
    av = X({}, Jn, { animationName: 0, elapsedTime: 0, pseudoElement: 0 }),
    lv = Nt(av),
    uv = X({}, Jn, {
      clipboardData: function (t) {
        return "clipboardData" in t ? t.clipboardData : window.clipboardData;
      },
    }),
    cv = Nt(uv),
    fv = X({}, Jn, { data: 0 }),
    Sf = Nt(fv),
    hv = {
      Esc: "Escape",
      Spacebar: " ",
      Left: "ArrowLeft",
      Up: "ArrowUp",
      Right: "ArrowRight",
      Down: "ArrowDown",
      Del: "Delete",
      Win: "OS",
      Menu: "ContextMenu",
      Apps: "ContextMenu",
      Scroll: "ScrollLock",
      MozPrintableKey: "Unidentified",
    },
    dv = {
      8: "Backspace",
      9: "Tab",
      12: "Clear",
      13: "Enter",
      16: "Shift",
      17: "Control",
      18: "Alt",
      19: "Pause",
      20: "CapsLock",
      27: "Escape",
      32: " ",
      33: "PageUp",
      34: "PageDown",
      35: "End",
      36: "Home",
      37: "ArrowLeft",
      38: "ArrowUp",
      39: "ArrowRight",
      40: "ArrowDown",
      45: "Insert",
      46: "Delete",
      112: "F1",
      113: "F2",
      114: "F3",
      115: "F4",
      116: "F5",
      117: "F6",
      118: "F7",
      119: "F8",
      120: "F9",
      121: "F10",
      122: "F11",
      123: "F12",
      144: "NumLock",
      145: "ScrollLock",
      224: "Meta",
    },
    pv = {
      Alt: "altKey",
      Control: "ctrlKey",
      Meta: "metaKey",
      Shift: "shiftKey",
    };
  function mv(t) {
    var n = this.nativeEvent;
    return n.getModifierState
      ? n.getModifierState(t)
      : (t = pv[t])
      ? !!n[t]
      : !1;
  }
  function za() {
    return mv;
  }
  var yv = X({}, zi, {
      key: function (t) {
        if (t.key) {
          var n = hv[t.key] || t.key;
          if (n !== "Unidentified") return n;
        }
        return t.type === "keypress"
          ? ((t = Zs(t)), t === 13 ? "Enter" : String.fromCharCode(t))
          : t.type === "keydown" || t.type === "keyup"
          ? dv[t.keyCode] || "Unidentified"
          : "";
      },
      code: 0,
      location: 0,
      ctrlKey: 0,
      shiftKey: 0,
      altKey: 0,
      metaKey: 0,
      repeat: 0,
      locale: 0,
      getModifierState: za,
      charCode: function (t) {
        return t.type === "keypress" ? Zs(t) : 0;
      },
      keyCode: function (t) {
        return t.type === "keydown" || t.type === "keyup" ? t.keyCode : 0;
      },
      which: function (t) {
        return t.type === "keypress"
          ? Zs(t)
          : t.type === "keydown" || t.type === "keyup"
          ? t.keyCode
          : 0;
      },
    }),
    gv = Nt(yv),
    vv = X({}, to, {
      pointerId: 0,
      width: 0,
      height: 0,
      pressure: 0,
      tangentialPressure: 0,
      tiltX: 0,
      tiltY: 0,
      twist: 0,
      pointerType: 0,
      isPrimary: 0,
    }),
    Ef = Nt(vv),
    _v = X({}, zi, {
      touches: 0,
      targetTouches: 0,
      changedTouches: 0,
      altKey: 0,
      metaKey: 0,
      ctrlKey: 0,
      shiftKey: 0,
      getModifierState: za,
    }),
    wv = Nt(_v),
    xv = X({}, Jn, { propertyName: 0, elapsedTime: 0, pseudoElement: 0 }),
    Sv = Nt(xv),
    Ev = X({}, to, {
      deltaX: function (t) {
        return "deltaX" in t
          ? t.deltaX
          : "wheelDeltaX" in t
          ? -t.wheelDeltaX
          : 0;
      },
      deltaY: function (t) {
        return "deltaY" in t
          ? t.deltaY
          : "wheelDeltaY" in t
          ? -t.wheelDeltaY
          : "wheelDelta" in t
          ? -t.wheelDelta
          : 0;
      },
      deltaZ: 0,
      deltaMode: 0,
    }),
    Pv = Nt(Ev),
    Av = [9, 13, 27, 32],
    Ha = d && "CompositionEvent" in window,
    qi = null;
  d && "documentMode" in document && (qi = document.documentMode);
  var Cv = d && "TextEvent" in window && !qi,
    Pf = d && (!Ha || (qi && 8 < qi && 11 >= qi)),
    Af = " ",
    Cf = !1;
  function kf(t, n) {
    switch (t) {
      case "keyup":
        return Av.indexOf(n.keyCode) !== -1;
      case "keydown":
        return n.keyCode !== 229;
      case "keypress":
      case "mousedown":
      case "focusout":
        return !0;
      default:
        return !1;
    }
  }
  function Rf(t) {
    return (t = t.detail), typeof t == "object" && "data" in t ? t.data : null;
  }
  var Zn = !1;
  function kv(t, n) {
    switch (t) {
      case "compositionend":
        return Rf(n);
      case "keypress":
        return n.which !== 32 ? null : ((Cf = !0), Af);
      case "textInput":
        return (t = n.data), t === Af && Cf ? null : t;
      default:
        return null;
    }
  }
  function Rv(t, n) {
    if (Zn)
      return t === "compositionend" || (!Ha && kf(t, n))
        ? ((t = _f()), (Js = Da = en = null), (Zn = !1), t)
        : null;
    switch (t) {
      case "paste":
        return null;
      case "keypress":
        if (!(n.ctrlKey || n.altKey || n.metaKey) || (n.ctrlKey && n.altKey)) {
          if (n.char && 1 < n.char.length) return n.char;
          if (n.which) return String.fromCharCode(n.which);
        }
        return null;
      case "compositionend":
        return Pf && n.locale !== "ko" ? null : n.data;
      default:
        return null;
    }
  }
  var bv = {
    color: !0,
    date: !0,
    datetime: !0,
    "datetime-local": !0,
    email: !0,
    month: !0,
    number: !0,
    password: !0,
    range: !0,
    search: !0,
    tel: !0,
    text: !0,
    time: !0,
    url: !0,
    week: !0,
  };
  function bf(t) {
    var n = t && t.nodeName && t.nodeName.toLowerCase();
    return n === "input" ? !!bv[t.type] : n === "textarea";
  }
  function Tf(t, n, s, a) {
    ht(a),
      (n = oo(n, "onChange")),
      0 < n.length &&
        ((s = new Ba("onChange", "change", null, s, a)),
        t.push({ event: s, listeners: n }));
  }
  var Vi = null,
    Gi = null;
  function Tv(t) {
    Xf(t, 0);
  }
  function ro(t) {
    var n = ii(t);
    if (Ie(n)) return t;
  }
  function Ov(t, n) {
    if (t === "change") return n;
  }
  var Of = !1;
  if (d) {
    var qa;
    if (d) {
      var Va = "oninput" in document;
      if (!Va) {
        var Mf = document.createElement("div");
        Mf.setAttribute("oninput", "return;"),
          (Va = typeof Mf.oninput == "function");
      }
      qa = Va;
    } else qa = !1;
    Of = qa && (!document.documentMode || 9 < document.documentMode);
  }
  function If() {
    Vi && (Vi.detachEvent("onpropertychange", Lf), (Gi = Vi = null));
  }
  function Lf(t) {
    if (t.propertyName === "value" && ro(Gi)) {
      var n = [];
      Tf(n, Gi, t, Me(t)), bi(Tv, n);
    }
  }
  function Mv(t, n, s) {
    t === "focusin"
      ? (If(), (Vi = n), (Gi = s), Vi.attachEvent("onpropertychange", Lf))
      : t === "focusout" && If();
  }
  function Iv(t) {
    if (t === "selectionchange" || t === "keyup" || t === "keydown")
      return ro(Gi);
  }
  function Lv(t, n) {
    if (t === "click") return ro(n);
  }
  function Fv(t, n) {
    if (t === "input" || t === "change") return ro(n);
  }
  function Nv(t, n) {
    return (t === n && (t !== 0 || 1 / t === 1 / n)) || (t !== t && n !== n);
  }
  var tr = typeof Object.is == "function" ? Object.is : Nv;
  function Wi(t, n) {
    if (tr(t, n)) return !0;
    if (
      typeof t != "object" ||
      t === null ||
      typeof n != "object" ||
      n === null
    )
      return !1;
    var s = Object.keys(t),
      a = Object.keys(n);
    if (s.length !== a.length) return !1;
    for (a = 0; a < s.length; a++) {
      var u = s[a];
      if (!m.call(n, u) || !tr(t[u], n[u])) return !1;
    }
    return !0;
  }
  function Ff(t) {
    for (; t && t.firstChild; ) t = t.firstChild;
    return t;
  }
  function Nf(t, n) {
    var s = Ff(t);
    t = 0;
    for (var a; s; ) {
      if (s.nodeType === 3) {
        if (((a = t + s.textContent.length), t <= n && a >= n))
          return { node: s, offset: n - t };
        t = a;
      }
      e: {
        for (; s; ) {
          if (s.nextSibling) {
            s = s.nextSibling;
            break e;
          }
          s = s.parentNode;
        }
        s = void 0;
      }
      s = Ff(s);
    }
  }
  function Df(t, n) {
    return t && n
      ? t === n
        ? !0
        : t && t.nodeType === 3
        ? !1
        : n && n.nodeType === 3
        ? Df(t, n.parentNode)
        : "contains" in t
        ? t.contains(n)
        : t.compareDocumentPosition
        ? !!(t.compareDocumentPosition(n) & 16)
        : !1
      : !1;
  }
  function Bf() {
    for (var t = window, n = Ue(); n instanceof t.HTMLIFrameElement; ) {
      try {
        var s = typeof n.contentWindow.location.href == "string";
      } catch {
        s = !1;
      }
      if (s) t = n.contentWindow;
      else break;
      n = Ue(t.document);
    }
    return n;
  }
  function Ga(t) {
    var n = t && t.nodeName && t.nodeName.toLowerCase();
    return (
      n &&
      ((n === "input" &&
        (t.type === "text" ||
          t.type === "search" ||
          t.type === "tel" ||
          t.type === "url" ||
          t.type === "password")) ||
        n === "textarea" ||
        t.contentEditable === "true")
    );
  }
  function Dv(t) {
    var n = Bf(),
      s = t.focusedElem,
      a = t.selectionRange;
    if (
      n !== s &&
      s &&
      s.ownerDocument &&
      Df(s.ownerDocument.documentElement, s)
    ) {
      if (a !== null && Ga(s)) {
        if (
          ((n = a.start),
          (t = a.end),
          t === void 0 && (t = n),
          "selectionStart" in s)
        )
          (s.selectionStart = n),
            (s.selectionEnd = Math.min(t, s.value.length));
        else if (
          ((t = ((n = s.ownerDocument || document) && n.defaultView) || window),
          t.getSelection)
        ) {
          t = t.getSelection();
          var u = s.textContent.length,
            h = Math.min(a.start, u);
          (a = a.end === void 0 ? h : Math.min(a.end, u)),
            !t.extend && h > a && ((u = a), (a = h), (h = u)),
            (u = Nf(s, h));
          var y = Nf(s, a);
          u &&
            y &&
            (t.rangeCount !== 1 ||
              t.anchorNode !== u.node ||
              t.anchorOffset !== u.offset ||
              t.focusNode !== y.node ||
              t.focusOffset !== y.offset) &&
            ((n = n.createRange()),
            n.setStart(u.node, u.offset),
            t.removeAllRanges(),
            h > a
              ? (t.addRange(n), t.extend(y.node, y.offset))
              : (n.setEnd(y.node, y.offset), t.addRange(n)));
        }
      }
      for (n = [], t = s; (t = t.parentNode); )
        t.nodeType === 1 &&
          n.push({ element: t, left: t.scrollLeft, top: t.scrollTop });
      for (typeof s.focus == "function" && s.focus(), s = 0; s < n.length; s++)
        (t = n[s]),
          (t.element.scrollLeft = t.left),
          (t.element.scrollTop = t.top);
    }
  }
  var Bv = d && "documentMode" in document && 11 >= document.documentMode,
    ei = null,
    Wa = null,
    Xi = null,
    Xa = !1;
  function Uf(t, n, s) {
    var a =
      s.window === s ? s.document : s.nodeType === 9 ? s : s.ownerDocument;
    Xa ||
      ei == null ||
      ei !== Ue(a) ||
      ((a = ei),
      "selectionStart" in a && Ga(a)
        ? (a = { start: a.selectionStart, end: a.selectionEnd })
        : ((a = (
            (a.ownerDocument && a.ownerDocument.defaultView) ||
            window
          ).getSelection()),
          (a = {
            anchorNode: a.anchorNode,
            anchorOffset: a.anchorOffset,
            focusNode: a.focusNode,
            focusOffset: a.focusOffset,
          })),
      (Xi && Wi(Xi, a)) ||
        ((Xi = a),
        (a = oo(Wa, "onSelect")),
        0 < a.length &&
          ((n = new Ba("onSelect", "select", null, n, s)),
          t.push({ event: n, listeners: a }),
          (n.target = ei))));
  }
  function no(t, n) {
    var s = {};
    return (
      (s[t.toLowerCase()] = n.toLowerCase()),
      (s["Webkit" + t] = "webkit" + n),
      (s["Moz" + t] = "moz" + n),
      s
    );
  }
  var ti = {
      animationend: no("Animation", "AnimationEnd"),
      animationiteration: no("Animation", "AnimationIteration"),
      animationstart: no("Animation", "AnimationStart"),
      transitionend: no("Transition", "TransitionEnd"),
    },
    Ya = {},
    jf = {};
  d &&
    ((jf = document.createElement("div").style),
    "AnimationEvent" in window ||
      (delete ti.animationend.animation,
      delete ti.animationiteration.animation,
      delete ti.animationstart.animation),
    "TransitionEvent" in window || delete ti.transitionend.transition);
  function io(t) {
    if (Ya[t]) return Ya[t];
    if (!ti[t]) return t;
    var n = ti[t],
      s;
    for (s in n) if (n.hasOwnProperty(s) && s in jf) return (Ya[t] = n[s]);
    return t;
  }
  var $f = io("animationend"),
    zf = io("animationiteration"),
    Hf = io("animationstart"),
    qf = io("transitionend"),
    Vf = new Map(),
    Gf =
      "abort auxClick cancel canPlay canPlayThrough click close contextMenu copy cut drag dragEnd dragEnter dragExit dragLeave dragOver dragStart drop durationChange emptied encrypted ended error gotPointerCapture input invalid keyDown keyPress keyUp load loadedData loadedMetadata loadStart lostPointerCapture mouseDown mouseMove mouseOut mouseOver mouseUp paste pause play playing pointerCancel pointerDown pointerMove pointerOut pointerOver pointerUp progress rateChange reset resize seeked seeking stalled submit suspend timeUpdate touchCancel touchEnd touchStart volumeChange scroll toggle touchMove waiting wheel".split(
        " "
      );
  function tn(t, n) {
    Vf.set(t, n), c(n, [t]);
  }
  for (var Qa = 0; Qa < Gf.length; Qa++) {
    var Ka = Gf[Qa],
      Uv = Ka.toLowerCase(),
      jv = Ka[0].toUpperCase() + Ka.slice(1);
    tn(Uv, "on" + jv);
  }
  tn($f, "onAnimationEnd"),
    tn(zf, "onAnimationIteration"),
    tn(Hf, "onAnimationStart"),
    tn("dblclick", "onDoubleClick"),
    tn("focusin", "onFocus"),
    tn("focusout", "onBlur"),
    tn(qf, "onTransitionEnd"),
    f("onMouseEnter", ["mouseout", "mouseover"]),
    f("onMouseLeave", ["mouseout", "mouseover"]),
    f("onPointerEnter", ["pointerout", "pointerover"]),
    f("onPointerLeave", ["pointerout", "pointerover"]),
    c(
      "onChange",
      "change click focusin focusout input keydown keyup selectionchange".split(
        " "
      )
    ),
    c(
      "onSelect",
      "focusout contextmenu dragend focusin keydown keyup mousedown mouseup selectionchange".split(
        " "
      )
    ),
    c("onBeforeInput", ["compositionend", "keypress", "textInput", "paste"]),
    c(
      "onCompositionEnd",
      "compositionend focusout keydown keypress keyup mousedown".split(" ")
    ),
    c(
      "onCompositionStart",
      "compositionstart focusout keydown keypress keyup mousedown".split(" ")
    ),
    c(
      "onCompositionUpdate",
      "compositionupdate focusout keydown keypress keyup mousedown".split(" ")
    );
  var Yi =
      "abort canplay canplaythrough durationchange emptied encrypted ended error loadeddata loadedmetadata loadstart pause play playing progress ratechange resize seeked seeking stalled suspend timeupdate volumechange waiting".split(
        " "
      ),
    $v = new Set(
      "cancel close invalid load scroll toggle".split(" ").concat(Yi)
    );
  function Wf(t, n, s) {
    var a = t.type || "unknown-event";
    (t.currentTarget = s), js(a, n, void 0, t), (t.currentTarget = null);
  }
  function Xf(t, n) {
    n = (n & 4) !== 0;
    for (var s = 0; s < t.length; s++) {
      var a = t[s],
        u = a.event;
      a = a.listeners;
      e: {
        var h = void 0;
        if (n)
          for (var y = a.length - 1; 0 <= y; y--) {
            var S = a[y],
              P = S.instance,
              I = S.currentTarget;
            if (((S = S.listener), P !== h && u.isPropagationStopped()))
              break e;
            Wf(u, S, I), (h = P);
          }
        else
          for (y = 0; y < a.length; y++) {
            if (
              ((S = a[y]),
              (P = S.instance),
              (I = S.currentTarget),
              (S = S.listener),
              P !== h && u.isPropagationStopped())
            )
              break e;
            Wf(u, S, I), (h = P);
          }
      }
    }
    if (Yr) throw ((t = Qn), (Yr = !1), (Qn = null), t);
  }
  function De(t, n) {
    var s = n[sl];
    s === void 0 && (s = n[sl] = new Set());
    var a = t + "__bubble";
    s.has(a) || (Yf(n, t, 2, !1), s.add(a));
  }
  function Ja(t, n, s) {
    var a = 0;
    n && (a |= 4), Yf(s, t, a, n);
  }
  var so = "_reactListening" + Math.random().toString(36).slice(2);
  function Qi(t) {
    if (!t[so]) {
      (t[so] = !0),
        o.forEach(function (s) {
          s !== "selectionchange" && ($v.has(s) || Ja(s, !1, t), Ja(s, !0, t));
        });
      var n = t.nodeType === 9 ? t : t.ownerDocument;
      n === null || n[so] || ((n[so] = !0), Ja("selectionchange", !1, n));
    }
  }
  function Yf(t, n, s, a) {
    switch (vf(n)) {
      case 1:
        var u = tv;
        break;
      case 4:
        u = rv;
        break;
      default:
        u = Fa;
    }
    (s = u.bind(null, n, s, t)),
      (u = void 0),
      !Yn ||
        (n !== "touchstart" && n !== "touchmove" && n !== "wheel") ||
        (u = !0),
      a
        ? u !== void 0
          ? t.addEventListener(n, s, { capture: !0, passive: u })
          : t.addEventListener(n, s, !0)
        : u !== void 0
        ? t.addEventListener(n, s, { passive: u })
        : t.addEventListener(n, s, !1);
  }
  function Za(t, n, s, a, u) {
    var h = a;
    if ((n & 1) === 0 && (n & 2) === 0 && a !== null)
      e: for (;;) {
        if (a === null) return;
        var y = a.tag;
        if (y === 3 || y === 4) {
          var S = a.stateNode.containerInfo;
          if (S === u || (S.nodeType === 8 && S.parentNode === u)) break;
          if (y === 4)
            for (y = a.return; y !== null; ) {
              var P = y.tag;
              if (
                (P === 3 || P === 4) &&
                ((P = y.stateNode.containerInfo),
                P === u || (P.nodeType === 8 && P.parentNode === u))
              )
                return;
              y = y.return;
            }
          for (; S !== null; ) {
            if (((y = En(S)), y === null)) return;
            if (((P = y.tag), P === 5 || P === 6)) {
              a = h = y;
              continue e;
            }
            S = S.parentNode;
          }
        }
        a = a.return;
      }
    bi(function () {
      var I = h,
        $ = Me(s),
        q = [];
      e: {
        var j = Vf.get(t);
        if (j !== void 0) {
          var K = Ba,
            ie = t;
          switch (t) {
            case "keypress":
              if (Zs(s) === 0) break e;
            case "keydown":
            case "keyup":
              K = gv;
              break;
            case "focusin":
              (ie = "focus"), (K = $a);
              break;
            case "focusout":
              (ie = "blur"), (K = $a);
              break;
            case "beforeblur":
            case "afterblur":
              K = $a;
              break;
            case "click":
              if (s.button === 2) break e;
            case "auxclick":
            case "dblclick":
            case "mousedown":
            case "mousemove":
            case "mouseup":
            case "mouseout":
            case "mouseover":
            case "contextmenu":
              K = xf;
              break;
            case "drag":
            case "dragend":
            case "dragenter":
            case "dragexit":
            case "dragleave":
            case "dragover":
            case "dragstart":
            case "drop":
              K = sv;
              break;
            case "touchcancel":
            case "touchend":
            case "touchmove":
            case "touchstart":
              K = wv;
              break;
            case $f:
            case zf:
            case Hf:
              K = lv;
              break;
            case qf:
              K = Sv;
              break;
            case "scroll":
              K = nv;
              break;
            case "wheel":
              K = Pv;
              break;
            case "copy":
            case "cut":
            case "paste":
              K = cv;
              break;
            case "gotpointercapture":
            case "lostpointercapture":
            case "pointercancel":
            case "pointerdown":
            case "pointermove":
            case "pointerout":
            case "pointerover":
            case "pointerup":
              K = Ef;
          }
          var se = (n & 4) !== 0,
            Xe = !se && t === "scroll",
            T = se ? (j !== null ? j + "Capture" : null) : j;
          se = [];
          for (var C = I, O; C !== null; ) {
            O = C;
            var V = O.stateNode;
            if (
              (O.tag === 5 &&
                V !== null &&
                ((O = V),
                T !== null &&
                  ((V = Wr(C, T)), V != null && se.push(Ki(C, V, O)))),
              Xe)
            )
              break;
            C = C.return;
          }
          0 < se.length &&
            ((j = new K(j, ie, null, s, $)),
            q.push({ event: j, listeners: se }));
        }
      }
      if ((n & 7) === 0) {
        e: {
          if (
            ((j = t === "mouseover" || t === "pointerover"),
            (K = t === "mouseout" || t === "pointerout"),
            j &&
              s !== Ce &&
              (ie = s.relatedTarget || s.fromElement) &&
              (En(ie) || ie[Tr]))
          )
            break e;
          if (
            (K || j) &&
            ((j =
              $.window === $
                ? $
                : (j = $.ownerDocument)
                ? j.defaultView || j.parentWindow
                : window),
            K
              ? ((ie = s.relatedTarget || s.toElement),
                (K = I),
                (ie = ie ? En(ie) : null),
                ie !== null &&
                  ((Xe = Zt(ie)),
                  ie !== Xe || (ie.tag !== 5 && ie.tag !== 6)) &&
                  (ie = null))
              : ((K = null), (ie = I)),
            K !== ie)
          ) {
            if (
              ((se = xf),
              (V = "onMouseLeave"),
              (T = "onMouseEnter"),
              (C = "mouse"),
              (t === "pointerout" || t === "pointerover") &&
                ((se = Ef),
                (V = "onPointerLeave"),
                (T = "onPointerEnter"),
                (C = "pointer")),
              (Xe = K == null ? j : ii(K)),
              (O = ie == null ? j : ii(ie)),
              (j = new se(V, C + "leave", K, s, $)),
              (j.target = Xe),
              (j.relatedTarget = O),
              (V = null),
              En($) === I &&
                ((se = new se(T, C + "enter", ie, s, $)),
                (se.target = O),
                (se.relatedTarget = Xe),
                (V = se)),
              (Xe = V),
              K && ie)
            )
              t: {
                for (se = K, T = ie, C = 0, O = se; O; O = ri(O)) C++;
                for (O = 0, V = T; V; V = ri(V)) O++;
                for (; 0 < C - O; ) (se = ri(se)), C--;
                for (; 0 < O - C; ) (T = ri(T)), O--;
                for (; C--; ) {
                  if (se === T || (T !== null && se === T.alternate)) break t;
                  (se = ri(se)), (T = ri(T));
                }
                se = null;
              }
            else se = null;
            K !== null && Qf(q, j, K, se, !1),
              ie !== null && Xe !== null && Qf(q, Xe, ie, se, !0);
          }
        }
        e: {
          if (
            ((j = I ? ii(I) : window),
            (K = j.nodeName && j.nodeName.toLowerCase()),
            K === "select" || (K === "input" && j.type === "file"))
          )
            var oe = Ov;
          else if (bf(j))
            if (Of) oe = Fv;
            else {
              oe = Iv;
              var ce = Mv;
            }
          else
            (K = j.nodeName) &&
              K.toLowerCase() === "input" &&
              (j.type === "checkbox" || j.type === "radio") &&
              (oe = Lv);
          if (oe && (oe = oe(t, I))) {
            Tf(q, oe, s, $);
            break e;
          }
          ce && ce(t, j, I),
            t === "focusout" &&
              (ce = j._wrapperState) &&
              ce.controlled &&
              j.type === "number" &&
              hr(j, "number", j.value);
        }
        switch (((ce = I ? ii(I) : window), t)) {
          case "focusin":
            (bf(ce) || ce.contentEditable === "true") &&
              ((ei = ce), (Wa = I), (Xi = null));
            break;
          case "focusout":
            Xi = Wa = ei = null;
            break;
          case "mousedown":
            Xa = !0;
            break;
          case "contextmenu":
          case "mouseup":
          case "dragend":
            (Xa = !1), Uf(q, s, $);
            break;
          case "selectionchange":
            if (Bv) break;
          case "keydown":
          case "keyup":
            Uf(q, s, $);
        }
        var fe;
        if (Ha)
          e: {
            switch (t) {
              case "compositionstart":
                var ye = "onCompositionStart";
                break e;
              case "compositionend":
                ye = "onCompositionEnd";
                break e;
              case "compositionupdate":
                ye = "onCompositionUpdate";
                break e;
            }
            ye = void 0;
          }
        else
          Zn
            ? kf(t, s) && (ye = "onCompositionEnd")
            : t === "keydown" &&
              s.keyCode === 229 &&
              (ye = "onCompositionStart");
        ye &&
          (Pf &&
            s.locale !== "ko" &&
            (Zn || ye !== "onCompositionStart"
              ? ye === "onCompositionEnd" && Zn && (fe = _f())
              : ((en = $),
                (Da = "value" in en ? en.value : en.textContent),
                (Zn = !0))),
          (ce = oo(I, ye)),
          0 < ce.length &&
            ((ye = new Sf(ye, t, null, s, $)),
            q.push({ event: ye, listeners: ce }),
            fe
              ? (ye.data = fe)
              : ((fe = Rf(s)), fe !== null && (ye.data = fe)))),
          (fe = Cv ? kv(t, s) : Rv(t, s)) &&
            ((I = oo(I, "onBeforeInput")),
            0 < I.length &&
              (($ = new Sf("onBeforeInput", "beforeinput", null, s, $)),
              q.push({ event: $, listeners: I }),
              ($.data = fe)));
      }
      Xf(q, n);
    });
  }
  function Ki(t, n, s) {
    return { instance: t, listener: n, currentTarget: s };
  }
  function oo(t, n) {
    for (var s = n + "Capture", a = []; t !== null; ) {
      var u = t,
        h = u.stateNode;
      u.tag === 5 &&
        h !== null &&
        ((u = h),
        (h = Wr(t, s)),
        h != null && a.unshift(Ki(t, h, u)),
        (h = Wr(t, n)),
        h != null && a.push(Ki(t, h, u))),
        (t = t.return);
    }
    return a;
  }
  function ri(t) {
    if (t === null) return null;
    do t = t.return;
    while (t && t.tag !== 5);
    return t || null;
  }
  function Qf(t, n, s, a, u) {
    for (var h = n._reactName, y = []; s !== null && s !== a; ) {
      var S = s,
        P = S.alternate,
        I = S.stateNode;
      if (P !== null && P === a) break;
      S.tag === 5 &&
        I !== null &&
        ((S = I),
        u
          ? ((P = Wr(s, h)), P != null && y.unshift(Ki(s, P, S)))
          : u || ((P = Wr(s, h)), P != null && y.push(Ki(s, P, S)))),
        (s = s.return);
    }
    y.length !== 0 && t.push({ event: n, listeners: y });
  }
  var zv = /\r\n?/g,
    Hv = /\u0000|\uFFFD/g;
  function Kf(t) {
    return (typeof t == "string" ? t : "" + t)
      .replace(
        zv,
        `
`
      )
      .replace(Hv, "");
  }
  function ao(t, n, s) {
    if (((n = Kf(n)), Kf(t) !== n && s)) throw Error(i(425));
  }
  function lo() {}
  var el = null,
    tl = null;
  function rl(t, n) {
    return (
      t === "textarea" ||
      t === "noscript" ||
      typeof n.children == "string" ||
      typeof n.children == "number" ||
      (typeof n.dangerouslySetInnerHTML == "object" &&
        n.dangerouslySetInnerHTML !== null &&
        n.dangerouslySetInnerHTML.__html != null)
    );
  }
  var nl = typeof setTimeout == "function" ? setTimeout : void 0,
    qv = typeof clearTimeout == "function" ? clearTimeout : void 0,
    Jf = typeof Promise == "function" ? Promise : void 0,
    Vv =
      typeof queueMicrotask == "function"
        ? queueMicrotask
        : typeof Jf < "u"
        ? function (t) {
            return Jf.resolve(null).then(t).catch(Gv);
          }
        : nl;
  function Gv(t) {
    setTimeout(function () {
      throw t;
    });
  }
  function il(t, n) {
    var s = n,
      a = 0;
    do {
      var u = s.nextSibling;
      if ((t.removeChild(s), u && u.nodeType === 8))
        if (((s = u.data), s === "/$")) {
          if (a === 0) {
            t.removeChild(u), $i(n);
            return;
          }
          a--;
        } else (s !== "$" && s !== "$?" && s !== "$!") || a++;
      s = u;
    } while (s);
    $i(n);
  }
  function rn(t) {
    for (; t != null; t = t.nextSibling) {
      var n = t.nodeType;
      if (n === 1 || n === 3) break;
      if (n === 8) {
        if (((n = t.data), n === "$" || n === "$!" || n === "$?")) break;
        if (n === "/$") return null;
      }
    }
    return t;
  }
  function Zf(t) {
    t = t.previousSibling;
    for (var n = 0; t; ) {
      if (t.nodeType === 8) {
        var s = t.data;
        if (s === "$" || s === "$!" || s === "$?") {
          if (n === 0) return t;
          n--;
        } else s === "/$" && n++;
      }
      t = t.previousSibling;
    }
    return null;
  }
  var ni = Math.random().toString(36).slice(2),
    gr = "__reactFiber$" + ni,
    Ji = "__reactProps$" + ni,
    Tr = "__reactContainer$" + ni,
    sl = "__reactEvents$" + ni,
    Wv = "__reactListeners$" + ni,
    Xv = "__reactHandles$" + ni;
  function En(t) {
    var n = t[gr];
    if (n) return n;
    for (var s = t.parentNode; s; ) {
      if ((n = s[Tr] || s[gr])) {
        if (
          ((s = n.alternate),
          n.child !== null || (s !== null && s.child !== null))
        )
          for (t = Zf(t); t !== null; ) {
            if ((s = t[gr])) return s;
            t = Zf(t);
          }
        return n;
      }
      (t = s), (s = t.parentNode);
    }
    return null;
  }
  function Zi(t) {
    return (
      (t = t[gr] || t[Tr]),
      !t || (t.tag !== 5 && t.tag !== 6 && t.tag !== 13 && t.tag !== 3)
        ? null
        : t
    );
  }
  function ii(t) {
    if (t.tag === 5 || t.tag === 6) return t.stateNode;
    throw Error(i(33));
  }
  function uo(t) {
    return t[Ji] || null;
  }
  var ol = [],
    si = -1;
  function nn(t) {
    return { current: t };
  }
  function Be(t) {
    0 > si || ((t.current = ol[si]), (ol[si] = null), si--);
  }
  function Ne(t, n) {
    si++, (ol[si] = t.current), (t.current = n);
  }
  var sn = {},
    dt = nn(sn),
    Rt = nn(!1),
    Pn = sn;
  function oi(t, n) {
    var s = t.type.contextTypes;
    if (!s) return sn;
    var a = t.stateNode;
    if (a && a.__reactInternalMemoizedUnmaskedChildContext === n)
      return a.__reactInternalMemoizedMaskedChildContext;
    var u = {},
      h;
    for (h in s) u[h] = n[h];
    return (
      a &&
        ((t = t.stateNode),
        (t.__reactInternalMemoizedUnmaskedChildContext = n),
        (t.__reactInternalMemoizedMaskedChildContext = u)),
      u
    );
  }
  function bt(t) {
    return (t = t.childContextTypes), t != null;
  }
  function co() {
    Be(Rt), Be(dt);
  }
  function eh(t, n, s) {
    if (dt.current !== sn) throw Error(i(168));
    Ne(dt, n), Ne(Rt, s);
  }
  function th(t, n, s) {
    var a = t.stateNode;
    if (((n = n.childContextTypes), typeof a.getChildContext != "function"))
      return s;
    a = a.getChildContext();
    for (var u in a) if (!(u in n)) throw Error(i(108, Y(t) || "Unknown", u));
    return X({}, s, a);
  }
  function fo(t) {
    return (
      (t =
        ((t = t.stateNode) && t.__reactInternalMemoizedMergedChildContext) ||
        sn),
      (Pn = dt.current),
      Ne(dt, t),
      Ne(Rt, Rt.current),
      !0
    );
  }
  function rh(t, n, s) {
    var a = t.stateNode;
    if (!a) throw Error(i(169));
    s
      ? ((t = th(t, n, Pn)),
        (a.__reactInternalMemoizedMergedChildContext = t),
        Be(Rt),
        Be(dt),
        Ne(dt, t))
      : Be(Rt),
      Ne(Rt, s);
  }
  var Or = null,
    ho = !1,
    al = !1;
  function nh(t) {
    Or === null ? (Or = [t]) : Or.push(t);
  }
  function Yv(t) {
    (ho = !0), nh(t);
  }
  function on() {
    if (!al && Or !== null) {
      al = !0;
      var t = 0,
        n = Fe;
      try {
        var s = Or;
        for (Fe = 1; t < s.length; t++) {
          var a = s[t];
          do a = a(!0);
          while (a !== null);
        }
        (Or = null), (ho = !1);
      } catch (u) {
        throw (Or !== null && (Or = Or.slice(t + 1)), zs(ba, on), u);
      } finally {
        (Fe = n), (al = !1);
      }
    }
    return null;
  }
  var ai = [],
    li = 0,
    po = null,
    mo = 0,
    $t = [],
    zt = 0,
    An = null,
    Mr = 1,
    Ir = "";
  function Cn(t, n) {
    (ai[li++] = mo), (ai[li++] = po), (po = t), (mo = n);
  }
  function ih(t, n, s) {
    ($t[zt++] = Mr), ($t[zt++] = Ir), ($t[zt++] = An), (An = t);
    var a = Mr;
    t = Ir;
    var u = 32 - er(a) - 1;
    (a &= ~(1 << u)), (s += 1);
    var h = 32 - er(n) + u;
    if (30 < h) {
      var y = u - (u % 5);
      (h = (a & ((1 << y) - 1)).toString(32)),
        (a >>= y),
        (u -= y),
        (Mr = (1 << (32 - er(n) + u)) | (s << u) | a),
        (Ir = h + t);
    } else (Mr = (1 << h) | (s << u) | a), (Ir = t);
  }
  function ll(t) {
    t.return !== null && (Cn(t, 1), ih(t, 1, 0));
  }
  function ul(t) {
    for (; t === po; )
      (po = ai[--li]), (ai[li] = null), (mo = ai[--li]), (ai[li] = null);
    for (; t === An; )
      (An = $t[--zt]),
        ($t[zt] = null),
        (Ir = $t[--zt]),
        ($t[zt] = null),
        (Mr = $t[--zt]),
        ($t[zt] = null);
  }
  var Dt = null,
    Bt = null,
    je = !1,
    rr = null;
  function sh(t, n) {
    var s = Gt(5, null, null, 0);
    (s.elementType = "DELETED"),
      (s.stateNode = n),
      (s.return = t),
      (n = t.deletions),
      n === null ? ((t.deletions = [s]), (t.flags |= 16)) : n.push(s);
  }
  function oh(t, n) {
    switch (t.tag) {
      case 5:
        var s = t.type;
        return (
          (n =
            n.nodeType !== 1 || s.toLowerCase() !== n.nodeName.toLowerCase()
              ? null
              : n),
          n !== null
            ? ((t.stateNode = n), (Dt = t), (Bt = rn(n.firstChild)), !0)
            : !1
        );
      case 6:
        return (
          (n = t.pendingProps === "" || n.nodeType !== 3 ? null : n),
          n !== null ? ((t.stateNode = n), (Dt = t), (Bt = null), !0) : !1
        );
      case 13:
        return (
          (n = n.nodeType !== 8 ? null : n),
          n !== null
            ? ((s = An !== null ? { id: Mr, overflow: Ir } : null),
              (t.memoizedState = {
                dehydrated: n,
                treeContext: s,
                retryLane: 1073741824,
              }),
              (s = Gt(18, null, null, 0)),
              (s.stateNode = n),
              (s.return = t),
              (t.child = s),
              (Dt = t),
              (Bt = null),
              !0)
            : !1
        );
      default:
        return !1;
    }
  }
  function cl(t) {
    return (t.mode & 1) !== 0 && (t.flags & 128) === 0;
  }
  function fl(t) {
    if (je) {
      var n = Bt;
      if (n) {
        var s = n;
        if (!oh(t, n)) {
          if (cl(t)) throw Error(i(418));
          n = rn(s.nextSibling);
          var a = Dt;
          n && oh(t, n)
            ? sh(a, s)
            : ((t.flags = (t.flags & -4097) | 2), (je = !1), (Dt = t));
        }
      } else {
        if (cl(t)) throw Error(i(418));
        (t.flags = (t.flags & -4097) | 2), (je = !1), (Dt = t);
      }
    }
  }
  function ah(t) {
    for (
      t = t.return;
      t !== null && t.tag !== 5 && t.tag !== 3 && t.tag !== 13;

    )
      t = t.return;
    Dt = t;
  }
  function yo(t) {
    if (t !== Dt) return !1;
    if (!je) return ah(t), (je = !0), !1;
    var n;
    if (
      ((n = t.tag !== 3) &&
        !(n = t.tag !== 5) &&
        ((n = t.type),
        (n = n !== "head" && n !== "body" && !rl(t.type, t.memoizedProps))),
      n && (n = Bt))
    ) {
      if (cl(t)) throw (lh(), Error(i(418)));
      for (; n; ) sh(t, n), (n = rn(n.nextSibling));
    }
    if ((ah(t), t.tag === 13)) {
      if (((t = t.memoizedState), (t = t !== null ? t.dehydrated : null), !t))
        throw Error(i(317));
      e: {
        for (t = t.nextSibling, n = 0; t; ) {
          if (t.nodeType === 8) {
            var s = t.data;
            if (s === "/$") {
              if (n === 0) {
                Bt = rn(t.nextSibling);
                break e;
              }
              n--;
            } else (s !== "$" && s !== "$!" && s !== "$?") || n++;
          }
          t = t.nextSibling;
        }
        Bt = null;
      }
    } else Bt = Dt ? rn(t.stateNode.nextSibling) : null;
    return !0;
  }
  function lh() {
    for (var t = Bt; t; ) t = rn(t.nextSibling);
  }
  function ui() {
    (Bt = Dt = null), (je = !1);
  }
  function hl(t) {
    rr === null ? (rr = [t]) : rr.push(t);
  }
  var Qv = U.ReactCurrentBatchConfig;
  function es(t, n, s) {
    if (
      ((t = s.ref),
      t !== null && typeof t != "function" && typeof t != "object")
    ) {
      if (s._owner) {
        if (((s = s._owner), s)) {
          if (s.tag !== 1) throw Error(i(309));
          var a = s.stateNode;
        }
        if (!a) throw Error(i(147, t));
        var u = a,
          h = "" + t;
        return n !== null &&
          n.ref !== null &&
          typeof n.ref == "function" &&
          n.ref._stringRef === h
          ? n.ref
          : ((n = function (y) {
              var S = u.refs;
              y === null ? delete S[h] : (S[h] = y);
            }),
            (n._stringRef = h),
            n);
      }
      if (typeof t != "string") throw Error(i(284));
      if (!s._owner) throw Error(i(290, t));
    }
    return t;
  }
  function go(t, n) {
    throw (
      ((t = Object.prototype.toString.call(n)),
      Error(
        i(
          31,
          t === "[object Object]"
            ? "object with keys {" + Object.keys(n).join(", ") + "}"
            : t
        )
      ))
    );
  }
  function uh(t) {
    var n = t._init;
    return n(t._payload);
  }
  function ch(t) {
    function n(T, C) {
      if (t) {
        var O = T.deletions;
        O === null ? ((T.deletions = [C]), (T.flags |= 16)) : O.push(C);
      }
    }
    function s(T, C) {
      if (!t) return null;
      for (; C !== null; ) n(T, C), (C = C.sibling);
      return null;
    }
    function a(T, C) {
      for (T = new Map(); C !== null; )
        C.key !== null ? T.set(C.key, C) : T.set(C.index, C), (C = C.sibling);
      return T;
    }
    function u(T, C) {
      return (T = pn(T, C)), (T.index = 0), (T.sibling = null), T;
    }
    function h(T, C, O) {
      return (
        (T.index = O),
        t
          ? ((O = T.alternate),
            O !== null
              ? ((O = O.index), O < C ? ((T.flags |= 2), C) : O)
              : ((T.flags |= 2), C))
          : ((T.flags |= 1048576), C)
      );
    }
    function y(T) {
      return t && T.alternate === null && (T.flags |= 2), T;
    }
    function S(T, C, O, V) {
      return C === null || C.tag !== 6
        ? ((C = nu(O, T.mode, V)), (C.return = T), C)
        : ((C = u(C, O)), (C.return = T), C);
    }
    function P(T, C, O, V) {
      var oe = O.type;
      return oe === G
        ? $(T, C, O.props.children, V, O.key)
        : C !== null &&
          (C.elementType === oe ||
            (typeof oe == "object" &&
              oe !== null &&
              oe.$$typeof === be &&
              uh(oe) === C.type))
        ? ((V = u(C, O.props)), (V.ref = es(T, C, O)), (V.return = T), V)
        : ((V = $o(O.type, O.key, O.props, null, T.mode, V)),
          (V.ref = es(T, C, O)),
          (V.return = T),
          V);
    }
    function I(T, C, O, V) {
      return C === null ||
        C.tag !== 4 ||
        C.stateNode.containerInfo !== O.containerInfo ||
        C.stateNode.implementation !== O.implementation
        ? ((C = iu(O, T.mode, V)), (C.return = T), C)
        : ((C = u(C, O.children || [])), (C.return = T), C);
    }
    function $(T, C, O, V, oe) {
      return C === null || C.tag !== 7
        ? ((C = Ln(O, T.mode, V, oe)), (C.return = T), C)
        : ((C = u(C, O)), (C.return = T), C);
    }
    function q(T, C, O) {
      if ((typeof C == "string" && C !== "") || typeof C == "number")
        return (C = nu("" + C, T.mode, O)), (C.return = T), C;
      if (typeof C == "object" && C !== null) {
        switch (C.$$typeof) {
          case z:
            return (
              (O = $o(C.type, C.key, C.props, null, T.mode, O)),
              (O.ref = es(T, null, C)),
              (O.return = T),
              O
            );
          case H:
            return (C = iu(C, T.mode, O)), (C.return = T), C;
          case be:
            var V = C._init;
            return q(T, V(C._payload), O);
        }
        if (kt(C) || J(C))
          return (C = Ln(C, T.mode, O, null)), (C.return = T), C;
        go(T, C);
      }
      return null;
    }
    function j(T, C, O, V) {
      var oe = C !== null ? C.key : null;
      if ((typeof O == "string" && O !== "") || typeof O == "number")
        return oe !== null ? null : S(T, C, "" + O, V);
      if (typeof O == "object" && O !== null) {
        switch (O.$$typeof) {
          case z:
            return O.key === oe ? P(T, C, O, V) : null;
          case H:
            return O.key === oe ? I(T, C, O, V) : null;
          case be:
            return (oe = O._init), j(T, C, oe(O._payload), V);
        }
        if (kt(O) || J(O)) return oe !== null ? null : $(T, C, O, V, null);
        go(T, O);
      }
      return null;
    }
    function K(T, C, O, V, oe) {
      if ((typeof V == "string" && V !== "") || typeof V == "number")
        return (T = T.get(O) || null), S(C, T, "" + V, oe);
      if (typeof V == "object" && V !== null) {
        switch (V.$$typeof) {
          case z:
            return (
              (T = T.get(V.key === null ? O : V.key) || null), P(C, T, V, oe)
            );
          case H:
            return (
              (T = T.get(V.key === null ? O : V.key) || null), I(C, T, V, oe)
            );
          case be:
            var ce = V._init;
            return K(T, C, O, ce(V._payload), oe);
        }
        if (kt(V) || J(V)) return (T = T.get(O) || null), $(C, T, V, oe, null);
        go(C, V);
      }
      return null;
    }
    function ie(T, C, O, V) {
      for (
        var oe = null, ce = null, fe = C, ye = (C = 0), ot = null;
        fe !== null && ye < O.length;
        ye++
      ) {
        fe.index > ye ? ((ot = fe), (fe = null)) : (ot = fe.sibling);
        var Te = j(T, fe, O[ye], V);
        if (Te === null) {
          fe === null && (fe = ot);
          break;
        }
        t && fe && Te.alternate === null && n(T, fe),
          (C = h(Te, C, ye)),
          ce === null ? (oe = Te) : (ce.sibling = Te),
          (ce = Te),
          (fe = ot);
      }
      if (ye === O.length) return s(T, fe), je && Cn(T, ye), oe;
      if (fe === null) {
        for (; ye < O.length; ye++)
          (fe = q(T, O[ye], V)),
            fe !== null &&
              ((C = h(fe, C, ye)),
              ce === null ? (oe = fe) : (ce.sibling = fe),
              (ce = fe));
        return je && Cn(T, ye), oe;
      }
      for (fe = a(T, fe); ye < O.length; ye++)
        (ot = K(fe, T, ye, O[ye], V)),
          ot !== null &&
            (t &&
              ot.alternate !== null &&
              fe.delete(ot.key === null ? ye : ot.key),
            (C = h(ot, C, ye)),
            ce === null ? (oe = ot) : (ce.sibling = ot),
            (ce = ot));
      return (
        t &&
          fe.forEach(function (mn) {
            return n(T, mn);
          }),
        je && Cn(T, ye),
        oe
      );
    }
    function se(T, C, O, V) {
      var oe = J(O);
      if (typeof oe != "function") throw Error(i(150));
      if (((O = oe.call(O)), O == null)) throw Error(i(151));
      for (
        var ce = (oe = null), fe = C, ye = (C = 0), ot = null, Te = O.next();
        fe !== null && !Te.done;
        ye++, Te = O.next()
      ) {
        fe.index > ye ? ((ot = fe), (fe = null)) : (ot = fe.sibling);
        var mn = j(T, fe, Te.value, V);
        if (mn === null) {
          fe === null && (fe = ot);
          break;
        }
        t && fe && mn.alternate === null && n(T, fe),
          (C = h(mn, C, ye)),
          ce === null ? (oe = mn) : (ce.sibling = mn),
          (ce = mn),
          (fe = ot);
      }
      if (Te.done) return s(T, fe), je && Cn(T, ye), oe;
      if (fe === null) {
        for (; !Te.done; ye++, Te = O.next())
          (Te = q(T, Te.value, V)),
            Te !== null &&
              ((C = h(Te, C, ye)),
              ce === null ? (oe = Te) : (ce.sibling = Te),
              (ce = Te));
        return je && Cn(T, ye), oe;
      }
      for (fe = a(T, fe); !Te.done; ye++, Te = O.next())
        (Te = K(fe, T, ye, Te.value, V)),
          Te !== null &&
            (t &&
              Te.alternate !== null &&
              fe.delete(Te.key === null ? ye : Te.key),
            (C = h(Te, C, ye)),
            ce === null ? (oe = Te) : (ce.sibling = Te),
            (ce = Te));
      return (
        t &&
          fe.forEach(function (b0) {
            return n(T, b0);
          }),
        je && Cn(T, ye),
        oe
      );
    }
    function Xe(T, C, O, V) {
      if (
        (typeof O == "object" &&
          O !== null &&
          O.type === G &&
          O.key === null &&
          (O = O.props.children),
        typeof O == "object" && O !== null)
      ) {
        switch (O.$$typeof) {
          case z:
            e: {
              for (var oe = O.key, ce = C; ce !== null; ) {
                if (ce.key === oe) {
                  if (((oe = O.type), oe === G)) {
                    if (ce.tag === 7) {
                      s(T, ce.sibling),
                        (C = u(ce, O.props.children)),
                        (C.return = T),
                        (T = C);
                      break e;
                    }
                  } else if (
                    ce.elementType === oe ||
                    (typeof oe == "object" &&
                      oe !== null &&
                      oe.$$typeof === be &&
                      uh(oe) === ce.type)
                  ) {
                    s(T, ce.sibling),
                      (C = u(ce, O.props)),
                      (C.ref = es(T, ce, O)),
                      (C.return = T),
                      (T = C);
                    break e;
                  }
                  s(T, ce);
                  break;
                } else n(T, ce);
                ce = ce.sibling;
              }
              O.type === G
                ? ((C = Ln(O.props.children, T.mode, V, O.key)),
                  (C.return = T),
                  (T = C))
                : ((V = $o(O.type, O.key, O.props, null, T.mode, V)),
                  (V.ref = es(T, C, O)),
                  (V.return = T),
                  (T = V));
            }
            return y(T);
          case H:
            e: {
              for (ce = O.key; C !== null; ) {
                if (C.key === ce)
                  if (
                    C.tag === 4 &&
                    C.stateNode.containerInfo === O.containerInfo &&
                    C.stateNode.implementation === O.implementation
                  ) {
                    s(T, C.sibling),
                      (C = u(C, O.children || [])),
                      (C.return = T),
                      (T = C);
                    break e;
                  } else {
                    s(T, C);
                    break;
                  }
                else n(T, C);
                C = C.sibling;
              }
              (C = iu(O, T.mode, V)), (C.return = T), (T = C);
            }
            return y(T);
          case be:
            return (ce = O._init), Xe(T, C, ce(O._payload), V);
        }
        if (kt(O)) return ie(T, C, O, V);
        if (J(O)) return se(T, C, O, V);
        go(T, O);
      }
      return (typeof O == "string" && O !== "") || typeof O == "number"
        ? ((O = "" + O),
          C !== null && C.tag === 6
            ? (s(T, C.sibling), (C = u(C, O)), (C.return = T), (T = C))
            : (s(T, C), (C = nu(O, T.mode, V)), (C.return = T), (T = C)),
          y(T))
        : s(T, C);
    }
    return Xe;
  }
  var ci = ch(!0),
    fh = ch(!1),
    vo = nn(null),
    _o = null,
    fi = null,
    dl = null;
  function pl() {
    dl = fi = _o = null;
  }
  function ml(t) {
    var n = vo.current;
    Be(vo), (t._currentValue = n);
  }
  function yl(t, n, s) {
    for (; t !== null; ) {
      var a = t.alternate;
      if (
        ((t.childLanes & n) !== n
          ? ((t.childLanes |= n), a !== null && (a.childLanes |= n))
          : a !== null && (a.childLanes & n) !== n && (a.childLanes |= n),
        t === s)
      )
        break;
      t = t.return;
    }
  }
  function hi(t, n) {
    (_o = t),
      (dl = fi = null),
      (t = t.dependencies),
      t !== null &&
        t.firstContext !== null &&
        ((t.lanes & n) !== 0 && (Tt = !0), (t.firstContext = null));
  }
  function Ht(t) {
    var n = t._currentValue;
    if (dl !== t)
      if (((t = { context: t, memoizedValue: n, next: null }), fi === null)) {
        if (_o === null) throw Error(i(308));
        (fi = t), (_o.dependencies = { lanes: 0, firstContext: t });
      } else fi = fi.next = t;
    return n;
  }
  var kn = null;
  function gl(t) {
    kn === null ? (kn = [t]) : kn.push(t);
  }
  function hh(t, n, s, a) {
    var u = n.interleaved;
    return (
      u === null ? ((s.next = s), gl(n)) : ((s.next = u.next), (u.next = s)),
      (n.interleaved = s),
      Lr(t, a)
    );
  }
  function Lr(t, n) {
    t.lanes |= n;
    var s = t.alternate;
    for (s !== null && (s.lanes |= n), s = t, t = t.return; t !== null; )
      (t.childLanes |= n),
        (s = t.alternate),
        s !== null && (s.childLanes |= n),
        (s = t),
        (t = t.return);
    return s.tag === 3 ? s.stateNode : null;
  }
  var an = !1;
  function vl(t) {
    t.updateQueue = {
      baseState: t.memoizedState,
      firstBaseUpdate: null,
      lastBaseUpdate: null,
      shared: { pending: null, interleaved: null, lanes: 0 },
      effects: null,
    };
  }
  function dh(t, n) {
    (t = t.updateQueue),
      n.updateQueue === t &&
        (n.updateQueue = {
          baseState: t.baseState,
          firstBaseUpdate: t.firstBaseUpdate,
          lastBaseUpdate: t.lastBaseUpdate,
          shared: t.shared,
          effects: t.effects,
        });
  }
  function Fr(t, n) {
    return {
      eventTime: t,
      lane: n,
      tag: 0,
      payload: null,
      callback: null,
      next: null,
    };
  }
  function ln(t, n, s) {
    var a = t.updateQueue;
    if (a === null) return null;
    if (((a = a.shared), (Re & 2) !== 0)) {
      var u = a.pending;
      return (
        u === null ? (n.next = n) : ((n.next = u.next), (u.next = n)),
        (a.pending = n),
        Lr(t, s)
      );
    }
    return (
      (u = a.interleaved),
      u === null ? ((n.next = n), gl(a)) : ((n.next = u.next), (u.next = n)),
      (a.interleaved = n),
      Lr(t, s)
    );
  }
  function wo(t, n, s) {
    if (
      ((n = n.updateQueue), n !== null && ((n = n.shared), (s & 4194240) !== 0))
    ) {
      var a = n.lanes;
      (a &= t.pendingLanes), (s |= a), (n.lanes = s), Ma(t, s);
    }
  }
  function ph(t, n) {
    var s = t.updateQueue,
      a = t.alternate;
    if (a !== null && ((a = a.updateQueue), s === a)) {
      var u = null,
        h = null;
      if (((s = s.firstBaseUpdate), s !== null)) {
        do {
          var y = {
            eventTime: s.eventTime,
            lane: s.lane,
            tag: s.tag,
            payload: s.payload,
            callback: s.callback,
            next: null,
          };
          h === null ? (u = h = y) : (h = h.next = y), (s = s.next);
        } while (s !== null);
        h === null ? (u = h = n) : (h = h.next = n);
      } else u = h = n;
      (s = {
        baseState: a.baseState,
        firstBaseUpdate: u,
        lastBaseUpdate: h,
        shared: a.shared,
        effects: a.effects,
      }),
        (t.updateQueue = s);
      return;
    }
    (t = s.lastBaseUpdate),
      t === null ? (s.firstBaseUpdate = n) : (t.next = n),
      (s.lastBaseUpdate = n);
  }
  function xo(t, n, s, a) {
    var u = t.updateQueue;
    an = !1;
    var h = u.firstBaseUpdate,
      y = u.lastBaseUpdate,
      S = u.shared.pending;
    if (S !== null) {
      u.shared.pending = null;
      var P = S,
        I = P.next;
      (P.next = null), y === null ? (h = I) : (y.next = I), (y = P);
      var $ = t.alternate;
      $ !== null &&
        (($ = $.updateQueue),
        (S = $.lastBaseUpdate),
        S !== y &&
          (S === null ? ($.firstBaseUpdate = I) : (S.next = I),
          ($.lastBaseUpdate = P)));
    }
    if (h !== null) {
      var q = u.baseState;
      (y = 0), ($ = I = P = null), (S = h);
      do {
        var j = S.lane,
          K = S.eventTime;
        if ((a & j) === j) {
          $ !== null &&
            ($ = $.next =
              {
                eventTime: K,
                lane: 0,
                tag: S.tag,
                payload: S.payload,
                callback: S.callback,
                next: null,
              });
          e: {
            var ie = t,
              se = S;
            switch (((j = n), (K = s), se.tag)) {
              case 1:
                if (((ie = se.payload), typeof ie == "function")) {
                  q = ie.call(K, q, j);
                  break e;
                }
                q = ie;
                break e;
              case 3:
                ie.flags = (ie.flags & -65537) | 128;
              case 0:
                if (
                  ((ie = se.payload),
                  (j = typeof ie == "function" ? ie.call(K, q, j) : ie),
                  j == null)
                )
                  break e;
                q = X({}, q, j);
                break e;
              case 2:
                an = !0;
            }
          }
          S.callback !== null &&
            S.lane !== 0 &&
            ((t.flags |= 64),
            (j = u.effects),
            j === null ? (u.effects = [S]) : j.push(S));
        } else
          (K = {
            eventTime: K,
            lane: j,
            tag: S.tag,
            payload: S.payload,
            callback: S.callback,
            next: null,
          }),
            $ === null ? ((I = $ = K), (P = q)) : ($ = $.next = K),
            (y |= j);
        if (((S = S.next), S === null)) {
          if (((S = u.shared.pending), S === null)) break;
          (j = S),
            (S = j.next),
            (j.next = null),
            (u.lastBaseUpdate = j),
            (u.shared.pending = null);
        }
      } while (!0);
      if (
        ($ === null && (P = q),
        (u.baseState = P),
        (u.firstBaseUpdate = I),
        (u.lastBaseUpdate = $),
        (n = u.shared.interleaved),
        n !== null)
      ) {
        u = n;
        do (y |= u.lane), (u = u.next);
        while (u !== n);
      } else h === null && (u.shared.lanes = 0);
      (Tn |= y), (t.lanes = y), (t.memoizedState = q);
    }
  }
  function mh(t, n, s) {
    if (((t = n.effects), (n.effects = null), t !== null))
      for (n = 0; n < t.length; n++) {
        var a = t[n],
          u = a.callback;
        if (u !== null) {
          if (((a.callback = null), (a = s), typeof u != "function"))
            throw Error(i(191, u));
          u.call(a);
        }
      }
  }
  var ts = {},
    vr = nn(ts),
    rs = nn(ts),
    ns = nn(ts);
  function Rn(t) {
    if (t === ts) throw Error(i(174));
    return t;
  }
  function _l(t, n) {
    switch ((Ne(ns, n), Ne(rs, t), Ne(vr, ts), (t = n.nodeType), t)) {
      case 9:
      case 11:
        n = (n = n.documentElement) ? n.namespaceURI : qn(null, "");
        break;
      default:
        (t = t === 8 ? n.parentNode : n),
          (n = t.namespaceURI || null),
          (t = t.tagName),
          (n = qn(n, t));
    }
    Be(vr), Ne(vr, n);
  }
  function di() {
    Be(vr), Be(rs), Be(ns);
  }
  function yh(t) {
    Rn(ns.current);
    var n = Rn(vr.current),
      s = qn(n, t.type);
    n !== s && (Ne(rs, t), Ne(vr, s));
  }
  function wl(t) {
    rs.current === t && (Be(vr), Be(rs));
  }
  var ze = nn(0);
  function So(t) {
    for (var n = t; n !== null; ) {
      if (n.tag === 13) {
        var s = n.memoizedState;
        if (
          s !== null &&
          ((s = s.dehydrated), s === null || s.data === "$?" || s.data === "$!")
        )
          return n;
      } else if (n.tag === 19 && n.memoizedProps.revealOrder !== void 0) {
        if ((n.flags & 128) !== 0) return n;
      } else if (n.child !== null) {
        (n.child.return = n), (n = n.child);
        continue;
      }
      if (n === t) break;
      for (; n.sibling === null; ) {
        if (n.return === null || n.return === t) return null;
        n = n.return;
      }
      (n.sibling.return = n.return), (n = n.sibling);
    }
    return null;
  }
  var xl = [];
  function Sl() {
    for (var t = 0; t < xl.length; t++)
      xl[t]._workInProgressVersionPrimary = null;
    xl.length = 0;
  }
  var Eo = U.ReactCurrentDispatcher,
    El = U.ReactCurrentBatchConfig,
    bn = 0,
    He = null,
    Je = null,
    it = null,
    Po = !1,
    is = !1,
    ss = 0,
    Kv = 0;
  function pt() {
    throw Error(i(321));
  }
  function Pl(t, n) {
    if (n === null) return !1;
    for (var s = 0; s < n.length && s < t.length; s++)
      if (!tr(t[s], n[s])) return !1;
    return !0;
  }
  function Al(t, n, s, a, u, h) {
    if (
      ((bn = h),
      (He = n),
      (n.memoizedState = null),
      (n.updateQueue = null),
      (n.lanes = 0),
      (Eo.current = t === null || t.memoizedState === null ? t0 : r0),
      (t = s(a, u)),
      is)
    ) {
      h = 0;
      do {
        if (((is = !1), (ss = 0), 25 <= h)) throw Error(i(301));
        (h += 1),
          (it = Je = null),
          (n.updateQueue = null),
          (Eo.current = n0),
          (t = s(a, u));
      } while (is);
    }
    if (
      ((Eo.current = ko),
      (n = Je !== null && Je.next !== null),
      (bn = 0),
      (it = Je = He = null),
      (Po = !1),
      n)
    )
      throw Error(i(300));
    return t;
  }
  function Cl() {
    var t = ss !== 0;
    return (ss = 0), t;
  }
  function _r() {
    var t = {
      memoizedState: null,
      baseState: null,
      baseQueue: null,
      queue: null,
      next: null,
    };
    return it === null ? (He.memoizedState = it = t) : (it = it.next = t), it;
  }
  function qt() {
    if (Je === null) {
      var t = He.alternate;
      t = t !== null ? t.memoizedState : null;
    } else t = Je.next;
    var n = it === null ? He.memoizedState : it.next;
    if (n !== null) (it = n), (Je = t);
    else {
      if (t === null) throw Error(i(310));
      (Je = t),
        (t = {
          memoizedState: Je.memoizedState,
          baseState: Je.baseState,
          baseQueue: Je.baseQueue,
          queue: Je.queue,
          next: null,
        }),
        it === null ? (He.memoizedState = it = t) : (it = it.next = t);
    }
    return it;
  }
  function os(t, n) {
    return typeof n == "function" ? n(t) : n;
  }
  function kl(t) {
    var n = qt(),
      s = n.queue;
    if (s === null) throw Error(i(311));
    s.lastRenderedReducer = t;
    var a = Je,
      u = a.baseQueue,
      h = s.pending;
    if (h !== null) {
      if (u !== null) {
        var y = u.next;
        (u.next = h.next), (h.next = y);
      }
      (a.baseQueue = u = h), (s.pending = null);
    }
    if (u !== null) {
      (h = u.next), (a = a.baseState);
      var S = (y = null),
        P = null,
        I = h;
      do {
        var $ = I.lane;
        if ((bn & $) === $)
          P !== null &&
            (P = P.next =
              {
                lane: 0,
                action: I.action,
                hasEagerState: I.hasEagerState,
                eagerState: I.eagerState,
                next: null,
              }),
            (a = I.hasEagerState ? I.eagerState : t(a, I.action));
        else {
          var q = {
            lane: $,
            action: I.action,
            hasEagerState: I.hasEagerState,
            eagerState: I.eagerState,
            next: null,
          };
          P === null ? ((S = P = q), (y = a)) : (P = P.next = q),
            (He.lanes |= $),
            (Tn |= $);
        }
        I = I.next;
      } while (I !== null && I !== h);
      P === null ? (y = a) : (P.next = S),
        tr(a, n.memoizedState) || (Tt = !0),
        (n.memoizedState = a),
        (n.baseState = y),
        (n.baseQueue = P),
        (s.lastRenderedState = a);
    }
    if (((t = s.interleaved), t !== null)) {
      u = t;
      do (h = u.lane), (He.lanes |= h), (Tn |= h), (u = u.next);
      while (u !== t);
    } else u === null && (s.lanes = 0);
    return [n.memoizedState, s.dispatch];
  }
  function Rl(t) {
    var n = qt(),
      s = n.queue;
    if (s === null) throw Error(i(311));
    s.lastRenderedReducer = t;
    var a = s.dispatch,
      u = s.pending,
      h = n.memoizedState;
    if (u !== null) {
      s.pending = null;
      var y = (u = u.next);
      do (h = t(h, y.action)), (y = y.next);
      while (y !== u);
      tr(h, n.memoizedState) || (Tt = !0),
        (n.memoizedState = h),
        n.baseQueue === null && (n.baseState = h),
        (s.lastRenderedState = h);
    }
    return [h, a];
  }
  function gh() {}
  function vh(t, n) {
    var s = He,
      a = qt(),
      u = n(),
      h = !tr(a.memoizedState, u);
    if (
      (h && ((a.memoizedState = u), (Tt = !0)),
      (a = a.queue),
      bl(xh.bind(null, s, a, t), [t]),
      a.getSnapshot !== n || h || (it !== null && it.memoizedState.tag & 1))
    ) {
      if (
        ((s.flags |= 2048),
        as(9, wh.bind(null, s, a, u, n), void 0, null),
        st === null)
      )
        throw Error(i(349));
      (bn & 30) !== 0 || _h(s, n, u);
    }
    return u;
  }
  function _h(t, n, s) {
    (t.flags |= 16384),
      (t = { getSnapshot: n, value: s }),
      (n = He.updateQueue),
      n === null
        ? ((n = { lastEffect: null, stores: null }),
          (He.updateQueue = n),
          (n.stores = [t]))
        : ((s = n.stores), s === null ? (n.stores = [t]) : s.push(t));
  }
  function wh(t, n, s, a) {
    (n.value = s), (n.getSnapshot = a), Sh(n) && Eh(t);
  }
  function xh(t, n, s) {
    return s(function () {
      Sh(n) && Eh(t);
    });
  }
  function Sh(t) {
    var n = t.getSnapshot;
    t = t.value;
    try {
      var s = n();
      return !tr(t, s);
    } catch {
      return !0;
    }
  }
  function Eh(t) {
    var n = Lr(t, 1);
    n !== null && or(n, t, 1, -1);
  }
  function Ph(t) {
    var n = _r();
    return (
      typeof t == "function" && (t = t()),
      (n.memoizedState = n.baseState = t),
      (t = {
        pending: null,
        interleaved: null,
        lanes: 0,
        dispatch: null,
        lastRenderedReducer: os,
        lastRenderedState: t,
      }),
      (n.queue = t),
      (t = t.dispatch = e0.bind(null, He, t)),
      [n.memoizedState, t]
    );
  }
  function as(t, n, s, a) {
    return (
      (t = { tag: t, create: n, destroy: s, deps: a, next: null }),
      (n = He.updateQueue),
      n === null
        ? ((n = { lastEffect: null, stores: null }),
          (He.updateQueue = n),
          (n.lastEffect = t.next = t))
        : ((s = n.lastEffect),
          s === null
            ? (n.lastEffect = t.next = t)
            : ((a = s.next), (s.next = t), (t.next = a), (n.lastEffect = t))),
      t
    );
  }
  function Ah() {
    return qt().memoizedState;
  }
  function Ao(t, n, s, a) {
    var u = _r();
    (He.flags |= t),
      (u.memoizedState = as(1 | n, s, void 0, a === void 0 ? null : a));
  }
  function Co(t, n, s, a) {
    var u = qt();
    a = a === void 0 ? null : a;
    var h = void 0;
    if (Je !== null) {
      var y = Je.memoizedState;
      if (((h = y.destroy), a !== null && Pl(a, y.deps))) {
        u.memoizedState = as(n, s, h, a);
        return;
      }
    }
    (He.flags |= t), (u.memoizedState = as(1 | n, s, h, a));
  }
  function Ch(t, n) {
    return Ao(8390656, 8, t, n);
  }
  function bl(t, n) {
    return Co(2048, 8, t, n);
  }
  function kh(t, n) {
    return Co(4, 2, t, n);
  }
  function Rh(t, n) {
    return Co(4, 4, t, n);
  }
  function bh(t, n) {
    if (typeof n == "function")
      return (
        (t = t()),
        n(t),
        function () {
          n(null);
        }
      );
    if (n != null)
      return (
        (t = t()),
        (n.current = t),
        function () {
          n.current = null;
        }
      );
  }
  function Th(t, n, s) {
    return (
      (s = s != null ? s.concat([t]) : null), Co(4, 4, bh.bind(null, n, t), s)
    );
  }
  function Tl() {}
  function Oh(t, n) {
    var s = qt();
    n = n === void 0 ? null : n;
    var a = s.memoizedState;
    return a !== null && n !== null && Pl(n, a[1])
      ? a[0]
      : ((s.memoizedState = [t, n]), t);
  }
  function Mh(t, n) {
    var s = qt();
    n = n === void 0 ? null : n;
    var a = s.memoizedState;
    return a !== null && n !== null && Pl(n, a[1])
      ? a[0]
      : ((t = t()), (s.memoizedState = [t, n]), t);
  }
  function Ih(t, n, s) {
    return (bn & 21) === 0
      ? (t.baseState && ((t.baseState = !1), (Tt = !0)), (t.memoizedState = s))
      : (tr(s, n) ||
          ((s = uf()), (He.lanes |= s), (Tn |= s), (t.baseState = !0)),
        n);
  }
  function Jv(t, n) {
    var s = Fe;
    (Fe = s !== 0 && 4 > s ? s : 4), t(!0);
    var a = El.transition;
    El.transition = {};
    try {
      t(!1), n();
    } finally {
      (Fe = s), (El.transition = a);
    }
  }
  function Lh() {
    return qt().memoizedState;
  }
  function Zv(t, n, s) {
    var a = hn(t);
    if (
      ((s = {
        lane: a,
        action: s,
        hasEagerState: !1,
        eagerState: null,
        next: null,
      }),
      Fh(t))
    )
      Nh(n, s);
    else if (((s = hh(t, n, s, a)), s !== null)) {
      var u = Pt();
      or(s, t, a, u), Dh(s, n, a);
    }
  }
  function e0(t, n, s) {
    var a = hn(t),
      u = {
        lane: a,
        action: s,
        hasEagerState: !1,
        eagerState: null,
        next: null,
      };
    if (Fh(t)) Nh(n, u);
    else {
      var h = t.alternate;
      if (
        t.lanes === 0 &&
        (h === null || h.lanes === 0) &&
        ((h = n.lastRenderedReducer), h !== null)
      )
        try {
          var y = n.lastRenderedState,
            S = h(y, s);
          if (((u.hasEagerState = !0), (u.eagerState = S), tr(S, y))) {
            var P = n.interleaved;
            P === null
              ? ((u.next = u), gl(n))
              : ((u.next = P.next), (P.next = u)),
              (n.interleaved = u);
            return;
          }
        } catch {
        } finally {
        }
      (s = hh(t, n, u, a)),
        s !== null && ((u = Pt()), or(s, t, a, u), Dh(s, n, a));
    }
  }
  function Fh(t) {
    var n = t.alternate;
    return t === He || (n !== null && n === He);
  }
  function Nh(t, n) {
    is = Po = !0;
    var s = t.pending;
    s === null ? (n.next = n) : ((n.next = s.next), (s.next = n)),
      (t.pending = n);
  }
  function Dh(t, n, s) {
    if ((s & 4194240) !== 0) {
      var a = n.lanes;
      (a &= t.pendingLanes), (s |= a), (n.lanes = s), Ma(t, s);
    }
  }
  var ko = {
      readContext: Ht,
      useCallback: pt,
      useContext: pt,
      useEffect: pt,
      useImperativeHandle: pt,
      useInsertionEffect: pt,
      useLayoutEffect: pt,
      useMemo: pt,
      useReducer: pt,
      useRef: pt,
      useState: pt,
      useDebugValue: pt,
      useDeferredValue: pt,
      useTransition: pt,
      useMutableSource: pt,
      useSyncExternalStore: pt,
      useId: pt,
      unstable_isNewReconciler: !1,
    },
    t0 = {
      readContext: Ht,
      useCallback: function (t, n) {
        return (_r().memoizedState = [t, n === void 0 ? null : n]), t;
      },
      useContext: Ht,
      useEffect: Ch,
      useImperativeHandle: function (t, n, s) {
        return (
          (s = s != null ? s.concat([t]) : null),
          Ao(4194308, 4, bh.bind(null, n, t), s)
        );
      },
      useLayoutEffect: function (t, n) {
        return Ao(4194308, 4, t, n);
      },
      useInsertionEffect: function (t, n) {
        return Ao(4, 2, t, n);
      },
      useMemo: function (t, n) {
        var s = _r();
        return (
          (n = n === void 0 ? null : n),
          (t = t()),
          (s.memoizedState = [t, n]),
          t
        );
      },
      useReducer: function (t, n, s) {
        var a = _r();
        return (
          (n = s !== void 0 ? s(n) : n),
          (a.memoizedState = a.baseState = n),
          (t = {
            pending: null,
            interleaved: null,
            lanes: 0,
            dispatch: null,
            lastRenderedReducer: t,
            lastRenderedState: n,
          }),
          (a.queue = t),
          (t = t.dispatch = Zv.bind(null, He, t)),
          [a.memoizedState, t]
        );
      },
      useRef: function (t) {
        var n = _r();
        return (t = { current: t }), (n.memoizedState = t);
      },
      useState: Ph,
      useDebugValue: Tl,
      useDeferredValue: function (t) {
        return (_r().memoizedState = t);
      },
      useTransition: function () {
        var t = Ph(!1),
          n = t[0];
        return (t = Jv.bind(null, t[1])), (_r().memoizedState = t), [n, t];
      },
      useMutableSource: function () {},
      useSyncExternalStore: function (t, n, s) {
        var a = He,
          u = _r();
        if (je) {
          if (s === void 0) throw Error(i(407));
          s = s();
        } else {
          if (((s = n()), st === null)) throw Error(i(349));
          (bn & 30) !== 0 || _h(a, n, s);
        }
        u.memoizedState = s;
        var h = { value: s, getSnapshot: n };
        return (
          (u.queue = h),
          Ch(xh.bind(null, a, h, t), [t]),
          (a.flags |= 2048),
          as(9, wh.bind(null, a, h, s, n), void 0, null),
          s
        );
      },
      useId: function () {
        var t = _r(),
          n = st.identifierPrefix;
        if (je) {
          var s = Ir,
            a = Mr;
          (s = (a & ~(1 << (32 - er(a) - 1))).toString(32) + s),
            (n = ":" + n + "R" + s),
            (s = ss++),
            0 < s && (n += "H" + s.toString(32)),
            (n += ":");
        } else (s = Kv++), (n = ":" + n + "r" + s.toString(32) + ":");
        return (t.memoizedState = n);
      },
      unstable_isNewReconciler: !1,
    },
    r0 = {
      readContext: Ht,
      useCallback: Oh,
      useContext: Ht,
      useEffect: bl,
      useImperativeHandle: Th,
      useInsertionEffect: kh,
      useLayoutEffect: Rh,
      useMemo: Mh,
      useReducer: kl,
      useRef: Ah,
      useState: function () {
        return kl(os);
      },
      useDebugValue: Tl,
      useDeferredValue: function (t) {
        var n = qt();
        return Ih(n, Je.memoizedState, t);
      },
      useTransition: function () {
        var t = kl(os)[0],
          n = qt().memoizedState;
        return [t, n];
      },
      useMutableSource: gh,
      useSyncExternalStore: vh,
      useId: Lh,
      unstable_isNewReconciler: !1,
    },
    n0 = {
      readContext: Ht,
      useCallback: Oh,
      useContext: Ht,
      useEffect: bl,
      useImperativeHandle: Th,
      useInsertionEffect: kh,
      useLayoutEffect: Rh,
      useMemo: Mh,
      useReducer: Rl,
      useRef: Ah,
      useState: function () {
        return Rl(os);
      },
      useDebugValue: Tl,
      useDeferredValue: function (t) {
        var n = qt();
        return Je === null ? (n.memoizedState = t) : Ih(n, Je.memoizedState, t);
      },
      useTransition: function () {
        var t = Rl(os)[0],
          n = qt().memoizedState;
        return [t, n];
      },
      useMutableSource: gh,
      useSyncExternalStore: vh,
      useId: Lh,
      unstable_isNewReconciler: !1,
    };
  function nr(t, n) {
    if (t && t.defaultProps) {
      (n = X({}, n)), (t = t.defaultProps);
      for (var s in t) n[s] === void 0 && (n[s] = t[s]);
      return n;
    }
    return n;
  }
  function Ol(t, n, s, a) {
    (n = t.memoizedState),
      (s = s(a, n)),
      (s = s == null ? n : X({}, n, s)),
      (t.memoizedState = s),
      t.lanes === 0 && (t.updateQueue.baseState = s);
  }
  var Ro = {
    isMounted: function (t) {
      return (t = t._reactInternals) ? Zt(t) === t : !1;
    },
    enqueueSetState: function (t, n, s) {
      t = t._reactInternals;
      var a = Pt(),
        u = hn(t),
        h = Fr(a, u);
      (h.payload = n),
        s != null && (h.callback = s),
        (n = ln(t, h, u)),
        n !== null && (or(n, t, u, a), wo(n, t, u));
    },
    enqueueReplaceState: function (t, n, s) {
      t = t._reactInternals;
      var a = Pt(),
        u = hn(t),
        h = Fr(a, u);
      (h.tag = 1),
        (h.payload = n),
        s != null && (h.callback = s),
        (n = ln(t, h, u)),
        n !== null && (or(n, t, u, a), wo(n, t, u));
    },
    enqueueForceUpdate: function (t, n) {
      t = t._reactInternals;
      var s = Pt(),
        a = hn(t),
        u = Fr(s, a);
      (u.tag = 2),
        n != null && (u.callback = n),
        (n = ln(t, u, a)),
        n !== null && (or(n, t, a, s), wo(n, t, a));
    },
  };
  function Bh(t, n, s, a, u, h, y) {
    return (
      (t = t.stateNode),
      typeof t.shouldComponentUpdate == "function"
        ? t.shouldComponentUpdate(a, h, y)
        : n.prototype && n.prototype.isPureReactComponent
        ? !Wi(s, a) || !Wi(u, h)
        : !0
    );
  }
  function Uh(t, n, s) {
    var a = !1,
      u = sn,
      h = n.contextType;
    return (
      typeof h == "object" && h !== null
        ? (h = Ht(h))
        : ((u = bt(n) ? Pn : dt.current),
          (a = n.contextTypes),
          (h = (a = a != null) ? oi(t, u) : sn)),
      (n = new n(s, h)),
      (t.memoizedState =
        n.state !== null && n.state !== void 0 ? n.state : null),
      (n.updater = Ro),
      (t.stateNode = n),
      (n._reactInternals = t),
      a &&
        ((t = t.stateNode),
        (t.__reactInternalMemoizedUnmaskedChildContext = u),
        (t.__reactInternalMemoizedMaskedChildContext = h)),
      n
    );
  }
  function jh(t, n, s, a) {
    (t = n.state),
      typeof n.componentWillReceiveProps == "function" &&
        n.componentWillReceiveProps(s, a),
      typeof n.UNSAFE_componentWillReceiveProps == "function" &&
        n.UNSAFE_componentWillReceiveProps(s, a),
      n.state !== t && Ro.enqueueReplaceState(n, n.state, null);
  }
  function Ml(t, n, s, a) {
    var u = t.stateNode;
    (u.props = s), (u.state = t.memoizedState), (u.refs = {}), vl(t);
    var h = n.contextType;
    typeof h == "object" && h !== null
      ? (u.context = Ht(h))
      : ((h = bt(n) ? Pn : dt.current), (u.context = oi(t, h))),
      (u.state = t.memoizedState),
      (h = n.getDerivedStateFromProps),
      typeof h == "function" && (Ol(t, n, h, s), (u.state = t.memoizedState)),
      typeof n.getDerivedStateFromProps == "function" ||
        typeof u.getSnapshotBeforeUpdate == "function" ||
        (typeof u.UNSAFE_componentWillMount != "function" &&
          typeof u.componentWillMount != "function") ||
        ((n = u.state),
        typeof u.componentWillMount == "function" && u.componentWillMount(),
        typeof u.UNSAFE_componentWillMount == "function" &&
          u.UNSAFE_componentWillMount(),
        n !== u.state && Ro.enqueueReplaceState(u, u.state, null),
        xo(t, s, u, a),
        (u.state = t.memoizedState)),
      typeof u.componentDidMount == "function" && (t.flags |= 4194308);
  }
  function pi(t, n) {
    try {
      var s = "",
        a = n;
      do (s += W(a)), (a = a.return);
      while (a);
      var u = s;
    } catch (h) {
      u =
        `
Error generating stack: ` +
        h.message +
        `
` +
        h.stack;
    }
    return { value: t, source: n, stack: u, digest: null };
  }
  function Il(t, n, s) {
    return { value: t, source: null, stack: s ?? null, digest: n ?? null };
  }
  function Ll(t, n) {
    try {
      console.error(n.value);
    } catch (s) {
      setTimeout(function () {
        throw s;
      });
    }
  }
  var i0 = typeof WeakMap == "function" ? WeakMap : Map;
  function $h(t, n, s) {
    (s = Fr(-1, s)), (s.tag = 3), (s.payload = { element: null });
    var a = n.value;
    return (
      (s.callback = function () {
        Fo || ((Fo = !0), (Yl = a)), Ll(t, n);
      }),
      s
    );
  }
  function zh(t, n, s) {
    (s = Fr(-1, s)), (s.tag = 3);
    var a = t.type.getDerivedStateFromError;
    if (typeof a == "function") {
      var u = n.value;
      (s.payload = function () {
        return a(u);
      }),
        (s.callback = function () {
          Ll(t, n);
        });
    }
    var h = t.stateNode;
    return (
      h !== null &&
        typeof h.componentDidCatch == "function" &&
        (s.callback = function () {
          Ll(t, n),
            typeof a != "function" &&
              (cn === null ? (cn = new Set([this])) : cn.add(this));
          var y = n.stack;
          this.componentDidCatch(n.value, {
            componentStack: y !== null ? y : "",
          });
        }),
      s
    );
  }
  function Hh(t, n, s) {
    var a = t.pingCache;
    if (a === null) {
      a = t.pingCache = new i0();
      var u = new Set();
      a.set(n, u);
    } else (u = a.get(n)), u === void 0 && ((u = new Set()), a.set(n, u));
    u.has(s) || (u.add(s), (t = v0.bind(null, t, n, s)), n.then(t, t));
  }
  function qh(t) {
    do {
      var n;
      if (
        ((n = t.tag === 13) &&
          ((n = t.memoizedState),
          (n = n !== null ? n.dehydrated !== null : !0)),
        n)
      )
        return t;
      t = t.return;
    } while (t !== null);
    return null;
  }
  function Vh(t, n, s, a, u) {
    return (t.mode & 1) === 0
      ? (t === n
          ? (t.flags |= 65536)
          : ((t.flags |= 128),
            (s.flags |= 131072),
            (s.flags &= -52805),
            s.tag === 1 &&
              (s.alternate === null
                ? (s.tag = 17)
                : ((n = Fr(-1, 1)), (n.tag = 2), ln(s, n, 1))),
            (s.lanes |= 1)),
        t)
      : ((t.flags |= 65536), (t.lanes = u), t);
  }
  var s0 = U.ReactCurrentOwner,
    Tt = !1;
  function Et(t, n, s, a) {
    n.child = t === null ? fh(n, null, s, a) : ci(n, t.child, s, a);
  }
  function Gh(t, n, s, a, u) {
    s = s.render;
    var h = n.ref;
    return (
      hi(n, u),
      (a = Al(t, n, s, a, h, u)),
      (s = Cl()),
      t !== null && !Tt
        ? ((n.updateQueue = t.updateQueue),
          (n.flags &= -2053),
          (t.lanes &= ~u),
          Nr(t, n, u))
        : (je && s && ll(n), (n.flags |= 1), Et(t, n, a, u), n.child)
    );
  }
  function Wh(t, n, s, a, u) {
    if (t === null) {
      var h = s.type;
      return typeof h == "function" &&
        !ru(h) &&
        h.defaultProps === void 0 &&
        s.compare === null &&
        s.defaultProps === void 0
        ? ((n.tag = 15), (n.type = h), Xh(t, n, h, a, u))
        : ((t = $o(s.type, null, a, n, n.mode, u)),
          (t.ref = n.ref),
          (t.return = n),
          (n.child = t));
    }
    if (((h = t.child), (t.lanes & u) === 0)) {
      var y = h.memoizedProps;
      if (
        ((s = s.compare), (s = s !== null ? s : Wi), s(y, a) && t.ref === n.ref)
      )
        return Nr(t, n, u);
    }
    return (
      (n.flags |= 1),
      (t = pn(h, a)),
      (t.ref = n.ref),
      (t.return = n),
      (n.child = t)
    );
  }
  function Xh(t, n, s, a, u) {
    if (t !== null) {
      var h = t.memoizedProps;
      if (Wi(h, a) && t.ref === n.ref)
        if (((Tt = !1), (n.pendingProps = a = h), (t.lanes & u) !== 0))
          (t.flags & 131072) !== 0 && (Tt = !0);
        else return (n.lanes = t.lanes), Nr(t, n, u);
    }
    return Fl(t, n, s, a, u);
  }
  function Yh(t, n, s) {
    var a = n.pendingProps,
      u = a.children,
      h = t !== null ? t.memoizedState : null;
    if (a.mode === "hidden")
      if ((n.mode & 1) === 0)
        (n.memoizedState = {
          baseLanes: 0,
          cachePool: null,
          transitions: null,
        }),
          Ne(yi, Ut),
          (Ut |= s);
      else {
        if ((s & 1073741824) === 0)
          return (
            (t = h !== null ? h.baseLanes | s : s),
            (n.lanes = n.childLanes = 1073741824),
            (n.memoizedState = {
              baseLanes: t,
              cachePool: null,
              transitions: null,
            }),
            (n.updateQueue = null),
            Ne(yi, Ut),
            (Ut |= t),
            null
          );
        (n.memoizedState = {
          baseLanes: 0,
          cachePool: null,
          transitions: null,
        }),
          (a = h !== null ? h.baseLanes : s),
          Ne(yi, Ut),
          (Ut |= a);
      }
    else
      h !== null ? ((a = h.baseLanes | s), (n.memoizedState = null)) : (a = s),
        Ne(yi, Ut),
        (Ut |= a);
    return Et(t, n, u, s), n.child;
  }
  function Qh(t, n) {
    var s = n.ref;
    ((t === null && s !== null) || (t !== null && t.ref !== s)) &&
      ((n.flags |= 512), (n.flags |= 2097152));
  }
  function Fl(t, n, s, a, u) {
    var h = bt(s) ? Pn : dt.current;
    return (
      (h = oi(n, h)),
      hi(n, u),
      (s = Al(t, n, s, a, h, u)),
      (a = Cl()),
      t !== null && !Tt
        ? ((n.updateQueue = t.updateQueue),
          (n.flags &= -2053),
          (t.lanes &= ~u),
          Nr(t, n, u))
        : (je && a && ll(n), (n.flags |= 1), Et(t, n, s, u), n.child)
    );
  }
  function Kh(t, n, s, a, u) {
    if (bt(s)) {
      var h = !0;
      fo(n);
    } else h = !1;
    if ((hi(n, u), n.stateNode === null))
      To(t, n), Uh(n, s, a), Ml(n, s, a, u), (a = !0);
    else if (t === null) {
      var y = n.stateNode,
        S = n.memoizedProps;
      y.props = S;
      var P = y.context,
        I = s.contextType;
      typeof I == "object" && I !== null
        ? (I = Ht(I))
        : ((I = bt(s) ? Pn : dt.current), (I = oi(n, I)));
      var $ = s.getDerivedStateFromProps,
        q =
          typeof $ == "function" ||
          typeof y.getSnapshotBeforeUpdate == "function";
      q ||
        (typeof y.UNSAFE_componentWillReceiveProps != "function" &&
          typeof y.componentWillReceiveProps != "function") ||
        ((S !== a || P !== I) && jh(n, y, a, I)),
        (an = !1);
      var j = n.memoizedState;
      (y.state = j),
        xo(n, a, y, u),
        (P = n.memoizedState),
        S !== a || j !== P || Rt.current || an
          ? (typeof $ == "function" && (Ol(n, s, $, a), (P = n.memoizedState)),
            (S = an || Bh(n, s, S, a, j, P, I))
              ? (q ||
                  (typeof y.UNSAFE_componentWillMount != "function" &&
                    typeof y.componentWillMount != "function") ||
                  (typeof y.componentWillMount == "function" &&
                    y.componentWillMount(),
                  typeof y.UNSAFE_componentWillMount == "function" &&
                    y.UNSAFE_componentWillMount()),
                typeof y.componentDidMount == "function" &&
                  (n.flags |= 4194308))
              : (typeof y.componentDidMount == "function" &&
                  (n.flags |= 4194308),
                (n.memoizedProps = a),
                (n.memoizedState = P)),
            (y.props = a),
            (y.state = P),
            (y.context = I),
            (a = S))
          : (typeof y.componentDidMount == "function" && (n.flags |= 4194308),
            (a = !1));
    } else {
      (y = n.stateNode),
        dh(t, n),
        (S = n.memoizedProps),
        (I = n.type === n.elementType ? S : nr(n.type, S)),
        (y.props = I),
        (q = n.pendingProps),
        (j = y.context),
        (P = s.contextType),
        typeof P == "object" && P !== null
          ? (P = Ht(P))
          : ((P = bt(s) ? Pn : dt.current), (P = oi(n, P)));
      var K = s.getDerivedStateFromProps;
      ($ =
        typeof K == "function" ||
        typeof y.getSnapshotBeforeUpdate == "function") ||
        (typeof y.UNSAFE_componentWillReceiveProps != "function" &&
          typeof y.componentWillReceiveProps != "function") ||
        ((S !== q || j !== P) && jh(n, y, a, P)),
        (an = !1),
        (j = n.memoizedState),
        (y.state = j),
        xo(n, a, y, u);
      var ie = n.memoizedState;
      S !== q || j !== ie || Rt.current || an
        ? (typeof K == "function" && (Ol(n, s, K, a), (ie = n.memoizedState)),
          (I = an || Bh(n, s, I, a, j, ie, P) || !1)
            ? ($ ||
                (typeof y.UNSAFE_componentWillUpdate != "function" &&
                  typeof y.componentWillUpdate != "function") ||
                (typeof y.componentWillUpdate == "function" &&
                  y.componentWillUpdate(a, ie, P),
                typeof y.UNSAFE_componentWillUpdate == "function" &&
                  y.UNSAFE_componentWillUpdate(a, ie, P)),
              typeof y.componentDidUpdate == "function" && (n.flags |= 4),
              typeof y.getSnapshotBeforeUpdate == "function" &&
                (n.flags |= 1024))
            : (typeof y.componentDidUpdate != "function" ||
                (S === t.memoizedProps && j === t.memoizedState) ||
                (n.flags |= 4),
              typeof y.getSnapshotBeforeUpdate != "function" ||
                (S === t.memoizedProps && j === t.memoizedState) ||
                (n.flags |= 1024),
              (n.memoizedProps = a),
              (n.memoizedState = ie)),
          (y.props = a),
          (y.state = ie),
          (y.context = P),
          (a = I))
        : (typeof y.componentDidUpdate != "function" ||
            (S === t.memoizedProps && j === t.memoizedState) ||
            (n.flags |= 4),
          typeof y.getSnapshotBeforeUpdate != "function" ||
            (S === t.memoizedProps && j === t.memoizedState) ||
            (n.flags |= 1024),
          (a = !1));
    }
    return Nl(t, n, s, a, h, u);
  }
  function Nl(t, n, s, a, u, h) {
    Qh(t, n);
    var y = (n.flags & 128) !== 0;
    if (!a && !y) return u && rh(n, s, !1), Nr(t, n, h);
    (a = n.stateNode), (s0.current = n);
    var S =
      y && typeof s.getDerivedStateFromError != "function" ? null : a.render();
    return (
      (n.flags |= 1),
      t !== null && y
        ? ((n.child = ci(n, t.child, null, h)), (n.child = ci(n, null, S, h)))
        : Et(t, n, S, h),
      (n.memoizedState = a.state),
      u && rh(n, s, !0),
      n.child
    );
  }
  function Jh(t) {
    var n = t.stateNode;
    n.pendingContext
      ? eh(t, n.pendingContext, n.pendingContext !== n.context)
      : n.context && eh(t, n.context, !1),
      _l(t, n.containerInfo);
  }
  function Zh(t, n, s, a, u) {
    return ui(), hl(u), (n.flags |= 256), Et(t, n, s, a), n.child;
  }
  var Dl = { dehydrated: null, treeContext: null, retryLane: 0 };
  function Bl(t) {
    return { baseLanes: t, cachePool: null, transitions: null };
  }
  function ed(t, n, s) {
    var a = n.pendingProps,
      u = ze.current,
      h = !1,
      y = (n.flags & 128) !== 0,
      S;
    if (
      ((S = y) ||
        (S = t !== null && t.memoizedState === null ? !1 : (u & 2) !== 0),
      S
        ? ((h = !0), (n.flags &= -129))
        : (t === null || t.memoizedState !== null) && (u |= 1),
      Ne(ze, u & 1),
      t === null)
    )
      return (
        fl(n),
        (t = n.memoizedState),
        t !== null && ((t = t.dehydrated), t !== null)
          ? ((n.mode & 1) === 0
              ? (n.lanes = 1)
              : t.data === "$!"
              ? (n.lanes = 8)
              : (n.lanes = 1073741824),
            null)
          : ((y = a.children),
            (t = a.fallback),
            h
              ? ((a = n.mode),
                (h = n.child),
                (y = { mode: "hidden", children: y }),
                (a & 1) === 0 && h !== null
                  ? ((h.childLanes = 0), (h.pendingProps = y))
                  : (h = zo(y, a, 0, null)),
                (t = Ln(t, a, s, null)),
                (h.return = n),
                (t.return = n),
                (h.sibling = t),
                (n.child = h),
                (n.child.memoizedState = Bl(s)),
                (n.memoizedState = Dl),
                t)
              : Ul(n, y))
      );
    if (((u = t.memoizedState), u !== null && ((S = u.dehydrated), S !== null)))
      return o0(t, n, y, a, S, u, s);
    if (h) {
      (h = a.fallback), (y = n.mode), (u = t.child), (S = u.sibling);
      var P = { mode: "hidden", children: a.children };
      return (
        (y & 1) === 0 && n.child !== u
          ? ((a = n.child),
            (a.childLanes = 0),
            (a.pendingProps = P),
            (n.deletions = null))
          : ((a = pn(u, P)), (a.subtreeFlags = u.subtreeFlags & 14680064)),
        S !== null ? (h = pn(S, h)) : ((h = Ln(h, y, s, null)), (h.flags |= 2)),
        (h.return = n),
        (a.return = n),
        (a.sibling = h),
        (n.child = a),
        (a = h),
        (h = n.child),
        (y = t.child.memoizedState),
        (y =
          y === null
            ? Bl(s)
            : {
                baseLanes: y.baseLanes | s,
                cachePool: null,
                transitions: y.transitions,
              }),
        (h.memoizedState = y),
        (h.childLanes = t.childLanes & ~s),
        (n.memoizedState = Dl),
        a
      );
    }
    return (
      (h = t.child),
      (t = h.sibling),
      (a = pn(h, { mode: "visible", children: a.children })),
      (n.mode & 1) === 0 && (a.lanes = s),
      (a.return = n),
      (a.sibling = null),
      t !== null &&
        ((s = n.deletions),
        s === null ? ((n.deletions = [t]), (n.flags |= 16)) : s.push(t)),
      (n.child = a),
      (n.memoizedState = null),
      a
    );
  }
  function Ul(t, n) {
    return (
      (n = zo({ mode: "visible", children: n }, t.mode, 0, null)),
      (n.return = t),
      (t.child = n)
    );
  }
  function bo(t, n, s, a) {
    return (
      a !== null && hl(a),
      ci(n, t.child, null, s),
      (t = Ul(n, n.pendingProps.children)),
      (t.flags |= 2),
      (n.memoizedState = null),
      t
    );
  }
  function o0(t, n, s, a, u, h, y) {
    if (s)
      return n.flags & 256
        ? ((n.flags &= -257), (a = Il(Error(i(422)))), bo(t, n, y, a))
        : n.memoizedState !== null
        ? ((n.child = t.child), (n.flags |= 128), null)
        : ((h = a.fallback),
          (u = n.mode),
          (a = zo({ mode: "visible", children: a.children }, u, 0, null)),
          (h = Ln(h, u, y, null)),
          (h.flags |= 2),
          (a.return = n),
          (h.return = n),
          (a.sibling = h),
          (n.child = a),
          (n.mode & 1) !== 0 && ci(n, t.child, null, y),
          (n.child.memoizedState = Bl(y)),
          (n.memoizedState = Dl),
          h);
    if ((n.mode & 1) === 0) return bo(t, n, y, null);
    if (u.data === "$!") {
      if (((a = u.nextSibling && u.nextSibling.dataset), a)) var S = a.dgst;
      return (
        (a = S), (h = Error(i(419))), (a = Il(h, a, void 0)), bo(t, n, y, a)
      );
    }
    if (((S = (y & t.childLanes) !== 0), Tt || S)) {
      if (((a = st), a !== null)) {
        switch (y & -y) {
          case 4:
            u = 2;
            break;
          case 16:
            u = 8;
            break;
          case 64:
          case 128:
          case 256:
          case 512:
          case 1024:
          case 2048:
          case 4096:
          case 8192:
          case 16384:
          case 32768:
          case 65536:
          case 131072:
          case 262144:
          case 524288:
          case 1048576:
          case 2097152:
          case 4194304:
          case 8388608:
          case 16777216:
          case 33554432:
          case 67108864:
            u = 32;
            break;
          case 536870912:
            u = 268435456;
            break;
          default:
            u = 0;
        }
        (u = (u & (a.suspendedLanes | y)) !== 0 ? 0 : u),
          u !== 0 &&
            u !== h.retryLane &&
            ((h.retryLane = u), Lr(t, u), or(a, t, u, -1));
      }
      return tu(), (a = Il(Error(i(421)))), bo(t, n, y, a);
    }
    return u.data === "$?"
      ? ((n.flags |= 128),
        (n.child = t.child),
        (n = _0.bind(null, t)),
        (u._reactRetry = n),
        null)
      : ((t = h.treeContext),
        (Bt = rn(u.nextSibling)),
        (Dt = n),
        (je = !0),
        (rr = null),
        t !== null &&
          (($t[zt++] = Mr),
          ($t[zt++] = Ir),
          ($t[zt++] = An),
          (Mr = t.id),
          (Ir = t.overflow),
          (An = n)),
        (n = Ul(n, a.children)),
        (n.flags |= 4096),
        n);
  }
  function td(t, n, s) {
    t.lanes |= n;
    var a = t.alternate;
    a !== null && (a.lanes |= n), yl(t.return, n, s);
  }
  function jl(t, n, s, a, u) {
    var h = t.memoizedState;
    h === null
      ? (t.memoizedState = {
          isBackwards: n,
          rendering: null,
          renderingStartTime: 0,
          last: a,
          tail: s,
          tailMode: u,
        })
      : ((h.isBackwards = n),
        (h.rendering = null),
        (h.renderingStartTime = 0),
        (h.last = a),
        (h.tail = s),
        (h.tailMode = u));
  }
  function rd(t, n, s) {
    var a = n.pendingProps,
      u = a.revealOrder,
      h = a.tail;
    if ((Et(t, n, a.children, s), (a = ze.current), (a & 2) !== 0))
      (a = (a & 1) | 2), (n.flags |= 128);
    else {
      if (t !== null && (t.flags & 128) !== 0)
        e: for (t = n.child; t !== null; ) {
          if (t.tag === 13) t.memoizedState !== null && td(t, s, n);
          else if (t.tag === 19) td(t, s, n);
          else if (t.child !== null) {
            (t.child.return = t), (t = t.child);
            continue;
          }
          if (t === n) break e;
          for (; t.sibling === null; ) {
            if (t.return === null || t.return === n) break e;
            t = t.return;
          }
          (t.sibling.return = t.return), (t = t.sibling);
        }
      a &= 1;
    }
    if ((Ne(ze, a), (n.mode & 1) === 0)) n.memoizedState = null;
    else
      switch (u) {
        case "forwards":
          for (s = n.child, u = null; s !== null; )
            (t = s.alternate),
              t !== null && So(t) === null && (u = s),
              (s = s.sibling);
          (s = u),
            s === null
              ? ((u = n.child), (n.child = null))
              : ((u = s.sibling), (s.sibling = null)),
            jl(n, !1, u, s, h);
          break;
        case "backwards":
          for (s = null, u = n.child, n.child = null; u !== null; ) {
            if (((t = u.alternate), t !== null && So(t) === null)) {
              n.child = u;
              break;
            }
            (t = u.sibling), (u.sibling = s), (s = u), (u = t);
          }
          jl(n, !0, s, null, h);
          break;
        case "together":
          jl(n, !1, null, null, void 0);
          break;
        default:
          n.memoizedState = null;
      }
    return n.child;
  }
  function To(t, n) {
    (n.mode & 1) === 0 &&
      t !== null &&
      ((t.alternate = null), (n.alternate = null), (n.flags |= 2));
  }
  function Nr(t, n, s) {
    if (
      (t !== null && (n.dependencies = t.dependencies),
      (Tn |= n.lanes),
      (s & n.childLanes) === 0)
    )
      return null;
    if (t !== null && n.child !== t.child) throw Error(i(153));
    if (n.child !== null) {
      for (
        t = n.child, s = pn(t, t.pendingProps), n.child = s, s.return = n;
        t.sibling !== null;

      )
        (t = t.sibling),
          (s = s.sibling = pn(t, t.pendingProps)),
          (s.return = n);
      s.sibling = null;
    }
    return n.child;
  }
  function a0(t, n, s) {
    switch (n.tag) {
      case 3:
        Jh(n), ui();
        break;
      case 5:
        yh(n);
        break;
      case 1:
        bt(n.type) && fo(n);
        break;
      case 4:
        _l(n, n.stateNode.containerInfo);
        break;
      case 10:
        var a = n.type._context,
          u = n.memoizedProps.value;
        Ne(vo, a._currentValue), (a._currentValue = u);
        break;
      case 13:
        if (((a = n.memoizedState), a !== null))
          return a.dehydrated !== null
            ? (Ne(ze, ze.current & 1), (n.flags |= 128), null)
            : (s & n.child.childLanes) !== 0
            ? ed(t, n, s)
            : (Ne(ze, ze.current & 1),
              (t = Nr(t, n, s)),
              t !== null ? t.sibling : null);
        Ne(ze, ze.current & 1);
        break;
      case 19:
        if (((a = (s & n.childLanes) !== 0), (t.flags & 128) !== 0)) {
          if (a) return rd(t, n, s);
          n.flags |= 128;
        }
        if (
          ((u = n.memoizedState),
          u !== null &&
            ((u.rendering = null), (u.tail = null), (u.lastEffect = null)),
          Ne(ze, ze.current),
          a)
        )
          break;
        return null;
      case 22:
      case 23:
        return (n.lanes = 0), Yh(t, n, s);
    }
    return Nr(t, n, s);
  }
  var nd, $l, id, sd;
  (nd = function (t, n) {
    for (var s = n.child; s !== null; ) {
      if (s.tag === 5 || s.tag === 6) t.appendChild(s.stateNode);
      else if (s.tag !== 4 && s.child !== null) {
        (s.child.return = s), (s = s.child);
        continue;
      }
      if (s === n) break;
      for (; s.sibling === null; ) {
        if (s.return === null || s.return === n) return;
        s = s.return;
      }
      (s.sibling.return = s.return), (s = s.sibling);
    }
  }),
    ($l = function () {}),
    (id = function (t, n, s, a) {
      var u = t.memoizedProps;
      if (u !== a) {
        (t = n.stateNode), Rn(vr.current);
        var h = null;
        switch (s) {
          case "input":
            (u = Ye(t, u)), (a = Ye(t, a)), (h = []);
            break;
          case "select":
            (u = X({}, u, { value: void 0 })),
              (a = X({}, a, { value: void 0 })),
              (h = []);
            break;
          case "textarea":
            (u = dr(t, u)), (a = dr(t, a)), (h = []);
            break;
          default:
            typeof u.onClick != "function" &&
              typeof a.onClick == "function" &&
              (t.onclick = lo);
        }
        M(s, a);
        var y;
        s = null;
        for (I in u)
          if (!a.hasOwnProperty(I) && u.hasOwnProperty(I) && u[I] != null)
            if (I === "style") {
              var S = u[I];
              for (y in S) S.hasOwnProperty(y) && (s || (s = {}), (s[y] = ""));
            } else
              I !== "dangerouslySetInnerHTML" &&
                I !== "children" &&
                I !== "suppressContentEditableWarning" &&
                I !== "suppressHydrationWarning" &&
                I !== "autoFocus" &&
                (l.hasOwnProperty(I)
                  ? h || (h = [])
                  : (h = h || []).push(I, null));
        for (I in a) {
          var P = a[I];
          if (
            ((S = u?.[I]),
            a.hasOwnProperty(I) && P !== S && (P != null || S != null))
          )
            if (I === "style")
              if (S) {
                for (y in S)
                  !S.hasOwnProperty(y) ||
                    (P && P.hasOwnProperty(y)) ||
                    (s || (s = {}), (s[y] = ""));
                for (y in P)
                  P.hasOwnProperty(y) &&
                    S[y] !== P[y] &&
                    (s || (s = {}), (s[y] = P[y]));
              } else s || (h || (h = []), h.push(I, s)), (s = P);
            else
              I === "dangerouslySetInnerHTML"
                ? ((P = P ? P.__html : void 0),
                  (S = S ? S.__html : void 0),
                  P != null && S !== P && (h = h || []).push(I, P))
                : I === "children"
                ? (typeof P != "string" && typeof P != "number") ||
                  (h = h || []).push(I, "" + P)
                : I !== "suppressContentEditableWarning" &&
                  I !== "suppressHydrationWarning" &&
                  (l.hasOwnProperty(I)
                    ? (P != null && I === "onScroll" && De("scroll", t),
                      h || S === P || (h = []))
                    : (h = h || []).push(I, P));
        }
        s && (h = h || []).push("style", s);
        var I = h;
        (n.updateQueue = I) && (n.flags |= 4);
      }
    }),
    (sd = function (t, n, s, a) {
      s !== a && (n.flags |= 4);
    });
  function ls(t, n) {
    if (!je)
      switch (t.tailMode) {
        case "hidden":
          n = t.tail;
          for (var s = null; n !== null; )
            n.alternate !== null && (s = n), (n = n.sibling);
          s === null ? (t.tail = null) : (s.sibling = null);
          break;
        case "collapsed":
          s = t.tail;
          for (var a = null; s !== null; )
            s.alternate !== null && (a = s), (s = s.sibling);
          a === null
            ? n || t.tail === null
              ? (t.tail = null)
              : (t.tail.sibling = null)
            : (a.sibling = null);
      }
  }
  function mt(t) {
    var n = t.alternate !== null && t.alternate.child === t.child,
      s = 0,
      a = 0;
    if (n)
      for (var u = t.child; u !== null; )
        (s |= u.lanes | u.childLanes),
          (a |= u.subtreeFlags & 14680064),
          (a |= u.flags & 14680064),
          (u.return = t),
          (u = u.sibling);
    else
      for (u = t.child; u !== null; )
        (s |= u.lanes | u.childLanes),
          (a |= u.subtreeFlags),
          (a |= u.flags),
          (u.return = t),
          (u = u.sibling);
    return (t.subtreeFlags |= a), (t.childLanes = s), n;
  }
  function l0(t, n, s) {
    var a = n.pendingProps;
    switch ((ul(n), n.tag)) {
      case 2:
      case 16:
      case 15:
      case 0:
      case 11:
      case 7:
      case 8:
      case 12:
      case 9:
      case 14:
        return mt(n), null;
      case 1:
        return bt(n.type) && co(), mt(n), null;
      case 3:
        return (
          (a = n.stateNode),
          di(),
          Be(Rt),
          Be(dt),
          Sl(),
          a.pendingContext &&
            ((a.context = a.pendingContext), (a.pendingContext = null)),
          (t === null || t.child === null) &&
            (yo(n)
              ? (n.flags |= 4)
              : t === null ||
                (t.memoizedState.isDehydrated && (n.flags & 256) === 0) ||
                ((n.flags |= 1024), rr !== null && (Jl(rr), (rr = null)))),
          $l(t, n),
          mt(n),
          null
        );
      case 5:
        wl(n);
        var u = Rn(ns.current);
        if (((s = n.type), t !== null && n.stateNode != null))
          id(t, n, s, a, u),
            t.ref !== n.ref && ((n.flags |= 512), (n.flags |= 2097152));
        else {
          if (!a) {
            if (n.stateNode === null) throw Error(i(166));
            return mt(n), null;
          }
          if (((t = Rn(vr.current)), yo(n))) {
            (a = n.stateNode), (s = n.type);
            var h = n.memoizedProps;
            switch (((a[gr] = n), (a[Ji] = h), (t = (n.mode & 1) !== 0), s)) {
              case "dialog":
                De("cancel", a), De("close", a);
                break;
              case "iframe":
              case "object":
              case "embed":
                De("load", a);
                break;
              case "video":
              case "audio":
                for (u = 0; u < Yi.length; u++) De(Yi[u], a);
                break;
              case "source":
                De("error", a);
                break;
              case "img":
              case "image":
              case "link":
                De("error", a), De("load", a);
                break;
              case "details":
                De("toggle", a);
                break;
              case "input":
                _t(a, h), De("invalid", a);
                break;
              case "select":
                (a._wrapperState = { wasMultiple: !!h.multiple }),
                  De("invalid", a);
                break;
              case "textarea":
                Ar(a, h), De("invalid", a);
            }
            M(s, h), (u = null);
            for (var y in h)
              if (h.hasOwnProperty(y)) {
                var S = h[y];
                y === "children"
                  ? typeof S == "string"
                    ? a.textContent !== S &&
                      (h.suppressHydrationWarning !== !0 &&
                        ao(a.textContent, S, t),
                      (u = ["children", S]))
                    : typeof S == "number" &&
                      a.textContent !== "" + S &&
                      (h.suppressHydrationWarning !== !0 &&
                        ao(a.textContent, S, t),
                      (u = ["children", "" + S]))
                  : l.hasOwnProperty(y) &&
                    S != null &&
                    y === "onScroll" &&
                    De("scroll", a);
              }
            switch (s) {
              case "input":
                ve(a), wt(a, h, !0);
                break;
              case "textarea":
                ve(a), Ns(a);
                break;
              case "select":
              case "option":
                break;
              default:
                typeof h.onClick == "function" && (a.onclick = lo);
            }
            (a = u), (n.updateQueue = a), a !== null && (n.flags |= 4);
          } else {
            (y = u.nodeType === 9 ? u : u.ownerDocument),
              t === "http://www.w3.org/1999/xhtml" && (t = Ds(s)),
              t === "http://www.w3.org/1999/xhtml"
                ? s === "script"
                  ? ((t = y.createElement("div")),
                    (t.innerHTML = "<script></script>"),
                    (t = t.removeChild(t.firstChild)))
                  : typeof a.is == "string"
                  ? (t = y.createElement(s, { is: a.is }))
                  : ((t = y.createElement(s)),
                    s === "select" &&
                      ((y = t),
                      a.multiple
                        ? (y.multiple = !0)
                        : a.size && (y.size = a.size)))
                : (t = y.createElementNS(t, s)),
              (t[gr] = n),
              (t[Ji] = a),
              nd(t, n, !1, !1),
              (n.stateNode = t);
            e: {
              switch (((y = L(s, a)), s)) {
                case "dialog":
                  De("cancel", t), De("close", t), (u = a);
                  break;
                case "iframe":
                case "object":
                case "embed":
                  De("load", t), (u = a);
                  break;
                case "video":
                case "audio":
                  for (u = 0; u < Yi.length; u++) De(Yi[u], t);
                  u = a;
                  break;
                case "source":
                  De("error", t), (u = a);
                  break;
                case "img":
                case "image":
                case "link":
                  De("error", t), De("load", t), (u = a);
                  break;
                case "details":
                  De("toggle", t), (u = a);
                  break;
                case "input":
                  _t(t, a), (u = Ye(t, a)), De("invalid", t);
                  break;
                case "option":
                  u = a;
                  break;
                case "select":
                  (t._wrapperState = { wasMultiple: !!a.multiple }),
                    (u = X({}, a, { value: void 0 })),
                    De("invalid", t);
                  break;
                case "textarea":
                  Ar(t, a), (u = dr(t, a)), De("invalid", t);
                  break;
                default:
                  u = a;
              }
              M(s, u), (S = u);
              for (h in S)
                if (S.hasOwnProperty(h)) {
                  var P = S[h];
                  h === "style"
                    ? Gn(t, P)
                    : h === "dangerouslySetInnerHTML"
                    ? ((P = P ? P.__html : void 0), P != null && Vr(t, P))
                    : h === "children"
                    ? typeof P == "string"
                      ? (s !== "textarea" || P !== "") && kr(t, P)
                      : typeof P == "number" && kr(t, "" + P)
                    : h !== "suppressContentEditableWarning" &&
                      h !== "suppressHydrationWarning" &&
                      h !== "autoFocus" &&
                      (l.hasOwnProperty(h)
                        ? P != null && h === "onScroll" && De("scroll", t)
                        : P != null && N(t, h, P, y));
                }
              switch (s) {
                case "input":
                  ve(t), wt(t, a, !1);
                  break;
                case "textarea":
                  ve(t), Ns(t);
                  break;
                case "option":
                  a.value != null && t.setAttribute("value", "" + ue(a.value));
                  break;
                case "select":
                  (t.multiple = !!a.multiple),
                    (h = a.value),
                    h != null
                      ? nt(t, !!a.multiple, h, !1)
                      : a.defaultValue != null &&
                        nt(t, !!a.multiple, a.defaultValue, !0);
                  break;
                default:
                  typeof u.onClick == "function" && (t.onclick = lo);
              }
              switch (s) {
                case "button":
                case "input":
                case "select":
                case "textarea":
                  a = !!a.autoFocus;
                  break e;
                case "img":
                  a = !0;
                  break e;
                default:
                  a = !1;
              }
            }
            a && (n.flags |= 4);
          }
          n.ref !== null && ((n.flags |= 512), (n.flags |= 2097152));
        }
        return mt(n), null;
      case 6:
        if (t && n.stateNode != null) sd(t, n, t.memoizedProps, a);
        else {
          if (typeof a != "string" && n.stateNode === null) throw Error(i(166));
          if (((s = Rn(ns.current)), Rn(vr.current), yo(n))) {
            if (
              ((a = n.stateNode),
              (s = n.memoizedProps),
              (a[gr] = n),
              (h = a.nodeValue !== s) && ((t = Dt), t !== null))
            )
              switch (t.tag) {
                case 3:
                  ao(a.nodeValue, s, (t.mode & 1) !== 0);
                  break;
                case 5:
                  t.memoizedProps.suppressHydrationWarning !== !0 &&
                    ao(a.nodeValue, s, (t.mode & 1) !== 0);
              }
            h && (n.flags |= 4);
          } else
            (a = (s.nodeType === 9 ? s : s.ownerDocument).createTextNode(a)),
              (a[gr] = n),
              (n.stateNode = a);
        }
        return mt(n), null;
      case 13:
        if (
          (Be(ze),
          (a = n.memoizedState),
          t === null ||
            (t.memoizedState !== null && t.memoizedState.dehydrated !== null))
        ) {
          if (je && Bt !== null && (n.mode & 1) !== 0 && (n.flags & 128) === 0)
            lh(), ui(), (n.flags |= 98560), (h = !1);
          else if (((h = yo(n)), a !== null && a.dehydrated !== null)) {
            if (t === null) {
              if (!h) throw Error(i(318));
              if (
                ((h = n.memoizedState),
                (h = h !== null ? h.dehydrated : null),
                !h)
              )
                throw Error(i(317));
              h[gr] = n;
            } else
              ui(),
                (n.flags & 128) === 0 && (n.memoizedState = null),
                (n.flags |= 4);
            mt(n), (h = !1);
          } else rr !== null && (Jl(rr), (rr = null)), (h = !0);
          if (!h) return n.flags & 65536 ? n : null;
        }
        return (n.flags & 128) !== 0
          ? ((n.lanes = s), n)
          : ((a = a !== null),
            a !== (t !== null && t.memoizedState !== null) &&
              a &&
              ((n.child.flags |= 8192),
              (n.mode & 1) !== 0 &&
                (t === null || (ze.current & 1) !== 0
                  ? Ze === 0 && (Ze = 3)
                  : tu())),
            n.updateQueue !== null && (n.flags |= 4),
            mt(n),
            null);
      case 4:
        return (
          di(),
          $l(t, n),
          t === null && Qi(n.stateNode.containerInfo),
          mt(n),
          null
        );
      case 10:
        return ml(n.type._context), mt(n), null;
      case 17:
        return bt(n.type) && co(), mt(n), null;
      case 19:
        if ((Be(ze), (h = n.memoizedState), h === null)) return mt(n), null;
        if (((a = (n.flags & 128) !== 0), (y = h.rendering), y === null))
          if (a) ls(h, !1);
          else {
            if (Ze !== 0 || (t !== null && (t.flags & 128) !== 0))
              for (t = n.child; t !== null; ) {
                if (((y = So(t)), y !== null)) {
                  for (
                    n.flags |= 128,
                      ls(h, !1),
                      a = y.updateQueue,
                      a !== null && ((n.updateQueue = a), (n.flags |= 4)),
                      n.subtreeFlags = 0,
                      a = s,
                      s = n.child;
                    s !== null;

                  )
                    (h = s),
                      (t = a),
                      (h.flags &= 14680066),
                      (y = h.alternate),
                      y === null
                        ? ((h.childLanes = 0),
                          (h.lanes = t),
                          (h.child = null),
                          (h.subtreeFlags = 0),
                          (h.memoizedProps = null),
                          (h.memoizedState = null),
                          (h.updateQueue = null),
                          (h.dependencies = null),
                          (h.stateNode = null))
                        : ((h.childLanes = y.childLanes),
                          (h.lanes = y.lanes),
                          (h.child = y.child),
                          (h.subtreeFlags = 0),
                          (h.deletions = null),
                          (h.memoizedProps = y.memoizedProps),
                          (h.memoizedState = y.memoizedState),
                          (h.updateQueue = y.updateQueue),
                          (h.type = y.type),
                          (t = y.dependencies),
                          (h.dependencies =
                            t === null
                              ? null
                              : {
                                  lanes: t.lanes,
                                  firstContext: t.firstContext,
                                })),
                      (s = s.sibling);
                  return Ne(ze, (ze.current & 1) | 2), n.child;
                }
                t = t.sibling;
              }
            h.tail !== null &&
              We() > gi &&
              ((n.flags |= 128), (a = !0), ls(h, !1), (n.lanes = 4194304));
          }
        else {
          if (!a)
            if (((t = So(y)), t !== null)) {
              if (
                ((n.flags |= 128),
                (a = !0),
                (s = t.updateQueue),
                s !== null && ((n.updateQueue = s), (n.flags |= 4)),
                ls(h, !0),
                h.tail === null &&
                  h.tailMode === "hidden" &&
                  !y.alternate &&
                  !je)
              )
                return mt(n), null;
            } else
              2 * We() - h.renderingStartTime > gi &&
                s !== 1073741824 &&
                ((n.flags |= 128), (a = !0), ls(h, !1), (n.lanes = 4194304));
          h.isBackwards
            ? ((y.sibling = n.child), (n.child = y))
            : ((s = h.last),
              s !== null ? (s.sibling = y) : (n.child = y),
              (h.last = y));
        }
        return h.tail !== null
          ? ((n = h.tail),
            (h.rendering = n),
            (h.tail = n.sibling),
            (h.renderingStartTime = We()),
            (n.sibling = null),
            (s = ze.current),
            Ne(ze, a ? (s & 1) | 2 : s & 1),
            n)
          : (mt(n), null);
      case 22:
      case 23:
        return (
          eu(),
          (a = n.memoizedState !== null),
          t !== null && (t.memoizedState !== null) !== a && (n.flags |= 8192),
          a && (n.mode & 1) !== 0
            ? (Ut & 1073741824) !== 0 &&
              (mt(n), n.subtreeFlags & 6 && (n.flags |= 8192))
            : mt(n),
          null
        );
      case 24:
        return null;
      case 25:
        return null;
    }
    throw Error(i(156, n.tag));
  }
  function u0(t, n) {
    switch ((ul(n), n.tag)) {
      case 1:
        return (
          bt(n.type) && co(),
          (t = n.flags),
          t & 65536 ? ((n.flags = (t & -65537) | 128), n) : null
        );
      case 3:
        return (
          di(),
          Be(Rt),
          Be(dt),
          Sl(),
          (t = n.flags),
          (t & 65536) !== 0 && (t & 128) === 0
            ? ((n.flags = (t & -65537) | 128), n)
            : null
        );
      case 5:
        return wl(n), null;
      case 13:
        if (
          (Be(ze), (t = n.memoizedState), t !== null && t.dehydrated !== null)
        ) {
          if (n.alternate === null) throw Error(i(340));
          ui();
        }
        return (
          (t = n.flags), t & 65536 ? ((n.flags = (t & -65537) | 128), n) : null
        );
      case 19:
        return Be(ze), null;
      case 4:
        return di(), null;
      case 10:
        return ml(n.type._context), null;
      case 22:
      case 23:
        return eu(), null;
      case 24:
        return null;
      default:
        return null;
    }
  }
  var Oo = !1,
    yt = !1,
    c0 = typeof WeakSet == "function" ? WeakSet : Set,
    Z = null;
  function mi(t, n) {
    var s = t.ref;
    if (s !== null)
      if (typeof s == "function")
        try {
          s(null);
        } catch (a) {
          Ge(t, n, a);
        }
      else s.current = null;
  }
  function zl(t, n, s) {
    try {
      s();
    } catch (a) {
      Ge(t, n, a);
    }
  }
  var od = !1;
  function f0(t, n) {
    if (((el = Qs), (t = Bf()), Ga(t))) {
      if ("selectionStart" in t)
        var s = { start: t.selectionStart, end: t.selectionEnd };
      else
        e: {
          s = ((s = t.ownerDocument) && s.defaultView) || window;
          var a = s.getSelection && s.getSelection();
          if (a && a.rangeCount !== 0) {
            s = a.anchorNode;
            var u = a.anchorOffset,
              h = a.focusNode;
            a = a.focusOffset;
            try {
              s.nodeType, h.nodeType;
            } catch {
              s = null;
              break e;
            }
            var y = 0,
              S = -1,
              P = -1,
              I = 0,
              $ = 0,
              q = t,
              j = null;
            t: for (;;) {
              for (
                var K;
                q !== s || (u !== 0 && q.nodeType !== 3) || (S = y + u),
                  q !== h || (a !== 0 && q.nodeType !== 3) || (P = y + a),
                  q.nodeType === 3 && (y += q.nodeValue.length),
                  (K = q.firstChild) !== null;

              )
                (j = q), (q = K);
              for (;;) {
                if (q === t) break t;
                if (
                  (j === s && ++I === u && (S = y),
                  j === h && ++$ === a && (P = y),
                  (K = q.nextSibling) !== null)
                )
                  break;
                (q = j), (j = q.parentNode);
              }
              q = K;
            }
            s = S === -1 || P === -1 ? null : { start: S, end: P };
          } else s = null;
        }
      s = s || { start: 0, end: 0 };
    } else s = null;
    for (
      tl = { focusedElem: t, selectionRange: s }, Qs = !1, Z = n;
      Z !== null;

    )
      if (((n = Z), (t = n.child), (n.subtreeFlags & 1028) !== 0 && t !== null))
        (t.return = n), (Z = t);
      else
        for (; Z !== null; ) {
          n = Z;
          try {
            var ie = n.alternate;
            if ((n.flags & 1024) !== 0)
              switch (n.tag) {
                case 0:
                case 11:
                case 15:
                  break;
                case 1:
                  if (ie !== null) {
                    var se = ie.memoizedProps,
                      Xe = ie.memoizedState,
                      T = n.stateNode,
                      C = T.getSnapshotBeforeUpdate(
                        n.elementType === n.type ? se : nr(n.type, se),
                        Xe
                      );
                    T.__reactInternalSnapshotBeforeUpdate = C;
                  }
                  break;
                case 3:
                  var O = n.stateNode.containerInfo;
                  O.nodeType === 1
                    ? (O.textContent = "")
                    : O.nodeType === 9 &&
                      O.documentElement &&
                      O.removeChild(O.documentElement);
                  break;
                case 5:
                case 6:
                case 4:
                case 17:
                  break;
                default:
                  throw Error(i(163));
              }
          } catch (V) {
            Ge(n, n.return, V);
          }
          if (((t = n.sibling), t !== null)) {
            (t.return = n.return), (Z = t);
            break;
          }
          Z = n.return;
        }
    return (ie = od), (od = !1), ie;
  }
  function us(t, n, s) {
    var a = n.updateQueue;
    if (((a = a !== null ? a.lastEffect : null), a !== null)) {
      var u = (a = a.next);
      do {
        if ((u.tag & t) === t) {
          var h = u.destroy;
          (u.destroy = void 0), h !== void 0 && zl(n, s, h);
        }
        u = u.next;
      } while (u !== a);
    }
  }
  function Mo(t, n) {
    if (
      ((n = n.updateQueue), (n = n !== null ? n.lastEffect : null), n !== null)
    ) {
      var s = (n = n.next);
      do {
        if ((s.tag & t) === t) {
          var a = s.create;
          s.destroy = a();
        }
        s = s.next;
      } while (s !== n);
    }
  }
  function Hl(t) {
    var n = t.ref;
    if (n !== null) {
      var s = t.stateNode;
      switch (t.tag) {
        case 5:
          t = s;
          break;
        default:
          t = s;
      }
      typeof n == "function" ? n(t) : (n.current = t);
    }
  }
  function ad(t) {
    var n = t.alternate;
    n !== null && ((t.alternate = null), ad(n)),
      (t.child = null),
      (t.deletions = null),
      (t.sibling = null),
      t.tag === 5 &&
        ((n = t.stateNode),
        n !== null &&
          (delete n[gr],
          delete n[Ji],
          delete n[sl],
          delete n[Wv],
          delete n[Xv])),
      (t.stateNode = null),
      (t.return = null),
      (t.dependencies = null),
      (t.memoizedProps = null),
      (t.memoizedState = null),
      (t.pendingProps = null),
      (t.stateNode = null),
      (t.updateQueue = null);
  }
  function ld(t) {
    return t.tag === 5 || t.tag === 3 || t.tag === 4;
  }
  function ud(t) {
    e: for (;;) {
      for (; t.sibling === null; ) {
        if (t.return === null || ld(t.return)) return null;
        t = t.return;
      }
      for (
        t.sibling.return = t.return, t = t.sibling;
        t.tag !== 5 && t.tag !== 6 && t.tag !== 18;

      ) {
        if (t.flags & 2 || t.child === null || t.tag === 4) continue e;
        (t.child.return = t), (t = t.child);
      }
      if (!(t.flags & 2)) return t.stateNode;
    }
  }
  function ql(t, n, s) {
    var a = t.tag;
    if (a === 5 || a === 6)
      (t = t.stateNode),
        n
          ? s.nodeType === 8
            ? s.parentNode.insertBefore(t, n)
            : s.insertBefore(t, n)
          : (s.nodeType === 8
              ? ((n = s.parentNode), n.insertBefore(t, s))
              : ((n = s), n.appendChild(t)),
            (s = s._reactRootContainer),
            s != null || n.onclick !== null || (n.onclick = lo));
    else if (a !== 4 && ((t = t.child), t !== null))
      for (ql(t, n, s), t = t.sibling; t !== null; )
        ql(t, n, s), (t = t.sibling);
  }
  function Vl(t, n, s) {
    var a = t.tag;
    if (a === 5 || a === 6)
      (t = t.stateNode), n ? s.insertBefore(t, n) : s.appendChild(t);
    else if (a !== 4 && ((t = t.child), t !== null))
      for (Vl(t, n, s), t = t.sibling; t !== null; )
        Vl(t, n, s), (t = t.sibling);
  }
  var ut = null,
    ir = !1;
  function un(t, n, s) {
    for (s = s.child; s !== null; ) cd(t, n, s), (s = s.sibling);
  }
  function cd(t, n, s) {
    if (yr && typeof yr.onCommitFiberUnmount == "function")
      try {
        yr.onCommitFiberUnmount(qs, s);
      } catch {}
    switch (s.tag) {
      case 5:
        yt || mi(s, n);
      case 6:
        var a = ut,
          u = ir;
        (ut = null),
          un(t, n, s),
          (ut = a),
          (ir = u),
          ut !== null &&
            (ir
              ? ((t = ut),
                (s = s.stateNode),
                t.nodeType === 8
                  ? t.parentNode.removeChild(s)
                  : t.removeChild(s))
              : ut.removeChild(s.stateNode));
        break;
      case 18:
        ut !== null &&
          (ir
            ? ((t = ut),
              (s = s.stateNode),
              t.nodeType === 8
                ? il(t.parentNode, s)
                : t.nodeType === 1 && il(t, s),
              $i(t))
            : il(ut, s.stateNode));
        break;
      case 4:
        (a = ut),
          (u = ir),
          (ut = s.stateNode.containerInfo),
          (ir = !0),
          un(t, n, s),
          (ut = a),
          (ir = u);
        break;
      case 0:
      case 11:
      case 14:
      case 15:
        if (
          !yt &&
          ((a = s.updateQueue), a !== null && ((a = a.lastEffect), a !== null))
        ) {
          u = a = a.next;
          do {
            var h = u,
              y = h.destroy;
            (h = h.tag),
              y !== void 0 && ((h & 2) !== 0 || (h & 4) !== 0) && zl(s, n, y),
              (u = u.next);
          } while (u !== a);
        }
        un(t, n, s);
        break;
      case 1:
        if (
          !yt &&
          (mi(s, n),
          (a = s.stateNode),
          typeof a.componentWillUnmount == "function")
        )
          try {
            (a.props = s.memoizedProps),
              (a.state = s.memoizedState),
              a.componentWillUnmount();
          } catch (S) {
            Ge(s, n, S);
          }
        un(t, n, s);
        break;
      case 21:
        un(t, n, s);
        break;
      case 22:
        s.mode & 1
          ? ((yt = (a = yt) || s.memoizedState !== null), un(t, n, s), (yt = a))
          : un(t, n, s);
        break;
      default:
        un(t, n, s);
    }
  }
  function fd(t) {
    var n = t.updateQueue;
    if (n !== null) {
      t.updateQueue = null;
      var s = t.stateNode;
      s === null && (s = t.stateNode = new c0()),
        n.forEach(function (a) {
          var u = w0.bind(null, t, a);
          s.has(a) || (s.add(a), a.then(u, u));
        });
    }
  }
  function sr(t, n) {
    var s = n.deletions;
    if (s !== null)
      for (var a = 0; a < s.length; a++) {
        var u = s[a];
        try {
          var h = t,
            y = n,
            S = y;
          e: for (; S !== null; ) {
            switch (S.tag) {
              case 5:
                (ut = S.stateNode), (ir = !1);
                break e;
              case 3:
                (ut = S.stateNode.containerInfo), (ir = !0);
                break e;
              case 4:
                (ut = S.stateNode.containerInfo), (ir = !0);
                break e;
            }
            S = S.return;
          }
          if (ut === null) throw Error(i(160));
          cd(h, y, u), (ut = null), (ir = !1);
          var P = u.alternate;
          P !== null && (P.return = null), (u.return = null);
        } catch (I) {
          Ge(u, n, I);
        }
      }
    if (n.subtreeFlags & 12854)
      for (n = n.child; n !== null; ) hd(n, t), (n = n.sibling);
  }
  function hd(t, n) {
    var s = t.alternate,
      a = t.flags;
    switch (t.tag) {
      case 0:
      case 11:
      case 14:
      case 15:
        if ((sr(n, t), wr(t), a & 4)) {
          try {
            us(3, t, t.return), Mo(3, t);
          } catch (se) {
            Ge(t, t.return, se);
          }
          try {
            us(5, t, t.return);
          } catch (se) {
            Ge(t, t.return, se);
          }
        }
        break;
      case 1:
        sr(n, t), wr(t), a & 512 && s !== null && mi(s, s.return);
        break;
      case 5:
        if (
          (sr(n, t),
          wr(t),
          a & 512 && s !== null && mi(s, s.return),
          t.flags & 32)
        ) {
          var u = t.stateNode;
          try {
            kr(u, "");
          } catch (se) {
            Ge(t, t.return, se);
          }
        }
        if (a & 4 && ((u = t.stateNode), u != null)) {
          var h = t.memoizedProps,
            y = s !== null ? s.memoizedProps : h,
            S = t.type,
            P = t.updateQueue;
          if (((t.updateQueue = null), P !== null))
            try {
              S === "input" && h.type === "radio" && h.name != null && Ke(u, h),
                L(S, y);
              var I = L(S, h);
              for (y = 0; y < P.length; y += 2) {
                var $ = P[y],
                  q = P[y + 1];
                $ === "style"
                  ? Gn(u, q)
                  : $ === "dangerouslySetInnerHTML"
                  ? Vr(u, q)
                  : $ === "children"
                  ? kr(u, q)
                  : N(u, $, q, I);
              }
              switch (S) {
                case "input":
                  rt(u, h);
                  break;
                case "textarea":
                  Cr(u, h);
                  break;
                case "select":
                  var j = u._wrapperState.wasMultiple;
                  u._wrapperState.wasMultiple = !!h.multiple;
                  var K = h.value;
                  K != null
                    ? nt(u, !!h.multiple, K, !1)
                    : j !== !!h.multiple &&
                      (h.defaultValue != null
                        ? nt(u, !!h.multiple, h.defaultValue, !0)
                        : nt(u, !!h.multiple, h.multiple ? [] : "", !1));
              }
              u[Ji] = h;
            } catch (se) {
              Ge(t, t.return, se);
            }
        }
        break;
      case 6:
        if ((sr(n, t), wr(t), a & 4)) {
          if (t.stateNode === null) throw Error(i(162));
          (u = t.stateNode), (h = t.memoizedProps);
          try {
            u.nodeValue = h;
          } catch (se) {
            Ge(t, t.return, se);
          }
        }
        break;
      case 3:
        if (
          (sr(n, t), wr(t), a & 4 && s !== null && s.memoizedState.isDehydrated)
        )
          try {
            $i(n.containerInfo);
          } catch (se) {
            Ge(t, t.return, se);
          }
        break;
      case 4:
        sr(n, t), wr(t);
        break;
      case 13:
        sr(n, t),
          wr(t),
          (u = t.child),
          u.flags & 8192 &&
            ((h = u.memoizedState !== null),
            (u.stateNode.isHidden = h),
            !h ||
              (u.alternate !== null && u.alternate.memoizedState !== null) ||
              (Xl = We())),
          a & 4 && fd(t);
        break;
      case 22:
        if (
          (($ = s !== null && s.memoizedState !== null),
          t.mode & 1 ? ((yt = (I = yt) || $), sr(n, t), (yt = I)) : sr(n, t),
          wr(t),
          a & 8192)
        ) {
          if (
            ((I = t.memoizedState !== null),
            (t.stateNode.isHidden = I) && !$ && (t.mode & 1) !== 0)
          )
            for (Z = t, $ = t.child; $ !== null; ) {
              for (q = Z = $; Z !== null; ) {
                switch (((j = Z), (K = j.child), j.tag)) {
                  case 0:
                  case 11:
                  case 14:
                  case 15:
                    us(4, j, j.return);
                    break;
                  case 1:
                    mi(j, j.return);
                    var ie = j.stateNode;
                    if (typeof ie.componentWillUnmount == "function") {
                      (a = j), (s = j.return);
                      try {
                        (n = a),
                          (ie.props = n.memoizedProps),
                          (ie.state = n.memoizedState),
                          ie.componentWillUnmount();
                      } catch (se) {
                        Ge(a, s, se);
                      }
                    }
                    break;
                  case 5:
                    mi(j, j.return);
                    break;
                  case 22:
                    if (j.memoizedState !== null) {
                      md(q);
                      continue;
                    }
                }
                K !== null ? ((K.return = j), (Z = K)) : md(q);
              }
              $ = $.sibling;
            }
          e: for ($ = null, q = t; ; ) {
            if (q.tag === 5) {
              if ($ === null) {
                $ = q;
                try {
                  (u = q.stateNode),
                    I
                      ? ((h = u.style),
                        typeof h.setProperty == "function"
                          ? h.setProperty("display", "none", "important")
                          : (h.display = "none"))
                      : ((S = q.stateNode),
                        (P = q.memoizedProps.style),
                        (y =
                          P != null && P.hasOwnProperty("display")
                            ? P.display
                            : null),
                        (S.style.display = Bs("display", y)));
                } catch (se) {
                  Ge(t, t.return, se);
                }
              }
            } else if (q.tag === 6) {
              if ($ === null)
                try {
                  q.stateNode.nodeValue = I ? "" : q.memoizedProps;
                } catch (se) {
                  Ge(t, t.return, se);
                }
            } else if (
              ((q.tag !== 22 && q.tag !== 23) ||
                q.memoizedState === null ||
                q === t) &&
              q.child !== null
            ) {
              (q.child.return = q), (q = q.child);
              continue;
            }
            if (q === t) break e;
            for (; q.sibling === null; ) {
              if (q.return === null || q.return === t) break e;
              $ === q && ($ = null), (q = q.return);
            }
            $ === q && ($ = null),
              (q.sibling.return = q.return),
              (q = q.sibling);
          }
        }
        break;
      case 19:
        sr(n, t), wr(t), a & 4 && fd(t);
        break;
      case 21:
        break;
      default:
        sr(n, t), wr(t);
    }
  }
  function wr(t) {
    var n = t.flags;
    if (n & 2) {
      try {
        e: {
          for (var s = t.return; s !== null; ) {
            if (ld(s)) {
              var a = s;
              break e;
            }
            s = s.return;
          }
          throw Error(i(160));
        }
        switch (a.tag) {
          case 5:
            var u = a.stateNode;
            a.flags & 32 && (kr(u, ""), (a.flags &= -33));
            var h = ud(t);
            Vl(t, h, u);
            break;
          case 3:
          case 4:
            var y = a.stateNode.containerInfo,
              S = ud(t);
            ql(t, S, y);
            break;
          default:
            throw Error(i(161));
        }
      } catch (P) {
        Ge(t, t.return, P);
      }
      t.flags &= -3;
    }
    n & 4096 && (t.flags &= -4097);
  }
  function h0(t, n, s) {
    (Z = t), dd(t);
  }
  function dd(t, n, s) {
    for (var a = (t.mode & 1) !== 0; Z !== null; ) {
      var u = Z,
        h = u.child;
      if (u.tag === 22 && a) {
        var y = u.memoizedState !== null || Oo;
        if (!y) {
          var S = u.alternate,
            P = (S !== null && S.memoizedState !== null) || yt;
          S = Oo;
          var I = yt;
          if (((Oo = y), (yt = P) && !I))
            for (Z = u; Z !== null; )
              (y = Z),
                (P = y.child),
                y.tag === 22 && y.memoizedState !== null
                  ? yd(u)
                  : P !== null
                  ? ((P.return = y), (Z = P))
                  : yd(u);
          for (; h !== null; ) (Z = h), dd(h), (h = h.sibling);
          (Z = u), (Oo = S), (yt = I);
        }
        pd(t);
      } else
        (u.subtreeFlags & 8772) !== 0 && h !== null
          ? ((h.return = u), (Z = h))
          : pd(t);
    }
  }
  function pd(t) {
    for (; Z !== null; ) {
      var n = Z;
      if ((n.flags & 8772) !== 0) {
        var s = n.alternate;
        try {
          if ((n.flags & 8772) !== 0)
            switch (n.tag) {
              case 0:
              case 11:
              case 15:
                yt || Mo(5, n);
                break;
              case 1:
                var a = n.stateNode;
                if (n.flags & 4 && !yt)
                  if (s === null) a.componentDidMount();
                  else {
                    var u =
                      n.elementType === n.type
                        ? s.memoizedProps
                        : nr(n.type, s.memoizedProps);
                    a.componentDidUpdate(
                      u,
                      s.memoizedState,
                      a.__reactInternalSnapshotBeforeUpdate
                    );
                  }
                var h = n.updateQueue;
                h !== null && mh(n, h, a);
                break;
              case 3:
                var y = n.updateQueue;
                if (y !== null) {
                  if (((s = null), n.child !== null))
                    switch (n.child.tag) {
                      case 5:
                        s = n.child.stateNode;
                        break;
                      case 1:
                        s = n.child.stateNode;
                    }
                  mh(n, y, s);
                }
                break;
              case 5:
                var S = n.stateNode;
                if (s === null && n.flags & 4) {
                  s = S;
                  var P = n.memoizedProps;
                  switch (n.type) {
                    case "button":
                    case "input":
                    case "select":
                    case "textarea":
                      P.autoFocus && s.focus();
                      break;
                    case "img":
                      P.src && (s.src = P.src);
                  }
                }
                break;
              case 6:
                break;
              case 4:
                break;
              case 12:
                break;
              case 13:
                if (n.memoizedState === null) {
                  var I = n.alternate;
                  if (I !== null) {
                    var $ = I.memoizedState;
                    if ($ !== null) {
                      var q = $.dehydrated;
                      q !== null && $i(q);
                    }
                  }
                }
                break;
              case 19:
              case 17:
              case 21:
              case 22:
              case 23:
              case 25:
                break;
              default:
                throw Error(i(163));
            }
          yt || (n.flags & 512 && Hl(n));
        } catch (j) {
          Ge(n, n.return, j);
        }
      }
      if (n === t) {
        Z = null;
        break;
      }
      if (((s = n.sibling), s !== null)) {
        (s.return = n.return), (Z = s);
        break;
      }
      Z = n.return;
    }
  }
  function md(t) {
    for (; Z !== null; ) {
      var n = Z;
      if (n === t) {
        Z = null;
        break;
      }
      var s = n.sibling;
      if (s !== null) {
        (s.return = n.return), (Z = s);
        break;
      }
      Z = n.return;
    }
  }
  function yd(t) {
    for (; Z !== null; ) {
      var n = Z;
      try {
        switch (n.tag) {
          case 0:
          case 11:
          case 15:
            var s = n.return;
            try {
              Mo(4, n);
            } catch (P) {
              Ge(n, s, P);
            }
            break;
          case 1:
            var a = n.stateNode;
            if (typeof a.componentDidMount == "function") {
              var u = n.return;
              try {
                a.componentDidMount();
              } catch (P) {
                Ge(n, u, P);
              }
            }
            var h = n.return;
            try {
              Hl(n);
            } catch (P) {
              Ge(n, h, P);
            }
            break;
          case 5:
            var y = n.return;
            try {
              Hl(n);
            } catch (P) {
              Ge(n, y, P);
            }
        }
      } catch (P) {
        Ge(n, n.return, P);
      }
      if (n === t) {
        Z = null;
        break;
      }
      var S = n.sibling;
      if (S !== null) {
        (S.return = n.return), (Z = S);
        break;
      }
      Z = n.return;
    }
  }
  var d0 = Math.ceil,
    Io = U.ReactCurrentDispatcher,
    Gl = U.ReactCurrentOwner,
    Vt = U.ReactCurrentBatchConfig,
    Re = 0,
    st = null,
    Qe = null,
    ct = 0,
    Ut = 0,
    yi = nn(0),
    Ze = 0,
    cs = null,
    Tn = 0,
    Lo = 0,
    Wl = 0,
    fs = null,
    Ot = null,
    Xl = 0,
    gi = 1 / 0,
    Dr = null,
    Fo = !1,
    Yl = null,
    cn = null,
    No = !1,
    fn = null,
    Do = 0,
    hs = 0,
    Ql = null,
    Bo = -1,
    Uo = 0;
  function Pt() {
    return (Re & 6) !== 0 ? We() : Bo !== -1 ? Bo : (Bo = We());
  }
  function hn(t) {
    return (t.mode & 1) === 0
      ? 1
      : (Re & 2) !== 0 && ct !== 0
      ? ct & -ct
      : Qv.transition !== null
      ? (Uo === 0 && (Uo = uf()), Uo)
      : ((t = Fe),
        t !== 0 || ((t = window.event), (t = t === void 0 ? 16 : vf(t.type))),
        t);
  }
  function or(t, n, s, a) {
    if (50 < hs) throw ((hs = 0), (Ql = null), Error(i(185)));
    Ni(t, s, a),
      ((Re & 2) === 0 || t !== st) &&
        (t === st && ((Re & 2) === 0 && (Lo |= s), Ze === 4 && dn(t, ct)),
        Mt(t, a),
        s === 1 &&
          Re === 0 &&
          (n.mode & 1) === 0 &&
          ((gi = We() + 500), ho && on()));
  }
  function Mt(t, n) {
    var s = t.callbackNode;
    Qg(t, n);
    var a = Ws(t, t === st ? ct : 0);
    if (a === 0)
      s !== null && Li(s), (t.callbackNode = null), (t.callbackPriority = 0);
    else if (((n = a & -a), t.callbackPriority !== n)) {
      if ((s != null && Li(s), n === 1))
        t.tag === 0 ? Yv(vd.bind(null, t)) : nh(vd.bind(null, t)),
          Vv(function () {
            (Re & 6) === 0 && on();
          }),
          (s = null);
      else {
        switch (cf(a)) {
          case 1:
            s = ba;
            break;
          case 4:
            s = af;
            break;
          case 16:
            s = Hs;
            break;
          case 536870912:
            s = lf;
            break;
          default:
            s = Hs;
        }
        s = Cd(s, gd.bind(null, t));
      }
      (t.callbackPriority = n), (t.callbackNode = s);
    }
  }
  function gd(t, n) {
    if (((Bo = -1), (Uo = 0), (Re & 6) !== 0)) throw Error(i(327));
    var s = t.callbackNode;
    if (vi() && t.callbackNode !== s) return null;
    var a = Ws(t, t === st ? ct : 0);
    if (a === 0) return null;
    if ((a & 30) !== 0 || (a & t.expiredLanes) !== 0 || n) n = jo(t, a);
    else {
      n = a;
      var u = Re;
      Re |= 2;
      var h = wd();
      (st !== t || ct !== n) && ((Dr = null), (gi = We() + 500), Mn(t, n));
      do
        try {
          y0();
          break;
        } catch (S) {
          _d(t, S);
        }
      while (!0);
      pl(),
        (Io.current = h),
        (Re = u),
        Qe !== null ? (n = 0) : ((st = null), (ct = 0), (n = Ze));
    }
    if (n !== 0) {
      if (
        (n === 2 && ((u = Ta(t)), u !== 0 && ((a = u), (n = Kl(t, u)))),
        n === 1)
      )
        throw ((s = cs), Mn(t, 0), dn(t, a), Mt(t, We()), s);
      if (n === 6) dn(t, a);
      else {
        if (
          ((u = t.current.alternate),
          (a & 30) === 0 &&
            !p0(u) &&
            ((n = jo(t, a)),
            n === 2 && ((h = Ta(t)), h !== 0 && ((a = h), (n = Kl(t, h)))),
            n === 1))
        )
          throw ((s = cs), Mn(t, 0), dn(t, a), Mt(t, We()), s);
        switch (((t.finishedWork = u), (t.finishedLanes = a), n)) {
          case 0:
          case 1:
            throw Error(i(345));
          case 2:
            In(t, Ot, Dr);
            break;
          case 3:
            if (
              (dn(t, a),
              (a & 130023424) === a && ((n = Xl + 500 - We()), 10 < n))
            ) {
              if (Ws(t, 0) !== 0) break;
              if (((u = t.suspendedLanes), (u & a) !== a)) {
                Pt(), (t.pingedLanes |= t.suspendedLanes & u);
                break;
              }
              t.timeoutHandle = nl(In.bind(null, t, Ot, Dr), n);
              break;
            }
            In(t, Ot, Dr);
            break;
          case 4:
            if ((dn(t, a), (a & 4194240) === a)) break;
            for (n = t.eventTimes, u = -1; 0 < a; ) {
              var y = 31 - er(a);
              (h = 1 << y), (y = n[y]), y > u && (u = y), (a &= ~h);
            }
            if (
              ((a = u),
              (a = We() - a),
              (a =
                (120 > a
                  ? 120
                  : 480 > a
                  ? 480
                  : 1080 > a
                  ? 1080
                  : 1920 > a
                  ? 1920
                  : 3e3 > a
                  ? 3e3
                  : 4320 > a
                  ? 4320
                  : 1960 * d0(a / 1960)) - a),
              10 < a)
            ) {
              t.timeoutHandle = nl(In.bind(null, t, Ot, Dr), a);
              break;
            }
            In(t, Ot, Dr);
            break;
          case 5:
            In(t, Ot, Dr);
            break;
          default:
            throw Error(i(329));
        }
      }
    }
    return Mt(t, We()), t.callbackNode === s ? gd.bind(null, t) : null;
  }
  function Kl(t, n) {
    var s = fs;
    return (
      t.current.memoizedState.isDehydrated && (Mn(t, n).flags |= 256),
      (t = jo(t, n)),
      t !== 2 && ((n = Ot), (Ot = s), n !== null && Jl(n)),
      t
    );
  }
  function Jl(t) {
    Ot === null ? (Ot = t) : Ot.push.apply(Ot, t);
  }
  function p0(t) {
    for (var n = t; ; ) {
      if (n.flags & 16384) {
        var s = n.updateQueue;
        if (s !== null && ((s = s.stores), s !== null))
          for (var a = 0; a < s.length; a++) {
            var u = s[a],
              h = u.getSnapshot;
            u = u.value;
            try {
              if (!tr(h(), u)) return !1;
            } catch {
              return !1;
            }
          }
      }
      if (((s = n.child), n.subtreeFlags & 16384 && s !== null))
        (s.return = n), (n = s);
      else {
        if (n === t) break;
        for (; n.sibling === null; ) {
          if (n.return === null || n.return === t) return !0;
          n = n.return;
        }
        (n.sibling.return = n.return), (n = n.sibling);
      }
    }
    return !0;
  }
  function dn(t, n) {
    for (
      n &= ~Wl,
        n &= ~Lo,
        t.suspendedLanes |= n,
        t.pingedLanes &= ~n,
        t = t.expirationTimes;
      0 < n;

    ) {
      var s = 31 - er(n),
        a = 1 << s;
      (t[s] = -1), (n &= ~a);
    }
  }
  function vd(t) {
    if ((Re & 6) !== 0) throw Error(i(327));
    vi();
    var n = Ws(t, 0);
    if ((n & 1) === 0) return Mt(t, We()), null;
    var s = jo(t, n);
    if (t.tag !== 0 && s === 2) {
      var a = Ta(t);
      a !== 0 && ((n = a), (s = Kl(t, a)));
    }
    if (s === 1) throw ((s = cs), Mn(t, 0), dn(t, n), Mt(t, We()), s);
    if (s === 6) throw Error(i(345));
    return (
      (t.finishedWork = t.current.alternate),
      (t.finishedLanes = n),
      In(t, Ot, Dr),
      Mt(t, We()),
      null
    );
  }
  function Zl(t, n) {
    var s = Re;
    Re |= 1;
    try {
      return t(n);
    } finally {
      (Re = s), Re === 0 && ((gi = We() + 500), ho && on());
    }
  }
  function On(t) {
    fn !== null && fn.tag === 0 && (Re & 6) === 0 && vi();
    var n = Re;
    Re |= 1;
    var s = Vt.transition,
      a = Fe;
    try {
      if (((Vt.transition = null), (Fe = 1), t)) return t();
    } finally {
      (Fe = a), (Vt.transition = s), (Re = n), (Re & 6) === 0 && on();
    }
  }
  function eu() {
    (Ut = yi.current), Be(yi);
  }
  function Mn(t, n) {
    (t.finishedWork = null), (t.finishedLanes = 0);
    var s = t.timeoutHandle;
    if ((s !== -1 && ((t.timeoutHandle = -1), qv(s)), Qe !== null))
      for (s = Qe.return; s !== null; ) {
        var a = s;
        switch ((ul(a), a.tag)) {
          case 1:
            (a = a.type.childContextTypes), a != null && co();
            break;
          case 3:
            di(), Be(Rt), Be(dt), Sl();
            break;
          case 5:
            wl(a);
            break;
          case 4:
            di();
            break;
          case 13:
            Be(ze);
            break;
          case 19:
            Be(ze);
            break;
          case 10:
            ml(a.type._context);
            break;
          case 22:
          case 23:
            eu();
        }
        s = s.return;
      }
    if (
      ((st = t),
      (Qe = t = pn(t.current, null)),
      (ct = Ut = n),
      (Ze = 0),
      (cs = null),
      (Wl = Lo = Tn = 0),
      (Ot = fs = null),
      kn !== null)
    ) {
      for (n = 0; n < kn.length; n++)
        if (((s = kn[n]), (a = s.interleaved), a !== null)) {
          s.interleaved = null;
          var u = a.next,
            h = s.pending;
          if (h !== null) {
            var y = h.next;
            (h.next = u), (a.next = y);
          }
          s.pending = a;
        }
      kn = null;
    }
    return t;
  }
  function _d(t, n) {
    do {
      var s = Qe;
      try {
        if ((pl(), (Eo.current = ko), Po)) {
          for (var a = He.memoizedState; a !== null; ) {
            var u = a.queue;
            u !== null && (u.pending = null), (a = a.next);
          }
          Po = !1;
        }
        if (
          ((bn = 0),
          (it = Je = He = null),
          (is = !1),
          (ss = 0),
          (Gl.current = null),
          s === null || s.return === null)
        ) {
          (Ze = 1), (cs = n), (Qe = null);
          break;
        }
        e: {
          var h = t,
            y = s.return,
            S = s,
            P = n;
          if (
            ((n = ct),
            (S.flags |= 32768),
            P !== null && typeof P == "object" && typeof P.then == "function")
          ) {
            var I = P,
              $ = S,
              q = $.tag;
            if (($.mode & 1) === 0 && (q === 0 || q === 11 || q === 15)) {
              var j = $.alternate;
              j
                ? (($.updateQueue = j.updateQueue),
                  ($.memoizedState = j.memoizedState),
                  ($.lanes = j.lanes))
                : (($.updateQueue = null), ($.memoizedState = null));
            }
            var K = qh(y);
            if (K !== null) {
              (K.flags &= -257),
                Vh(K, y, S, h, n),
                K.mode & 1 && Hh(h, I, n),
                (n = K),
                (P = I);
              var ie = n.updateQueue;
              if (ie === null) {
                var se = new Set();
                se.add(P), (n.updateQueue = se);
              } else ie.add(P);
              break e;
            } else {
              if ((n & 1) === 0) {
                Hh(h, I, n), tu();
                break e;
              }
              P = Error(i(426));
            }
          } else if (je && S.mode & 1) {
            var Xe = qh(y);
            if (Xe !== null) {
              (Xe.flags & 65536) === 0 && (Xe.flags |= 256),
                Vh(Xe, y, S, h, n),
                hl(pi(P, S));
              break e;
            }
          }
          (h = P = pi(P, S)),
            Ze !== 4 && (Ze = 2),
            fs === null ? (fs = [h]) : fs.push(h),
            (h = y);
          do {
            switch (h.tag) {
              case 3:
                (h.flags |= 65536), (n &= -n), (h.lanes |= n);
                var T = $h(h, P, n);
                ph(h, T);
                break e;
              case 1:
                S = P;
                var C = h.type,
                  O = h.stateNode;
                if (
                  (h.flags & 128) === 0 &&
                  (typeof C.getDerivedStateFromError == "function" ||
                    (O !== null &&
                      typeof O.componentDidCatch == "function" &&
                      (cn === null || !cn.has(O))))
                ) {
                  (h.flags |= 65536), (n &= -n), (h.lanes |= n);
                  var V = zh(h, S, n);
                  ph(h, V);
                  break e;
                }
            }
            h = h.return;
          } while (h !== null);
        }
        Sd(s);
      } catch (oe) {
        (n = oe), Qe === s && s !== null && (Qe = s = s.return);
        continue;
      }
      break;
    } while (!0);
  }
  function wd() {
    var t = Io.current;
    return (Io.current = ko), t === null ? ko : t;
  }
  function tu() {
    (Ze === 0 || Ze === 3 || Ze === 2) && (Ze = 4),
      st === null ||
        ((Tn & 268435455) === 0 && (Lo & 268435455) === 0) ||
        dn(st, ct);
  }
  function jo(t, n) {
    var s = Re;
    Re |= 2;
    var a = wd();
    (st !== t || ct !== n) && ((Dr = null), Mn(t, n));
    do
      try {
        m0();
        break;
      } catch (u) {
        _d(t, u);
      }
    while (!0);
    if ((pl(), (Re = s), (Io.current = a), Qe !== null)) throw Error(i(261));
    return (st = null), (ct = 0), Ze;
  }
  function m0() {
    for (; Qe !== null; ) xd(Qe);
  }
  function y0() {
    for (; Qe !== null && !$g(); ) xd(Qe);
  }
  function xd(t) {
    var n = Ad(t.alternate, t, Ut);
    (t.memoizedProps = t.pendingProps),
      n === null ? Sd(t) : (Qe = n),
      (Gl.current = null);
  }
  function Sd(t) {
    var n = t;
    do {
      var s = n.alternate;
      if (((t = n.return), (n.flags & 32768) === 0)) {
        if (((s = l0(s, n, Ut)), s !== null)) {
          Qe = s;
          return;
        }
      } else {
        if (((s = u0(s, n)), s !== null)) {
          (s.flags &= 32767), (Qe = s);
          return;
        }
        if (t !== null)
          (t.flags |= 32768), (t.subtreeFlags = 0), (t.deletions = null);
        else {
          (Ze = 6), (Qe = null);
          return;
        }
      }
      if (((n = n.sibling), n !== null)) {
        Qe = n;
        return;
      }
      Qe = n = t;
    } while (n !== null);
    Ze === 0 && (Ze = 5);
  }
  function In(t, n, s) {
    var a = Fe,
      u = Vt.transition;
    try {
      (Vt.transition = null), (Fe = 1), g0(t, n, s, a);
    } finally {
      (Vt.transition = u), (Fe = a);
    }
    return null;
  }
  function g0(t, n, s, a) {
    do vi();
    while (fn !== null);
    if ((Re & 6) !== 0) throw Error(i(327));
    s = t.finishedWork;
    var u = t.finishedLanes;
    if (s === null) return null;
    if (((t.finishedWork = null), (t.finishedLanes = 0), s === t.current))
      throw Error(i(177));
    (t.callbackNode = null), (t.callbackPriority = 0);
    var h = s.lanes | s.childLanes;
    if (
      (Kg(t, h),
      t === st && ((Qe = st = null), (ct = 0)),
      ((s.subtreeFlags & 2064) === 0 && (s.flags & 2064) === 0) ||
        No ||
        ((No = !0),
        Cd(Hs, function () {
          return vi(), null;
        })),
      (h = (s.flags & 15990) !== 0),
      (s.subtreeFlags & 15990) !== 0 || h)
    ) {
      (h = Vt.transition), (Vt.transition = null);
      var y = Fe;
      Fe = 1;
      var S = Re;
      (Re |= 4),
        (Gl.current = null),
        f0(t, s),
        hd(s, t),
        Dv(tl),
        (Qs = !!el),
        (tl = el = null),
        (t.current = s),
        h0(s),
        zg(),
        (Re = S),
        (Fe = y),
        (Vt.transition = h);
    } else t.current = s;
    if (
      (No && ((No = !1), (fn = t), (Do = u)),
      (h = t.pendingLanes),
      h === 0 && (cn = null),
      Vg(s.stateNode),
      Mt(t, We()),
      n !== null)
    )
      for (a = t.onRecoverableError, s = 0; s < n.length; s++)
        (u = n[s]), a(u.value, { componentStack: u.stack, digest: u.digest });
    if (Fo) throw ((Fo = !1), (t = Yl), (Yl = null), t);
    return (
      (Do & 1) !== 0 && t.tag !== 0 && vi(),
      (h = t.pendingLanes),
      (h & 1) !== 0 ? (t === Ql ? hs++ : ((hs = 0), (Ql = t))) : (hs = 0),
      on(),
      null
    );
  }
  function vi() {
    if (fn !== null) {
      var t = cf(Do),
        n = Vt.transition,
        s = Fe;
      try {
        if (((Vt.transition = null), (Fe = 16 > t ? 16 : t), fn === null))
          var a = !1;
        else {
          if (((t = fn), (fn = null), (Do = 0), (Re & 6) !== 0))
            throw Error(i(331));
          var u = Re;
          for (Re |= 4, Z = t.current; Z !== null; ) {
            var h = Z,
              y = h.child;
            if ((Z.flags & 16) !== 0) {
              var S = h.deletions;
              if (S !== null) {
                for (var P = 0; P < S.length; P++) {
                  var I = S[P];
                  for (Z = I; Z !== null; ) {
                    var $ = Z;
                    switch ($.tag) {
                      case 0:
                      case 11:
                      case 15:
                        us(8, $, h);
                    }
                    var q = $.child;
                    if (q !== null) (q.return = $), (Z = q);
                    else
                      for (; Z !== null; ) {
                        $ = Z;
                        var j = $.sibling,
                          K = $.return;
                        if ((ad($), $ === I)) {
                          Z = null;
                          break;
                        }
                        if (j !== null) {
                          (j.return = K), (Z = j);
                          break;
                        }
                        Z = K;
                      }
                  }
                }
                var ie = h.alternate;
                if (ie !== null) {
                  var se = ie.child;
                  if (se !== null) {
                    ie.child = null;
                    do {
                      var Xe = se.sibling;
                      (se.sibling = null), (se = Xe);
                    } while (se !== null);
                  }
                }
                Z = h;
              }
            }
            if ((h.subtreeFlags & 2064) !== 0 && y !== null)
              (y.return = h), (Z = y);
            else
              e: for (; Z !== null; ) {
                if (((h = Z), (h.flags & 2048) !== 0))
                  switch (h.tag) {
                    case 0:
                    case 11:
                    case 15:
                      us(9, h, h.return);
                  }
                var T = h.sibling;
                if (T !== null) {
                  (T.return = h.return), (Z = T);
                  break e;
                }
                Z = h.return;
              }
          }
          var C = t.current;
          for (Z = C; Z !== null; ) {
            y = Z;
            var O = y.child;
            if ((y.subtreeFlags & 2064) !== 0 && O !== null)
              (O.return = y), (Z = O);
            else
              e: for (y = C; Z !== null; ) {
                if (((S = Z), (S.flags & 2048) !== 0))
                  try {
                    switch (S.tag) {
                      case 0:
                      case 11:
                      case 15:
                        Mo(9, S);
                    }
                  } catch (oe) {
                    Ge(S, S.return, oe);
                  }
                if (S === y) {
                  Z = null;
                  break e;
                }
                var V = S.sibling;
                if (V !== null) {
                  (V.return = S.return), (Z = V);
                  break e;
                }
                Z = S.return;
              }
          }
          if (
            ((Re = u),
            on(),
            yr && typeof yr.onPostCommitFiberRoot == "function")
          )
            try {
              yr.onPostCommitFiberRoot(qs, t);
            } catch {}
          a = !0;
        }
        return a;
      } finally {
        (Fe = s), (Vt.transition = n);
      }
    }
    return !1;
  }
  function Ed(t, n, s) {
    (n = pi(s, n)),
      (n = $h(t, n, 1)),
      (t = ln(t, n, 1)),
      (n = Pt()),
      t !== null && (Ni(t, 1, n), Mt(t, n));
  }
  function Ge(t, n, s) {
    if (t.tag === 3) Ed(t, t, s);
    else
      for (; n !== null; ) {
        if (n.tag === 3) {
          Ed(n, t, s);
          break;
        } else if (n.tag === 1) {
          var a = n.stateNode;
          if (
            typeof n.type.getDerivedStateFromError == "function" ||
            (typeof a.componentDidCatch == "function" &&
              (cn === null || !cn.has(a)))
          ) {
            (t = pi(s, t)),
              (t = zh(n, t, 1)),
              (n = ln(n, t, 1)),
              (t = Pt()),
              n !== null && (Ni(n, 1, t), Mt(n, t));
            break;
          }
        }
        n = n.return;
      }
  }
  function v0(t, n, s) {
    var a = t.pingCache;
    a !== null && a.delete(n),
      (n = Pt()),
      (t.pingedLanes |= t.suspendedLanes & s),
      st === t &&
        (ct & s) === s &&
        (Ze === 4 || (Ze === 3 && (ct & 130023424) === ct && 500 > We() - Xl)
          ? Mn(t, 0)
          : (Wl |= s)),
      Mt(t, n);
  }
  function Pd(t, n) {
    n === 0 &&
      ((t.mode & 1) === 0
        ? (n = 1)
        : ((n = Gs), (Gs <<= 1), (Gs & 130023424) === 0 && (Gs = 4194304)));
    var s = Pt();
    (t = Lr(t, n)), t !== null && (Ni(t, n, s), Mt(t, s));
  }
  function _0(t) {
    var n = t.memoizedState,
      s = 0;
    n !== null && (s = n.retryLane), Pd(t, s);
  }
  function w0(t, n) {
    var s = 0;
    switch (t.tag) {
      case 13:
        var a = t.stateNode,
          u = t.memoizedState;
        u !== null && (s = u.retryLane);
        break;
      case 19:
        a = t.stateNode;
        break;
      default:
        throw Error(i(314));
    }
    a !== null && a.delete(n), Pd(t, s);
  }
  var Ad;
  Ad = function (t, n, s) {
    if (t !== null)
      if (t.memoizedProps !== n.pendingProps || Rt.current) Tt = !0;
      else {
        if ((t.lanes & s) === 0 && (n.flags & 128) === 0)
          return (Tt = !1), a0(t, n, s);
        Tt = (t.flags & 131072) !== 0;
      }
    else (Tt = !1), je && (n.flags & 1048576) !== 0 && ih(n, mo, n.index);
    switch (((n.lanes = 0), n.tag)) {
      case 2:
        var a = n.type;
        To(t, n), (t = n.pendingProps);
        var u = oi(n, dt.current);
        hi(n, s), (u = Al(null, n, a, t, u, s));
        var h = Cl();
        return (
          (n.flags |= 1),
          typeof u == "object" &&
          u !== null &&
          typeof u.render == "function" &&
          u.$$typeof === void 0
            ? ((n.tag = 1),
              (n.memoizedState = null),
              (n.updateQueue = null),
              bt(a) ? ((h = !0), fo(n)) : (h = !1),
              (n.memoizedState =
                u.state !== null && u.state !== void 0 ? u.state : null),
              vl(n),
              (u.updater = Ro),
              (n.stateNode = u),
              (u._reactInternals = n),
              Ml(n, a, t, s),
              (n = Nl(null, n, a, !0, h, s)))
            : ((n.tag = 0), je && h && ll(n), Et(null, n, u, s), (n = n.child)),
          n
        );
      case 16:
        a = n.elementType;
        e: {
          switch (
            (To(t, n),
            (t = n.pendingProps),
            (u = a._init),
            (a = u(a._payload)),
            (n.type = a),
            (u = n.tag = S0(a)),
            (t = nr(a, t)),
            u)
          ) {
            case 0:
              n = Fl(null, n, a, t, s);
              break e;
            case 1:
              n = Kh(null, n, a, t, s);
              break e;
            case 11:
              n = Gh(null, n, a, t, s);
              break e;
            case 14:
              n = Wh(null, n, a, nr(a.type, t), s);
              break e;
          }
          throw Error(i(306, a, ""));
        }
        return n;
      case 0:
        return (
          (a = n.type),
          (u = n.pendingProps),
          (u = n.elementType === a ? u : nr(a, u)),
          Fl(t, n, a, u, s)
        );
      case 1:
        return (
          (a = n.type),
          (u = n.pendingProps),
          (u = n.elementType === a ? u : nr(a, u)),
          Kh(t, n, a, u, s)
        );
      case 3:
        e: {
          if ((Jh(n), t === null)) throw Error(i(387));
          (a = n.pendingProps),
            (h = n.memoizedState),
            (u = h.element),
            dh(t, n),
            xo(n, a, null, s);
          var y = n.memoizedState;
          if (((a = y.element), h.isDehydrated))
            if (
              ((h = {
                element: a,
                isDehydrated: !1,
                cache: y.cache,
                pendingSuspenseBoundaries: y.pendingSuspenseBoundaries,
                transitions: y.transitions,
              }),
              (n.updateQueue.baseState = h),
              (n.memoizedState = h),
              n.flags & 256)
            ) {
              (u = pi(Error(i(423)), n)), (n = Zh(t, n, a, s, u));
              break e;
            } else if (a !== u) {
              (u = pi(Error(i(424)), n)), (n = Zh(t, n, a, s, u));
              break e;
            } else
              for (
                Bt = rn(n.stateNode.containerInfo.firstChild),
                  Dt = n,
                  je = !0,
                  rr = null,
                  s = fh(n, null, a, s),
                  n.child = s;
                s;

              )
                (s.flags = (s.flags & -3) | 4096), (s = s.sibling);
          else {
            if ((ui(), a === u)) {
              n = Nr(t, n, s);
              break e;
            }
            Et(t, n, a, s);
          }
          n = n.child;
        }
        return n;
      case 5:
        return (
          yh(n),
          t === null && fl(n),
          (a = n.type),
          (u = n.pendingProps),
          (h = t !== null ? t.memoizedProps : null),
          (y = u.children),
          rl(a, u) ? (y = null) : h !== null && rl(a, h) && (n.flags |= 32),
          Qh(t, n),
          Et(t, n, y, s),
          n.child
        );
      case 6:
        return t === null && fl(n), null;
      case 13:
        return ed(t, n, s);
      case 4:
        return (
          _l(n, n.stateNode.containerInfo),
          (a = n.pendingProps),
          t === null ? (n.child = ci(n, null, a, s)) : Et(t, n, a, s),
          n.child
        );
      case 11:
        return (
          (a = n.type),
          (u = n.pendingProps),
          (u = n.elementType === a ? u : nr(a, u)),
          Gh(t, n, a, u, s)
        );
      case 7:
        return Et(t, n, n.pendingProps, s), n.child;
      case 8:
        return Et(t, n, n.pendingProps.children, s), n.child;
      case 12:
        return Et(t, n, n.pendingProps.children, s), n.child;
      case 10:
        e: {
          if (
            ((a = n.type._context),
            (u = n.pendingProps),
            (h = n.memoizedProps),
            (y = u.value),
            Ne(vo, a._currentValue),
            (a._currentValue = y),
            h !== null)
          )
            if (tr(h.value, y)) {
              if (h.children === u.children && !Rt.current) {
                n = Nr(t, n, s);
                break e;
              }
            } else
              for (h = n.child, h !== null && (h.return = n); h !== null; ) {
                var S = h.dependencies;
                if (S !== null) {
                  y = h.child;
                  for (var P = S.firstContext; P !== null; ) {
                    if (P.context === a) {
                      if (h.tag === 1) {
                        (P = Fr(-1, s & -s)), (P.tag = 2);
                        var I = h.updateQueue;
                        if (I !== null) {
                          I = I.shared;
                          var $ = I.pending;
                          $ === null
                            ? (P.next = P)
                            : ((P.next = $.next), ($.next = P)),
                            (I.pending = P);
                        }
                      }
                      (h.lanes |= s),
                        (P = h.alternate),
                        P !== null && (P.lanes |= s),
                        yl(h.return, s, n),
                        (S.lanes |= s);
                      break;
                    }
                    P = P.next;
                  }
                } else if (h.tag === 10) y = h.type === n.type ? null : h.child;
                else if (h.tag === 18) {
                  if (((y = h.return), y === null)) throw Error(i(341));
                  (y.lanes |= s),
                    (S = y.alternate),
                    S !== null && (S.lanes |= s),
                    yl(y, s, n),
                    (y = h.sibling);
                } else y = h.child;
                if (y !== null) y.return = h;
                else
                  for (y = h; y !== null; ) {
                    if (y === n) {
                      y = null;
                      break;
                    }
                    if (((h = y.sibling), h !== null)) {
                      (h.return = y.return), (y = h);
                      break;
                    }
                    y = y.return;
                  }
                h = y;
              }
          Et(t, n, u.children, s), (n = n.child);
        }
        return n;
      case 9:
        return (
          (u = n.type),
          (a = n.pendingProps.children),
          hi(n, s),
          (u = Ht(u)),
          (a = a(u)),
          (n.flags |= 1),
          Et(t, n, a, s),
          n.child
        );
      case 14:
        return (
          (a = n.type),
          (u = nr(a, n.pendingProps)),
          (u = nr(a.type, u)),
          Wh(t, n, a, u, s)
        );
      case 15:
        return Xh(t, n, n.type, n.pendingProps, s);
      case 17:
        return (
          (a = n.type),
          (u = n.pendingProps),
          (u = n.elementType === a ? u : nr(a, u)),
          To(t, n),
          (n.tag = 1),
          bt(a) ? ((t = !0), fo(n)) : (t = !1),
          hi(n, s),
          Uh(n, a, u),
          Ml(n, a, u, s),
          Nl(null, n, a, !0, t, s)
        );
      case 19:
        return rd(t, n, s);
      case 22:
        return Yh(t, n, s);
    }
    throw Error(i(156, n.tag));
  };
  function Cd(t, n) {
    return zs(t, n);
  }
  function x0(t, n, s, a) {
    (this.tag = t),
      (this.key = s),
      (this.sibling =
        this.child =
        this.return =
        this.stateNode =
        this.type =
        this.elementType =
          null),
      (this.index = 0),
      (this.ref = null),
      (this.pendingProps = n),
      (this.dependencies =
        this.memoizedState =
        this.updateQueue =
        this.memoizedProps =
          null),
      (this.mode = a),
      (this.subtreeFlags = this.flags = 0),
      (this.deletions = null),
      (this.childLanes = this.lanes = 0),
      (this.alternate = null);
  }
  function Gt(t, n, s, a) {
    return new x0(t, n, s, a);
  }
  function ru(t) {
    return (t = t.prototype), !(!t || !t.isReactComponent);
  }
  function S0(t) {
    if (typeof t == "function") return ru(t) ? 1 : 0;
    if (t != null) {
      if (((t = t.$$typeof), t === te)) return 11;
      if (t === ke) return 14;
    }
    return 2;
  }
  function pn(t, n) {
    var s = t.alternate;
    return (
      s === null
        ? ((s = Gt(t.tag, n, t.key, t.mode)),
          (s.elementType = t.elementType),
          (s.type = t.type),
          (s.stateNode = t.stateNode),
          (s.alternate = t),
          (t.alternate = s))
        : ((s.pendingProps = n),
          (s.type = t.type),
          (s.flags = 0),
          (s.subtreeFlags = 0),
          (s.deletions = null)),
      (s.flags = t.flags & 14680064),
      (s.childLanes = t.childLanes),
      (s.lanes = t.lanes),
      (s.child = t.child),
      (s.memoizedProps = t.memoizedProps),
      (s.memoizedState = t.memoizedState),
      (s.updateQueue = t.updateQueue),
      (n = t.dependencies),
      (s.dependencies =
        n === null ? null : { lanes: n.lanes, firstContext: n.firstContext }),
      (s.sibling = t.sibling),
      (s.index = t.index),
      (s.ref = t.ref),
      s
    );
  }
  function $o(t, n, s, a, u, h) {
    var y = 2;
    if (((a = t), typeof t == "function")) ru(t) && (y = 1);
    else if (typeof t == "string") y = 5;
    else
      e: switch (t) {
        case G:
          return Ln(s.children, u, h, n);
        case Q:
          (y = 8), (u |= 8);
          break;
        case me:
          return (
            (t = Gt(12, s, n, u | 2)), (t.elementType = me), (t.lanes = h), t
          );
        case _e:
          return (t = Gt(13, s, n, u)), (t.elementType = _e), (t.lanes = h), t;
        case Ae:
          return (t = Gt(19, s, n, u)), (t.elementType = Ae), (t.lanes = h), t;
        case Se:
          return zo(s, u, h, n);
        default:
          if (typeof t == "object" && t !== null)
            switch (t.$$typeof) {
              case ae:
                y = 10;
                break e;
              case xe:
                y = 9;
                break e;
              case te:
                y = 11;
                break e;
              case ke:
                y = 14;
                break e;
              case be:
                (y = 16), (a = null);
                break e;
            }
          throw Error(i(130, t == null ? t : typeof t, ""));
      }
    return (
      (n = Gt(y, s, n, u)), (n.elementType = t), (n.type = a), (n.lanes = h), n
    );
  }
  function Ln(t, n, s, a) {
    return (t = Gt(7, t, a, n)), (t.lanes = s), t;
  }
  function zo(t, n, s, a) {
    return (
      (t = Gt(22, t, a, n)),
      (t.elementType = Se),
      (t.lanes = s),
      (t.stateNode = { isHidden: !1 }),
      t
    );
  }
  function nu(t, n, s) {
    return (t = Gt(6, t, null, n)), (t.lanes = s), t;
  }
  function iu(t, n, s) {
    return (
      (n = Gt(4, t.children !== null ? t.children : [], t.key, n)),
      (n.lanes = s),
      (n.stateNode = {
        containerInfo: t.containerInfo,
        pendingChildren: null,
        implementation: t.implementation,
      }),
      n
    );
  }
  function E0(t, n, s, a, u) {
    (this.tag = n),
      (this.containerInfo = t),
      (this.finishedWork =
        this.pingCache =
        this.current =
        this.pendingChildren =
          null),
      (this.timeoutHandle = -1),
      (this.callbackNode = this.pendingContext = this.context = null),
      (this.callbackPriority = 0),
      (this.eventTimes = Oa(0)),
      (this.expirationTimes = Oa(-1)),
      (this.entangledLanes =
        this.finishedLanes =
        this.mutableReadLanes =
        this.expiredLanes =
        this.pingedLanes =
        this.suspendedLanes =
        this.pendingLanes =
          0),
      (this.entanglements = Oa(0)),
      (this.identifierPrefix = a),
      (this.onRecoverableError = u),
      (this.mutableSourceEagerHydrationData = null);
  }
  function su(t, n, s, a, u, h, y, S, P) {
    return (
      (t = new E0(t, n, s, S, P)),
      n === 1 ? ((n = 1), h === !0 && (n |= 8)) : (n = 0),
      (h = Gt(3, null, null, n)),
      (t.current = h),
      (h.stateNode = t),
      (h.memoizedState = {
        element: a,
        isDehydrated: s,
        cache: null,
        transitions: null,
        pendingSuspenseBoundaries: null,
      }),
      vl(h),
      t
    );
  }
  function P0(t, n, s) {
    var a =
      3 < arguments.length && arguments[3] !== void 0 ? arguments[3] : null;
    return {
      $$typeof: H,
      key: a == null ? null : "" + a,
      children: t,
      containerInfo: n,
      implementation: s,
    };
  }
  function kd(t) {
    if (!t) return sn;
    t = t._reactInternals;
    e: {
      if (Zt(t) !== t || t.tag !== 1) throw Error(i(170));
      var n = t;
      do {
        switch (n.tag) {
          case 3:
            n = n.stateNode.context;
            break e;
          case 1:
            if (bt(n.type)) {
              n = n.stateNode.__reactInternalMemoizedMergedChildContext;
              break e;
            }
        }
        n = n.return;
      } while (n !== null);
      throw Error(i(171));
    }
    if (t.tag === 1) {
      var s = t.type;
      if (bt(s)) return th(t, s, n);
    }
    return n;
  }
  function Rd(t, n, s, a, u, h, y, S, P) {
    return (
      (t = su(s, a, !0, t, u, h, y, S, P)),
      (t.context = kd(null)),
      (s = t.current),
      (a = Pt()),
      (u = hn(s)),
      (h = Fr(a, u)),
      (h.callback = n ?? null),
      ln(s, h, u),
      (t.current.lanes = u),
      Ni(t, u, a),
      Mt(t, a),
      t
    );
  }
  function Ho(t, n, s, a) {
    var u = n.current,
      h = Pt(),
      y = hn(u);
    return (
      (s = kd(s)),
      n.context === null ? (n.context = s) : (n.pendingContext = s),
      (n = Fr(h, y)),
      (n.payload = { element: t }),
      (a = a === void 0 ? null : a),
      a !== null && (n.callback = a),
      (t = ln(u, n, y)),
      t !== null && (or(t, u, y, h), wo(t, u, y)),
      y
    );
  }
  function qo(t) {
    if (((t = t.current), !t.child)) return null;
    switch (t.child.tag) {
      case 5:
        return t.child.stateNode;
      default:
        return t.child.stateNode;
    }
  }
  function bd(t, n) {
    if (((t = t.memoizedState), t !== null && t.dehydrated !== null)) {
      var s = t.retryLane;
      t.retryLane = s !== 0 && s < n ? s : n;
    }
  }
  function ou(t, n) {
    bd(t, n), (t = t.alternate) && bd(t, n);
  }
  function A0() {
    return null;
  }
  var Td =
    typeof reportError == "function"
      ? reportError
      : function (t) {
          console.error(t);
        };
  function au(t) {
    this._internalRoot = t;
  }
  (Vo.prototype.render = au.prototype.render =
    function (t) {
      var n = this._internalRoot;
      if (n === null) throw Error(i(409));
      Ho(t, n, null, null);
    }),
    (Vo.prototype.unmount = au.prototype.unmount =
      function () {
        var t = this._internalRoot;
        if (t !== null) {
          this._internalRoot = null;
          var n = t.containerInfo;
          On(function () {
            Ho(null, t, null, null);
          }),
            (n[Tr] = null);
        }
      });
  function Vo(t) {
    this._internalRoot = t;
  }
  Vo.prototype.unstable_scheduleHydration = function (t) {
    if (t) {
      var n = df();
      t = { blockedOn: null, target: t, priority: n };
      for (var s = 0; s < Zr.length && n !== 0 && n < Zr[s].priority; s++);
      Zr.splice(s, 0, t), s === 0 && yf(t);
    }
  };
  function lu(t) {
    return !(!t || (t.nodeType !== 1 && t.nodeType !== 9 && t.nodeType !== 11));
  }
  function Go(t) {
    return !(
      !t ||
      (t.nodeType !== 1 &&
        t.nodeType !== 9 &&
        t.nodeType !== 11 &&
        (t.nodeType !== 8 || t.nodeValue !== " react-mount-point-unstable "))
    );
  }
  function Od() {}
  function C0(t, n, s, a, u) {
    if (u) {
      if (typeof a == "function") {
        var h = a;
        a = function () {
          var I = qo(y);
          h.call(I);
        };
      }
      var y = Rd(n, a, t, 0, null, !1, !1, "", Od);
      return (
        (t._reactRootContainer = y),
        (t[Tr] = y.current),
        Qi(t.nodeType === 8 ? t.parentNode : t),
        On(),
        y
      );
    }
    for (; (u = t.lastChild); ) t.removeChild(u);
    if (typeof a == "function") {
      var S = a;
      a = function () {
        var I = qo(P);
        S.call(I);
      };
    }
    var P = su(t, 0, !1, null, null, !1, !1, "", Od);
    return (
      (t._reactRootContainer = P),
      (t[Tr] = P.current),
      Qi(t.nodeType === 8 ? t.parentNode : t),
      On(function () {
        Ho(n, P, s, a);
      }),
      P
    );
  }
  function Wo(t, n, s, a, u) {
    var h = s._reactRootContainer;
    if (h) {
      var y = h;
      if (typeof u == "function") {
        var S = u;
        u = function () {
          var P = qo(y);
          S.call(P);
        };
      }
      Ho(n, y, t, u);
    } else y = C0(s, n, t, u, a);
    return qo(y);
  }
  (ff = function (t) {
    switch (t.tag) {
      case 3:
        var n = t.stateNode;
        if (n.current.memoizedState.isDehydrated) {
          var s = Fi(n.pendingLanes);
          s !== 0 &&
            (Ma(n, s | 1),
            Mt(n, We()),
            (Re & 6) === 0 && ((gi = We() + 500), on()));
        }
        break;
      case 13:
        On(function () {
          var a = Lr(t, 1);
          if (a !== null) {
            var u = Pt();
            or(a, t, 1, u);
          }
        }),
          ou(t, 1);
    }
  }),
    (Ia = function (t) {
      if (t.tag === 13) {
        var n = Lr(t, 134217728);
        if (n !== null) {
          var s = Pt();
          or(n, t, 134217728, s);
        }
        ou(t, 134217728);
      }
    }),
    (hf = function (t) {
      if (t.tag === 13) {
        var n = hn(t),
          s = Lr(t, n);
        if (s !== null) {
          var a = Pt();
          or(s, t, n, a);
        }
        ou(t, n);
      }
    }),
    (df = function () {
      return Fe;
    }),
    (pf = function (t, n) {
      var s = Fe;
      try {
        return (Fe = t), n();
      } finally {
        Fe = s;
      }
    }),
    (Le = function (t, n, s) {
      switch (n) {
        case "input":
          if ((rt(t, s), (n = s.name), s.type === "radio" && n != null)) {
            for (s = t; s.parentNode; ) s = s.parentNode;
            for (
              s = s.querySelectorAll(
                "input[name=" + JSON.stringify("" + n) + '][type="radio"]'
              ),
                n = 0;
              n < s.length;
              n++
            ) {
              var a = s[n];
              if (a !== t && a.form === t.form) {
                var u = uo(a);
                if (!u) throw Error(i(90));
                Ie(a), rt(a, u);
              }
            }
          }
          break;
        case "textarea":
          Cr(t, s);
          break;
        case "select":
          (n = s.value), n != null && nt(t, !!s.multiple, n, !1);
      }
    }),
    (Xn = Zl),
    (Rr = On);
  var k0 = { usingClientEntryPoint: !1, Events: [Zi, ii, uo, ht, Kt, Zl] },
    ds = {
      findFiberByHostInstance: En,
      bundleType: 0,
      version: "18.3.1",
      rendererPackageName: "react-dom",
    },
    R0 = {
      bundleType: ds.bundleType,
      version: ds.version,
      rendererPackageName: ds.rendererPackageName,
      rendererConfig: ds.rendererConfig,
      overrideHookState: null,
      overrideHookStateDeletePath: null,
      overrideHookStateRenamePath: null,
      overrideProps: null,
      overridePropsDeletePath: null,
      overridePropsRenamePath: null,
      setErrorHandler: null,
      setSuspenseHandler: null,
      scheduleUpdate: null,
      currentDispatcherRef: U.ReactCurrentDispatcher,
      findHostInstanceByFiber: function (t) {
        return (t = br(t)), t === null ? null : t.stateNode;
      },
      findFiberByHostInstance: ds.findFiberByHostInstance || A0,
      findHostInstancesForRefresh: null,
      scheduleRefresh: null,
      scheduleRoot: null,
      setRefreshHandler: null,
      getCurrentFiber: null,
      reconcilerVersion: "18.3.1-next-f1338f8080-20240426",
    };
  if (typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ < "u") {
    var Xo = __REACT_DEVTOOLS_GLOBAL_HOOK__;
    if (!Xo.isDisabled && Xo.supportsFiber)
      try {
        (qs = Xo.inject(R0)), (yr = Xo);
      } catch {}
  }
  return (
    (It.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED = k0),
    (It.createPortal = function (t, n) {
      var s =
        2 < arguments.length && arguments[2] !== void 0 ? arguments[2] : null;
      if (!lu(n)) throw Error(i(200));
      return P0(t, n, null, s);
    }),
    (It.createRoot = function (t, n) {
      if (!lu(t)) throw Error(i(299));
      var s = !1,
        a = "",
        u = Td;
      return (
        n != null &&
          (n.unstable_strictMode === !0 && (s = !0),
          n.identifierPrefix !== void 0 && (a = n.identifierPrefix),
          n.onRecoverableError !== void 0 && (u = n.onRecoverableError)),
        (n = su(t, 1, !1, null, null, s, !1, a, u)),
        (t[Tr] = n.current),
        Qi(t.nodeType === 8 ? t.parentNode : t),
        new au(n)
      );
    }),
    (It.findDOMNode = function (t) {
      if (t == null) return null;
      if (t.nodeType === 1) return t;
      var n = t._reactInternals;
      if (n === void 0)
        throw typeof t.render == "function"
          ? Error(i(188))
          : ((t = Object.keys(t).join(",")), Error(i(268, t)));
      return (t = br(n)), (t = t === null ? null : t.stateNode), t;
    }),
    (It.flushSync = function (t) {
      return On(t);
    }),
    (It.hydrate = function (t, n, s) {
      if (!Go(n)) throw Error(i(200));
      return Wo(null, t, n, !0, s);
    }),
    (It.hydrateRoot = function (t, n, s) {
      if (!lu(t)) throw Error(i(405));
      var a = (s != null && s.hydratedSources) || null,
        u = !1,
        h = "",
        y = Td;
      if (
        (s != null &&
          (s.unstable_strictMode === !0 && (u = !0),
          s.identifierPrefix !== void 0 && (h = s.identifierPrefix),
          s.onRecoverableError !== void 0 && (y = s.onRecoverableError)),
        (n = Rd(n, null, t, 1, s ?? null, u, !1, h, y)),
        (t[Tr] = n.current),
        Qi(t),
        a)
      )
        for (t = 0; t < a.length; t++)
          (s = a[t]),
            (u = s._getVersion),
            (u = u(s._source)),
            n.mutableSourceEagerHydrationData == null
              ? (n.mutableSourceEagerHydrationData = [s, u])
              : n.mutableSourceEagerHydrationData.push(s, u);
      return new Vo(n);
    }),
    (It.render = function (t, n, s) {
      if (!Go(n)) throw Error(i(200));
      return Wo(null, t, n, !1, s);
    }),
    (It.unmountComponentAtNode = function (t) {
      if (!Go(t)) throw Error(i(40));
      return t._reactRootContainer
        ? (On(function () {
            Wo(null, null, t, !1, function () {
              (t._reactRootContainer = null), (t[Tr] = null);
            });
          }),
          !0)
        : !1;
    }),
    (It.unstable_batchedUpdates = Zl),
    (It.unstable_renderSubtreeIntoContainer = function (t, n, s, a) {
      if (!Go(s)) throw Error(i(200));
      if (t == null || t._reactInternals === void 0) throw Error(i(38));
      return Wo(t, n, s, !1, a);
    }),
    (It.version = "18.3.1-next-f1338f8080-20240426"),
    It
  );
}
var Tm;
function BS() {
  if (Tm) return wc.exports;
  Tm = 1;
  function r() {
    if (
      !(
        typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ > "u" ||
        typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE != "function"
      )
    )
      try {
        __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE(r);
      } catch (e) {
        console.error(e);
      }
  }
  return r(), (wc.exports = DS()), wc.exports;
}
var Om;
function US() {
  if (Om) return ta;
  Om = 1;
  var r = BS();
  return (ta.createRoot = r.createRoot), (ta.hydrateRoot = r.hydrateRoot), ta;
}
var jS = US();
window.axios = $e;
const $S = "Weizhen Games";
ux({
  title: (r) => `${r} - ${$S}`,
  resolve: (r) =>
    fx(
      `./Pages/${r}.jsx`,
      Object.assign({
        "./Pages/Auth/ConfirmPassword.jsx": () =>
          Pe(
            () => import("./ConfirmPassword-CGqZ4eGy.js"),
            __vite__mapDeps([6, 7, 8, 9, 10, 11, 12, 4, 5])
          ),
        "./Pages/Auth/ForgotPassword.jsx": () =>
          Pe(
            () => import("./ForgotPassword-D2wYq80S.js"),
            __vite__mapDeps([13, 7, 9, 10, 11, 12, 4, 5])
          ),
        "./Pages/Auth/Login.jsx": () =>
          Pe(
            () => import("./Login-_PHr24uR.js"),
            __vite__mapDeps([14, 15, 7, 8, 9, 10, 11, 12, 4, 5])
          ),
        "./Pages/Auth/Register.jsx": () =>
          Pe(
            () => import("./Register-k--fK94k.js"),
            __vite__mapDeps([16, 7, 8, 9, 10, 11, 12, 4, 5])
          ),
        "./Pages/Auth/ResetPassword.jsx": () =>
          Pe(
            () => import("./ResetPassword-TXam1puG.js"),
            __vite__mapDeps([17, 7, 8, 9, 10, 11, 12, 4, 5])
          ),
        "./Pages/Auth/VerifyEmail.jsx": () =>
          Pe(
            () => import("./VerifyEmail-BdCPZrp2.js"),
            __vite__mapDeps([18, 9, 11, 12, 4, 5])
          ),
        "./Pages/CentralAdmin/Layout/CentralAdminLayout.jsx": () =>
          Pe(
            () => import("./CentralAdminLayout-Cbu_i4m7.js"),
            __vite__mapDeps([19, 4, 5, 20])
          ),
        "./Pages/Dashboard.jsx": () =>
          Pe(
            () => import("./Dashboard-CovVvXVO.js"),
            __vite__mapDeps([21, 19, 4, 5, 20])
          ),
        "./Pages/Game.jsx": () =>
          Pe(
            () => import("./app-DEV1gfeS.js").then((e) => e.G),
            __vite__mapDeps([4, 5])
          ),
        "./Pages/Profile/Edit.jsx": () =>
          Pe(
            () => import("./Edit-C2Gwxhlu.js"),
            __vite__mapDeps([22, 23, 12, 24, 25, 26, 7, 8, 10, 4, 5, 27, 9, 28])
          ),
        "./Pages/Profile/Partials/DeleteUserForm.jsx": () =>
          Pe(
            () => import("./DeleteUserForm-CaYkx09F.js"),
            __vite__mapDeps([26, 7, 8, 24, 25, 10, 4, 5])
          ),
        "./Pages/Profile/Partials/UpdatePasswordForm.jsx": () =>
          Pe(
            () => import("./UpdatePasswordForm-B8a4qOZc.js"),
            __vite__mapDeps([27, 7, 8, 9, 10, 25, 4, 5])
          ),
        "./Pages/Profile/Partials/UpdateProfileInformationForm.jsx": () =>
          Pe(
            () => import("./UpdateProfileInformationForm-B7HaU-sl.js"),
            __vite__mapDeps([28, 7, 8, 9, 10, 25, 4, 5])
          ),
        "./Pages/Tenant/Admin/Deposits.jsx": () =>
          Pe(
            () => import("./Deposits-rD0cUBS9.js"),
            __vite__mapDeps([29, 30, 31, 4, 5, 32, 33])
          ),
        "./Pages/Tenant/Admin/Jackpot.jsx": () =>
          Pe(
            () => import("./Jackpot-CBhrBH6I.js"),
            __vite__mapDeps([34, 30, 31, 4, 5, 32])
          ),
        "./Pages/Tenant/Admin/Layout/AdminLayout.jsx": () =>
          Pe(
            () => import("./AdminLayout-XOYPXGkG.js"),
            __vite__mapDeps([30, 31, 4, 5, 32])
          ),
        "./Pages/Tenant/Admin/Partials/ChangePasswordModal.jsx": () =>
          Pe(
            () => import("./ChangePasswordModal-BWoRzeQs.js"),
            __vite__mapDeps([31, 4, 5])
          ),
        "./Pages/Tenant/Admin/Partials/EditUserModal.jsx": () =>
          Pe(
            () => import("./EditUserModal-Cm7Tw_4Y.js"),
            __vite__mapDeps([35, 4, 5])
          ),
        "./Pages/Tenant/Admin/Partials/ResetPasswordModal.jsx": () =>
          Pe(
            () => import("./ResetPasswordModal-BvQoIqGF.js"),
            __vite__mapDeps([36, 4, 5])
          ),
        "./Pages/Tenant/Admin/Partials/TransactionModal.jsx": () =>
          Pe(
            () => import("./TransactionModal-D6eZM7vU.js"),
            __vite__mapDeps([33, 4, 5])
          ),
        "./Pages/Tenant/Admin/SangriaFiscal.jsx": () =>
          Pe(
            () => import("./SangriaFiscal-BiGG_tFP.js"),
            __vite__mapDeps([37, 30, 31, 4, 5, 32])
          ),
        "./Pages/Tenant/Admin/SangriaFiscalProfessional.jsx": () =>
          Pe(
            () => import("./SangriaFiscalProfessional-CPfaWSjD.js"),
            __vite__mapDeps([38, 4, 5])
          ),
        "./Pages/Tenant/Admin/SangriaFiscal_backup.jsx": () =>
          Pe(
            () => import("./SangriaFiscal_backup-BvKzKN2U.js"),
            __vite__mapDeps([39, 30, 31, 4, 5, 32])
          ),
        "./Pages/Tenant/Admin/Settings.jsx": () =>
          Pe(
            () => import("./Settings-CkZO6HhW.js"),
            __vite__mapDeps([40, 30, 31, 4, 5, 32])
          ),
        "./Pages/Tenant/Admin/Users.jsx": () =>
          Pe(
            () => import("./Users-CIkGEKaF.js"),
            __vite__mapDeps([41, 30, 31, 4, 5, 32, 35, 36])
          ),
        "./Pages/Tenant/Admin/WeizhenManager.jsx": () =>
          Pe(
            () => import("./WeizhenManager-DHEFPIOy.js"),
            __vite__mapDeps([42, 30, 31, 4, 5, 32])
          ),
        "./Pages/Tenant/Admin/Withdrawals.jsx": () =>
          Pe(
            () => import("./Withdrawals-DmZsUA6j.js"),
            __vite__mapDeps([43, 30, 31, 4, 5, 32, 33])
          ),
        "./Pages/Tenant/Auth/Login.jsx": () =>
          Pe(
            () => import("./Login-Db_DB0y2.js"),
            __vite__mapDeps([44, 15, 7, 8, 9, 10, 4, 5])
          ),
        "./Pages/Tenant/Auth/Register.jsx": () =>
          Pe(
            () => import("./Register-CgqfjIpJ.js"),
            __vite__mapDeps([45, 10, 4, 5])
          ),
        "./Pages/Tenant/Game/InGame.jsx": () =>
          Pe(
            () => import("./InGame-BuzDpMYM.js"),
            __vite__mapDeps([46, 47, 2, 48, 49, 50, 4, 5])
          ),
        "./Pages/Tenant/Game/Launch.jsx": () =>
          Pe(
            () => import("./Launch-CvycAOTb.js"),
            __vite__mapDeps([51, 52, 53, 49, 50, 4, 5, 54])
          ),
        "./Pages/Tenant/Game/LobbyUI.jsx": () =>
          Pe(
            () => import("./LobbyUI-BKWQ5jUv.js"),
            __vite__mapDeps([55, 4, 5])
          ),
        "./Pages/Tenant/Game/Main.jsx": () =>
          Pe(
            () => import("./Main-CNXtrjPC.js").then((e) => e.M),
            __vite__mapDeps([56, 49, 47, 2, 48, 52, 53, 3])
          ),
        "./Pages/Tenant/Unauthorized.jsx": () =>
          Pe(
            () => import("./Unauthorized-B1N0TLZf.js"),
            __vite__mapDeps([57, 4, 5])
          ),
        "./Pages/Tenants/Create.jsx": () =>
          Pe(
            () => import("./Create-DUD93sqd.js"),
            __vite__mapDeps([58, 23, 12, 24, 25, 4, 5])
          ),
        "./Pages/Welcome.jsx": () =>
          Pe(
            () => import("./Welcome-B6zCJ_m7.js"),
            __vite__mapDeps([59, 4, 5])
          ),
      })
    ),
  setup({ el: r, App: e, props: i }) {
    jS.createRoot(r).render(D0.jsx(e, { ...i }));
  },
  progress: { color: "#4B5563" },
});
export {
  dE as $,
  fS as A,
  hS as B,
  Fx as C,
  sf as D,
  ft as E,
  Id as F,
  BS as G,
  uE as H,
  Rg as I,
  Wc as J,
  gn as K,
  cE as L,
  Sx as M,
  Ve as N,
  gt as O,
  Er as P,
  Mm as Q,
  Lc as R,
  Rs as S,
  cg as T,
  Hc as U,
  lS as V,
  wn as W,
  Wx as X,
  pa as Y,
  tS as Z,
  Pe as _,
  lE as a,
  iS as a0,
  Ax as a1,
  hE as b,
  $e as c,
  Pr as d,
  Am as e,
  Fs as f,
  zr as g,
  tt as h,
  Ux as i,
  D0 as j,
  jr as k,
  qr as l,
  xn as m,
  sm as n,
  of as o,
  Hr as p,
  Pm as q,
  ee as r,
  _i as s,
  aE as t,
  fE as u,
  Pi as v,
  vn as w,
  Em as x,
  wi as y,
  Ig as z,
};
