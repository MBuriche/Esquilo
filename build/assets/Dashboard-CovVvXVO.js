import {
  a as H,
  r as o,
  u as z,
  j as e,
  H as R,
  L as U,
  b as L,
} from "./app-ISxEiS1S.js";
import F from "./CentralAdminLayout-Cbu_i4m7.js";
import "./app-DEV1gfeS.js";
function w({ open: l, onClose: d, title: a, children: r, size: m = "md" }) {
  if (!l) return null;
  const x = {
    md: "max-w-md",
    lg: "max-w-2xl",
    xl: "max-w-4xl",
    "2xl": "max-w-6xl",
  };
  return e.jsx("div", {
    className:
      "fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm",
    onClick: d,
    children: e.jsxs("div", {
      className: `bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full ${x[m]} m-4 overflow-hidden max-h-[90vh] flex flex-col`,
      onClick: (c) => c.stopPropagation(),
      children: [
        e.jsxs("div", {
          className:
            "flex justify-between items-center p-6 border-b border-gray-700 flex-shrink-0",
          children: [
            e.jsx("h3", {
              className: "text-lg font-semibold text-white",
              children: a,
            }),
            e.jsx("button", {
              className:
                "text-gray-400 hover:text-gray-300 transition-colors p-1 rounded-md hover:bg-gray-800",
              onClick: d,
              children: e.jsx("svg", {
                xmlns: "http://www.w3.org/2000/svg",
                className: "h-5 w-5",
                fill: "none",
                viewBox: "0 0 24 24",
                stroke: "currentColor",
                children: e.jsx("path", {
                  strokeLinecap: "round",
                  strokeLinejoin: "round",
                  strokeWidth: 2,
                  d: "M6 18L18 6M6 6l12 12",
                }),
              }),
            }),
          ],
        }),
        e.jsx("div", { className: "p-6 overflow-auto flex-1", children: r }),
      ],
    }),
  });
}
function V({ open: l, onClose: d, tenantId: a }) {
  const [r, m] = o.useState([]),
    [x, c] = o.useState(!1),
    [y, k] = o.useState(null),
    h = o.useRef(null),
    b = async () => {
      if (a)
        try {
          c(!0);
          const t = await fetch(`/tenant/live-games?tenant=${a}`, {
            credentials: "include",
            headers: {
              Accept: "application/json",
              "X-Requested-With": "XMLHttpRequest",
            },
          });
          if (t.ok) {
            const n = await t.json();
            m(n.games || []), k(new Date(n.timestamp));
          }
        } catch (t) {
          console.error("Error fetching live games:", t);
        } finally {
          c(!1);
        }
    };
  o.useEffect(
    () => (
      l && a && (b(), (h.current = setInterval(b, 2e3))),
      () => {
        h.current && (clearInterval(h.current), (h.current = null));
      }
    ),
    [l, a]
  );
  const p = (t) =>
      new Intl.NumberFormat("pt-BR", {
        style: "currency",
        currency: "BRL",
      }).format(t),
    g = (t) =>
      t.is_live
        ? e.jsxs("span", {
            className:
              "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-900/50 text-green-300",
            children: [
              e.jsx("div", {
                className:
                  "w-1.5 h-1.5 bg-green-400 rounded-full mr-1.5 animate-pulse",
              }),
              "Ao Vivo (",
              t.chests_opened,
              "/9)",
            ],
          })
        : t.status === "finished"
        ? t.found_fox
          ? e.jsx("span", {
              className:
                "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-900/50 text-red-300",
              children: "🦊 Perdeu",
            })
          : t.completed_game
          ? e.jsx("span", {
              className:
                "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-900/50 text-blue-300",
              children: "✅ Completou",
            })
          : t.cash_out
          ? e.jsx("span", {
              className:
                "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-900/50 text-yellow-300",
              children: "💰 Cash Out",
            })
          : e.jsx("span", {
              className:
                "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-900/50 text-gray-300",
              children: "Finalizado",
            })
        : e.jsx("span", {
            className:
              "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-900/50 text-gray-300",
            children: t.status,
          }),
    j = (t) => {
      switch (t) {
        case "generous":
          return "text-green-400";
        case "restrictive":
          return "text-red-400";
        case "balanced":
        default:
          return "text-yellow-400";
      }
    };
  return e.jsx(w, {
    open: l,
    onClose: d,
    title: `Jogos Ao Vivo - Tenant ${a}`,
    size: "2xl",
    children: e.jsxs("div", {
      className: "space-y-4",
      children: [
        e.jsxs("div", {
          className: "flex items-center justify-between",
          children: [
            e.jsx("div", {
              className: "flex items-center space-x-4",
              children: e.jsxs("div", {
                className: "flex items-center space-x-2",
                children: [
                  x
                    ? e.jsx("div", {
                        className:
                          "w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full animate-spin",
                      })
                    : e.jsx("div", {
                        className:
                          "w-2 h-2 bg-green-400 rounded-full animate-pulse",
                      }),
                  e.jsx("span", {
                    className: "text-sm text-gray-400",
                    children: "Atualização instantânea",
                  }),
                ],
              }),
            }),
            y &&
              e.jsxs("span", {
                className: "text-xs text-gray-500",
                children: ["Última atualização: ", y.toLocaleTimeString()],
              }),
          ],
        }),
        e.jsx("div", {
          className: "bg-gray-800/30 rounded-lg overflow-hidden",
          children: e.jsx("div", {
            className: "overflow-x-auto",
            children: e.jsxs("table", {
              className: "min-w-full divide-y divide-gray-700/50",
              children: [
                e.jsx("thead", {
                  className: "bg-gray-900/50",
                  children: e.jsxs("tr", {
                    children: [
                      e.jsx("th", {
                        className:
                          "px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase",
                        children: "Jogador",
                      }),
                      e.jsx("th", {
                        className:
                          "px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase",
                        children: "Aposta",
                      }),
                      e.jsx("th", {
                        className:
                          "px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase",
                        children: "Ganho Atual",
                      }),
                      e.jsx("th", {
                        className:
                          "px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase",
                        children: "Status",
                      }),
                      e.jsx("th", {
                        className:
                          "px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase",
                        children: "Bônus",
                      }),
                      e.jsx("th", {
                        className:
                          "px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase",
                        children: "RTP",
                      }),
                      e.jsx("th", {
                        className:
                          "px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase",
                        children: "Horário",
                      }),
                    ],
                  }),
                }),
                e.jsxs("tbody", {
                  className: "divide-y divide-gray-700/30",
                  children: [
                    r.length === 0 &&
                      e.jsx("tr", {
                        children: e.jsx("td", {
                          colSpan: 7,
                          className: "px-4 py-8 text-center text-gray-500",
                          children: x
                            ? "Carregando jogos..."
                            : "Nenhum jogo encontrado",
                        }),
                      }),
                    r.map((t) =>
                      e.jsxs(
                        "tr",
                        {
                          className: `hover:bg-gray-800/20 transition-colors ${
                            t.is_live ? "bg-green-900/10" : ""
                          }`,
                          children: [
                            e.jsx("td", {
                              className: "px-4 py-3 whitespace-nowrap",
                              children: e.jsxs("div", {
                                children: [
                                  e.jsx("div", {
                                    className: "text-sm font-medium text-white",
                                    children: t.user.name,
                                  }),
                                  e.jsx("div", {
                                    className: "text-xs text-gray-400",
                                    children: t.user.email,
                                  }),
                                ],
                              }),
                            }),
                            e.jsx("td", {
                              className: "px-4 py-3 whitespace-nowrap",
                              children: e.jsx("div", {
                                className: "text-sm font-medium text-white",
                                children: p(t.amount),
                              }),
                            }),
                            e.jsxs("td", {
                              className: "px-4 py-3 whitespace-nowrap",
                              children: [
                                e.jsx("div", {
                                  className:
                                    "text-sm font-medium text-green-400",
                                  children: p(
                                    t.is_live ? t.current_win || 0 : t.win
                                  ),
                                }),
                                t.is_live &&
                                  t.current_win > 0 &&
                                  e.jsxs("div", {
                                    className: "text-xs text-gray-500",
                                    children: [
                                      (
                                        (t.current_win / t.amount) *
                                        100
                                      ).toFixed(0),
                                      "% retorno",
                                    ],
                                  }),
                              ],
                            }),
                            e.jsx("td", {
                              className: "px-4 py-3 whitespace-nowrap",
                              children: g(t),
                            }),
                            e.jsx("td", {
                              className: "px-4 py-3 whitespace-nowrap",
                              children: t.bonus_active
                                ? e.jsxs("div", {
                                    className:
                                      "text-sm font-bold text-purple-400",
                                    children: [t.bonus_multiplier, "x"],
                                  })
                                : e.jsx("div", {
                                    className: "text-sm text-gray-500",
                                    children: "-",
                                  }),
                            }),
                            e.jsx("td", {
                              className: "px-4 py-3 whitespace-nowrap",
                              children: e.jsx("div", {
                                className: `text-sm font-medium ${j(
                                  t.rtp_mode
                                )}`,
                                children: t.rtp_mode || "balanced",
                              }),
                            }),
                            e.jsxs("td", {
                              className: "px-4 py-3 whitespace-nowrap",
                              children: [
                                e.jsx("div", {
                                  className: "text-sm text-gray-300",
                                  children: t.created_at,
                                }),
                                t.is_live &&
                                  e.jsxs("div", {
                                    className: "text-xs text-gray-500",
                                    children: ["atualizado: ", t.updated_at],
                                  }),
                              ],
                            }),
                          ],
                        },
                        t.id
                      )
                    ),
                  ],
                }),
              ],
            }),
          }),
        }),
        r.length > 0 &&
          e.jsxs("div", {
            className:
              "grid grid-cols-1 md:grid-cols-4 gap-4 pt-4 border-t border-gray-700/50",
            children: [
              e.jsxs("div", {
                className: "text-center",
                children: [
                  e.jsx("div", {
                    className: "text-2xl font-bold text-green-400",
                    children: r.filter((t) => t.is_live).length,
                  }),
                  e.jsx("div", {
                    className: "text-xs text-gray-400",
                    children: "Jogos Ativos",
                  }),
                ],
              }),
              e.jsxs("div", {
                className: "text-center",
                children: [
                  e.jsx("div", {
                    className: "text-2xl font-bold text-blue-400",
                    children: p(r.reduce((t, n) => t + n.amount, 0)),
                  }),
                  e.jsx("div", {
                    className: "text-xs text-gray-400",
                    children: "Total Apostado",
                  }),
                ],
              }),
              e.jsxs("div", {
                className: "text-center",
                children: [
                  e.jsx("div", {
                    className: "text-2xl font-bold text-purple-400",
                    children: p(
                      r.reduce(
                        (t, n) => t + (n.is_live ? n.current_win || 0 : n.win),
                        0
                      )
                    ),
                  }),
                  e.jsx("div", {
                    className: "text-xs text-gray-400",
                    children: "Total Ganho",
                  }),
                ],
              }),
              e.jsxs("div", {
                className: "text-center",
                children: [
                  e.jsx("div", {
                    className: "text-2xl font-bold text-yellow-400",
                    children: r.filter((t) => t.bonus_active).length,
                  }),
                  e.jsx("div", {
                    className: "text-xs text-gray-400",
                    children: "Com Bônus",
                  }),
                ],
              }),
            ],
          }),
      ],
    }),
  });
}
function q() {
  const { tenants: l = [], flash: d = {} } = H().props,
    [a, r] = o.useState(null),
    [m, x] = o.useState(null),
    [c, y] = o.useState({ all: !1, single: null }),
    [k, h] = o.useState(!1),
    [b, p] = o.useState(null),
    {
      data: g,
      setData: j,
      post: t,
      put: n,
      processing: N,
      errors: f,
      reset: C,
    } = z({ id: "", domain: "" }),
    _ = () => {
      C(), r("create");
    },
    M = (s) => {
      j({ id: s.id, domain: s.domains[0]?.domain || "" }), x(s), r("edit");
    },
    A = (s) => {
      x(s), r("delete");
    },
    D = (s) => {
      p(s.id), h(!0);
    },
    T = (s) => {
      s.preventDefault(),
        t(route("tenants.store"), {
          onSuccess: () => {
            r(null), C();
          },
        });
    },
    W = (s) => {
      s.preventDefault(),
        n(route("tenants.update", m.id), {
          onSuccess: () => {
            r(null), C();
          },
        });
    },
    S = () => {
      L.delete(route("tenants.destroy", m.id), {
        onSuccess: () => r(null),
        onFinish: () => x(null),
      });
    },
    B = () => {
      y({ ...c, all: !0 }),
        L.post(
          route("tenants.migrateAll"),
          {},
          { onFinish: () => y({ ...c, all: !1 }) }
        );
    },
    u = l.reduce(
      (s, i) => ({
        totalUsers: s.totalUsers + (i.total_users || 0),
        onlineUsers: s.onlineUsers + (i.online_users || 0),
        totalDeposits: s.totalDeposits + (i.total_deposits || 0),
        totalWithdrawals: s.totalWithdrawals + (i.total_withdrawals || 0),
        totalDepositAmount:
          s.totalDepositAmount + (parseFloat(i.deposit_amount) || 0),
        totalWithdrawalAmount:
          s.totalWithdrawalAmount + (parseFloat(i.withdrawal_amount) || 0),
        pendingDeposits: s.pendingDeposits + (i.pending_deposits || 0),
        pendingWithdrawals: s.pendingWithdrawals + (i.pending_withdrawals || 0),
        firstTimeDeposits: s.firstTimeDeposits + (i.first_time_deposits || 0),
        totalJackpotAmount:
          s.totalJackpotAmount + (parseFloat(i.jackpot_amount) || 0),
      }),
      {
        totalUsers: 0,
        onlineUsers: 0,
        totalDeposits: 0,
        totalWithdrawals: 0,
        totalDepositAmount: 0,
        totalWithdrawalAmount: 0,
        pendingDeposits: 0,
        pendingWithdrawals: 0,
        firstTimeDeposits: 0,
        totalJackpotAmount: 0,
      }
    ),
    v = (s) =>
      new Intl.NumberFormat("pt-BR", {
        style: "currency",
        currency: "BRL",
      }).format(s);
  return e.jsxs(F, {
    title: "Dashboard Central",
    children: [
      e.jsx(R, { title: "Dashboard Central" }),
      e.jsxs("div", {
        className: "space-y-8",
        children: [
          d.success &&
            e.jsx("div", {
              className:
                "p-4 bg-green-900/50 border border-green-700 text-green-300 rounded-lg backdrop-blur-sm",
              children: e.jsxs("div", {
                className: "flex items-center",
                children: [
                  e.jsx("svg", {
                    className: "w-5 h-5 mr-3",
                    fill: "none",
                    stroke: "currentColor",
                    viewBox: "0 0 24 24",
                    children: e.jsx("path", {
                      strokeLinecap: "round",
                      strokeLinejoin: "round",
                      strokeWidth: 2,
                      d: "M5 13l4 4L19 7",
                    }),
                  }),
                  d.success,
                ],
              }),
            }),
          d.error &&
            e.jsx("div", {
              className:
                "p-4 bg-red-900/50 border border-red-700 text-red-300 rounded-lg backdrop-blur-sm",
              children: e.jsxs("div", {
                className: "flex items-center",
                children: [
                  e.jsx("svg", {
                    className: "w-5 h-5 mr-3",
                    fill: "none",
                    stroke: "currentColor",
                    viewBox: "0 0 24 24",
                    children: e.jsx("path", {
                      strokeLinecap: "round",
                      strokeLinejoin: "round",
                      strokeWidth: 2,
                      d: "M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
                    }),
                  }),
                  d.error,
                ],
              }),
            }),
          e.jsxs("div", {
            className:
              "flex flex-col space-y-4 sm:flex-row sm:items-center sm:justify-between sm:space-y-0",
            children: [
              e.jsxs("div", {
                children: [
                  e.jsx("h1", {
                    className: "text-2xl font-bold text-white",
                    children: "Dashboard Central",
                  }),
                  e.jsx("p", {
                    className: "mt-1 text-sm text-gray-400",
                    children: "Visão geral de todos os tenants",
                  }),
                ],
              }),
              e.jsxs("div", {
                className: "flex items-center space-x-3",
                children: [
                  e.jsxs("button", {
                    onClick: B,
                    disabled: c.all,
                    className:
                      "inline-flex items-center px-4 py-2 bg-gray-700/50 border border-gray-600 rounded-lg font-medium text-sm text-gray-300 hover:bg-gray-600/50 hover:text-white focus:outline-none focus:ring-2 focus:ring-gray-500 disabled:opacity-50 transition-all duration-200",
                    children: [
                      e.jsx("svg", {
                        className: "w-4 h-4 mr-2",
                        fill: "none",
                        stroke: "currentColor",
                        viewBox: "0 0 24 24",
                        children: e.jsx("path", {
                          strokeLinecap: "round",
                          strokeLinejoin: "round",
                          strokeWidth: 2,
                          d: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15",
                        }),
                      }),
                      c.all ? "Executando..." : "Migrar Todos",
                    ],
                  }),
                  e.jsxs("button", {
                    onClick: _,
                    className:
                      "inline-flex items-center px-4 py-2 bg-blue-600/80 border border-transparent rounded-lg font-medium text-sm text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all duration-200",
                    children: [
                      e.jsx("svg", {
                        className: "w-4 h-4 mr-2",
                        fill: "none",
                        stroke: "currentColor",
                        viewBox: "0 0 24 24",
                        children: e.jsx("path", {
                          strokeLinecap: "round",
                          strokeLinejoin: "round",
                          strokeWidth: 2,
                          d: "M12 4v16m8-8H4",
                        }),
                      }),
                      "Novo Tenant",
                    ],
                  }),
                ],
              }),
            ],
          }),
          e.jsxs("div", {
            className: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-6",
            children: [
              e.jsx("div", {
                className:
                  "bg-gray-900/50 border border-gray-700/50 rounded-xl p-6 backdrop-blur-sm",
                children: e.jsxs("div", {
                  className: "flex items-center",
                  children: [
                    e.jsx("div", {
                      className: "p-3 rounded-lg bg-blue-500/20",
                      children: e.jsx("svg", {
                        className: "w-6 h-6 text-blue-400",
                        fill: "none",
                        stroke: "currentColor",
                        viewBox: "0 0 24 24",
                        children: e.jsx("path", {
                          strokeLinecap: "round",
                          strokeLinejoin: "round",
                          strokeWidth: 2,
                          d: "M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4",
                        }),
                      }),
                    }),
                    e.jsxs("div", {
                      className: "ml-4",
                      children: [
                        e.jsx("p", {
                          className: "text-sm font-medium text-gray-400",
                          children: "Total de Tenants",
                        }),
                        e.jsx("p", {
                          className: "text-2xl font-bold text-white",
                          children: l.length,
                        }),
                      ],
                    }),
                  ],
                }),
              }),
              e.jsx("div", {
                className:
                  "bg-gray-900/50 border border-gray-700/50 rounded-xl p-6 backdrop-blur-sm",
                children: e.jsxs("div", {
                  className: "flex items-center",
                  children: [
                    e.jsx("div", {
                      className: "p-3 rounded-lg bg-green-500/20",
                      children: e.jsx("svg", {
                        className: "w-6 h-6 text-green-400",
                        fill: "none",
                        stroke: "currentColor",
                        viewBox: "0 0 24 24",
                        children: e.jsx("path", {
                          strokeLinecap: "round",
                          strokeLinejoin: "round",
                          strokeWidth: 2,
                          d: "M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M15 21a6 6 0 00-9-5.197m0 0A5.975 5.975 0 0112 13a5.975 5.975 0 013 1.803M15 21a9 9 0 10-9-9",
                        }),
                      }),
                    }),
                    e.jsxs("div", {
                      className: "ml-4",
                      children: [
                        e.jsx("p", {
                          className: "text-sm font-medium text-gray-400",
                          children: "Total de Usuários",
                        }),
                        e.jsx("p", {
                          className: "text-2xl font-bold text-white",
                          children: u.totalUsers,
                        }),
                      ],
                    }),
                  ],
                }),
              }),
              e.jsx("div", {
                className:
                  "bg-gray-900/50 border border-gray-700/50 rounded-xl p-6 backdrop-blur-sm",
                children: e.jsxs("div", {
                  className: "flex items-center",
                  children: [
                    e.jsx("div", {
                      className: "p-3 rounded-lg bg-emerald-500/20",
                      children: e.jsx("svg", {
                        className: "w-6 h-6 text-emerald-400",
                        fill: "none",
                        stroke: "currentColor",
                        viewBox: "0 0 24 24",
                        children: e.jsx("path", {
                          strokeLinecap: "round",
                          strokeLinejoin: "round",
                          strokeWidth: 2,
                          d: "M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z",
                        }),
                      }),
                    }),
                    e.jsxs("div", {
                      className: "ml-4",
                      children: [
                        e.jsx("p", {
                          className: "text-sm font-medium text-gray-400",
                          children: "Usuários Online",
                        }),
                        e.jsx("p", {
                          className: "text-2xl font-bold text-emerald-400",
                          children: u.onlineUsers,
                        }),
                        e.jsx("p", {
                          className: "text-xs text-gray-500",
                          children: "últimos 5 minutos",
                        }),
                      ],
                    }),
                  ],
                }),
              }),
              e.jsx("div", {
                className:
                  "bg-gray-900/50 border border-gray-700/50 rounded-xl p-6 backdrop-blur-sm",
                children: e.jsxs("div", {
                  className: "flex items-center",
                  children: [
                    e.jsx("div", {
                      className: "p-3 rounded-lg bg-yellow-500/20",
                      children: e.jsxs("svg", {
                        className: "w-6 h-6 text-yellow-400",
                        fill: "none",
                        stroke: "currentColor",
                        viewBox: "0 0 24 24",
                        children: [
                          e.jsx("circle", {
                            cx: "12",
                            cy: "12",
                            r: "10",
                            stroke: "currentColor",
                            strokeWidth: "2",
                            fill: "none",
                          }),
                          e.jsx("path", {
                            strokeLinecap: "round",
                            strokeLinejoin: "round",
                            d: "M8 15h8M9 9h6M10 12h4",
                          }),
                        ],
                      }),
                    }),
                    e.jsxs("div", {
                      className: "ml-4",
                      children: [
                        e.jsx("p", {
                          className: "text-sm font-medium text-gray-400",
                          children: "Total Jackpots",
                        }),
                        e.jsx("p", {
                          className: "text-2xl font-bold text-yellow-400",
                          children: v(u.totalJackpotAmount),
                        }),
                        e.jsx("p", {
                          className: "text-xs text-gray-500",
                          children: "todos os tenants",
                        }),
                      ],
                    }),
                  ],
                }),
              }),
              e.jsx("div", {
                className:
                  "bg-gray-900/50 border border-gray-700/50 rounded-xl p-6 backdrop-blur-sm",
                children: e.jsxs("div", {
                  className: "flex items-center",
                  children: [
                    e.jsx("div", {
                      className: "p-3 rounded-lg bg-purple-500/20",
                      children: e.jsx("svg", {
                        className: "w-6 h-6 text-purple-400",
                        fill: "none",
                        stroke: "currentColor",
                        viewBox: "0 0 24 24",
                        children: e.jsx("path", {
                          strokeLinecap: "round",
                          strokeLinejoin: "round",
                          strokeWidth: 2,
                          d: "M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10",
                        }),
                      }),
                    }),
                    e.jsxs("div", {
                      className: "ml-4",
                      children: [
                        e.jsx("p", {
                          className: "text-sm font-medium text-gray-400",
                          children: "Total Depósitos",
                        }),
                        e.jsx("p", {
                          className: "text-2xl font-bold text-white",
                          children: v(u.totalDepositAmount),
                        }),
                        e.jsxs("p", {
                          className: "text-xs text-gray-500",
                          children: [u.totalDeposits, " transações"],
                        }),
                      ],
                    }),
                  ],
                }),
              }),
              e.jsx("div", {
                className:
                  "bg-gray-900/50 border border-gray-700/50 rounded-xl p-6 backdrop-blur-sm",
                children: e.jsxs("div", {
                  className: "flex items-center",
                  children: [
                    e.jsx("div", {
                      className: "p-3 rounded-lg bg-orange-500/20",
                      children: e.jsx("svg", {
                        className: "w-6 h-6 text-orange-400",
                        fill: "none",
                        stroke: "currentColor",
                        viewBox: "0 0 24 24",
                        children: e.jsx("path", {
                          strokeLinecap: "round",
                          strokeLinejoin: "round",
                          strokeWidth: 2,
                          d: "M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12",
                        }),
                      }),
                    }),
                    e.jsxs("div", {
                      className: "ml-4",
                      children: [
                        e.jsx("p", {
                          className: "text-sm font-medium text-gray-400",
                          children: "Total Saques",
                        }),
                        e.jsx("p", {
                          className: "text-2xl font-bold text-white",
                          children: v(u.totalWithdrawalAmount),
                        }),
                        e.jsxs("p", {
                          className: "text-xs text-gray-500",
                          children: [u.totalWithdrawals, " transações"],
                        }),
                      ],
                    }),
                  ],
                }),
              }),
            ],
          }),
          e.jsxs("div", {
            className:
              "bg-gray-900/50 border border-gray-700/50 rounded-xl overflow-hidden backdrop-blur-sm",
            children: [
              e.jsx("div", {
                className: "px-6 py-4 border-b border-gray-700/50",
                children: e.jsx("h3", {
                  className: "text-lg font-semibold text-white",
                  children: "Tenants Detalhados",
                }),
              }),
              e.jsx("div", {
                className: "overflow-x-auto",
                children: e.jsxs("table", {
                  className: "min-w-full divide-y divide-gray-700/50",
                  children: [
                    e.jsx("thead", {
                      className: "bg-gray-800/30",
                      children: e.jsxs("tr", {
                        children: [
                          e.jsx("th", {
                            className:
                              "px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider",
                            children: "Tenant",
                          }),
                          e.jsx("th", {
                            className:
                              "px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider",
                            children: "Usuários",
                          }),
                          e.jsx("th", {
                            className:
                              "px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider",
                            children: "Online",
                          }),
                          e.jsx("th", {
                            className:
                              "px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider",
                            children: "Jackpot",
                          }),
                          e.jsx("th", {
                            className:
                              "px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider",
                            children: "Depósitos",
                          }),
                          e.jsx("th", {
                            className:
                              "px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider",
                            children: "Saques",
                          }),
                          e.jsx("th", {
                            className:
                              "px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider",
                            children: "Pendentes",
                          }),
                          e.jsx("th", {
                            className:
                              "px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider",
                            children: "Status",
                          }),
                          e.jsx("th", {
                            className:
                              "px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider",
                            children: "Ações",
                          }),
                        ],
                      }),
                    }),
                    e.jsxs("tbody", {
                      className: "divide-y divide-gray-700/50",
                      children: [
                        l.length === 0 &&
                          e.jsx("tr", {
                            children: e.jsx("td", {
                              colSpan: 9,
                              className: "px-6 py-12 text-center",
                              children: e.jsxs("div", {
                                className: "text-center",
                                children: [
                                  e.jsx("svg", {
                                    className:
                                      "mx-auto h-12 w-12 text-gray-600",
                                    fill: "none",
                                    viewBox: "0 0 24 24",
                                    stroke: "currentColor",
                                    children: e.jsx("path", {
                                      strokeLinecap: "round",
                                      strokeLinejoin: "round",
                                      strokeWidth: 2,
                                      d: "M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4",
                                    }),
                                  }),
                                  e.jsx("h3", {
                                    className:
                                      "mt-4 text-lg font-medium text-gray-300",
                                    children: "Nenhum tenant encontrado",
                                  }),
                                  e.jsx("p", {
                                    className: "mt-2 text-sm text-gray-500",
                                    children:
                                      "Comece criando seu primeiro tenant.",
                                  }),
                                ],
                              }),
                            }),
                          }),
                        l.map((s) =>
                          e.jsxs(
                            "tr",
                            {
                              className:
                                "hover:bg-gray-800/30 transition-colors",
                              children: [
                                e.jsx("td", {
                                  className: "px-6 py-4 whitespace-nowrap",
                                  children: e.jsxs("div", {
                                    className: "flex items-center",
                                    children: [
                                      e.jsx("div", {
                                        className:
                                          "w-10 h-10 bg-gradient-to-br from-purple-500 to-blue-500 rounded-lg flex items-center justify-center mr-3",
                                        children: e.jsx("span", {
                                          className:
                                            "text-sm font-bold text-white",
                                          children: s.id
                                            .charAt(0)
                                            .toUpperCase(),
                                        }),
                                      }),
                                      e.jsxs("div", {
                                        children: [
                                          e.jsx("div", {
                                            className:
                                              "text-sm font-medium text-white",
                                            children: s.id,
                                          }),
                                          e.jsx("div", {
                                            className: "text-sm text-gray-400",
                                            children:
                                              s.domains[0]?.domain || "N/A",
                                          }),
                                        ],
                                      }),
                                    ],
                                  }),
                                }),
                                e.jsxs("td", {
                                  className: "px-6 py-4 whitespace-nowrap",
                                  children: [
                                    e.jsx("div", {
                                      className:
                                        "text-sm text-white font-medium",
                                      children: s.total_users || 0,
                                    }),
                                    e.jsxs("div", {
                                      className: "text-xs text-gray-400",
                                      children: [
                                        s.active_users_last_30_days || 0,
                                        " ativos (30d)",
                                      ],
                                    }),
                                  ],
                                }),
                                e.jsxs("td", {
                                  className: "px-6 py-4 whitespace-nowrap",
                                  children: [
                                    e.jsxs("div", {
                                      className: "flex items-center",
                                      children: [
                                        e.jsx("div", {
                                          className: `w-2 h-2 rounded-full mr-2 ${
                                            (s.online_users || 0) > 0
                                              ? "bg-green-400 animate-pulse"
                                              : "bg-gray-500"
                                          }`,
                                        }),
                                        e.jsx("div", {
                                          className:
                                            "text-sm text-emerald-400 font-medium",
                                          children: s.online_users || 0,
                                        }),
                                      ],
                                    }),
                                    e.jsx("div", {
                                      className: "text-xs text-gray-500",
                                      children: "últimos 5min",
                                    }),
                                  ],
                                }),
                                e.jsxs("td", {
                                  className: "px-6 py-4 whitespace-nowrap",
                                  children: [
                                    e.jsx("div", {
                                      className:
                                        "text-sm text-yellow-400 font-medium",
                                      children: v(s.jackpot_amount || 0),
                                    }),
                                    e.jsx("div", {
                                      className: "text-xs text-gray-400",
                                      children: "prêmio acumulado",
                                    }),
                                  ],
                                }),
                                e.jsxs("td", {
                                  className: "px-6 py-4 whitespace-nowrap",
                                  children: [
                                    e.jsx("div", {
                                      className:
                                        "text-sm text-white font-medium",
                                      children: v(s.deposit_amount || 0),
                                    }),
                                    e.jsxs("div", {
                                      className: "text-xs text-gray-400",
                                      children: [
                                        s.total_deposits || 0,
                                        " transações",
                                      ],
                                    }),
                                    e.jsxs("div", {
                                      className: "text-xs text-green-400",
                                      children: [
                                        s.first_time_deposits || 0,
                                        " primeiros depósitos",
                                      ],
                                    }),
                                  ],
                                }),
                                e.jsxs("td", {
                                  className: "px-6 py-4 whitespace-nowrap",
                                  children: [
                                    e.jsx("div", {
                                      className:
                                        "text-sm text-white font-medium",
                                      children: v(s.withdrawal_amount || 0),
                                    }),
                                    e.jsxs("div", {
                                      className: "text-xs text-gray-400",
                                      children: [
                                        s.total_withdrawals || 0,
                                        " transações",
                                      ],
                                    }),
                                  ],
                                }),
                                e.jsx("td", {
                                  className: "px-6 py-4 whitespace-nowrap",
                                  children: e.jsxs("div", {
                                    className: "space-y-1",
                                    children: [
                                      (s.pending_deposits || 0) > 0 &&
                                        e.jsxs("div", {
                                          className:
                                            "inline-flex items-center px-2 py-1 rounded-full text-xs bg-yellow-900/50 text-yellow-300",
                                          children: [
                                            s.pending_deposits,
                                            " depósitos",
                                          ],
                                        }),
                                      (s.pending_withdrawals || 0) > 0 &&
                                        e.jsxs("div", {
                                          className:
                                            "inline-flex items-center px-2 py-1 rounded-full text-xs bg-orange-900/50 text-orange-300",
                                          children: [
                                            s.pending_withdrawals,
                                            " saques",
                                          ],
                                        }),
                                      (s.pending_deposits || 0) === 0 &&
                                        (s.pending_withdrawals || 0) === 0 &&
                                        e.jsx("div", {
                                          className: "text-xs text-gray-500",
                                          children: "Nenhum pendente",
                                        }),
                                    ],
                                  }),
                                }),
                                e.jsx("td", {
                                  className: "px-6 py-4 whitespace-nowrap",
                                  children: e.jsxs("span", {
                                    className:
                                      "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-900/50 text-green-300",
                                    children: [
                                      e.jsx("div", {
                                        className:
                                          "w-1.5 h-1.5 bg-green-400 rounded-full mr-1.5",
                                      }),
                                      "Ativo",
                                    ],
                                  }),
                                }),
                                e.jsx("td", {
                                  className:
                                    "px-6 py-4 whitespace-nowrap text-right text-sm font-medium",
                                  children: e.jsxs("div", {
                                    className:
                                      "flex items-center justify-end space-x-2",
                                    children: [
                                      e.jsx("button", {
                                        onClick: () => D(s),
                                        className:
                                          "inline-flex items-center p-1.5 text-gray-400 hover:text-green-400 rounded-md hover:bg-gray-800/50 transition-colors",
                                        title: "Jogos Ao Vivo",
                                        children: e.jsx("svg", {
                                          className: "w-4 h-4",
                                          fill: "none",
                                          stroke: "currentColor",
                                          viewBox: "0 0 24 24",
                                          children: e.jsx("path", {
                                            strokeLinecap: "round",
                                            strokeLinejoin: "round",
                                            strokeWidth: 2,
                                            d: "M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z",
                                          }),
                                        }),
                                      }),
                                      e.jsx(U, {
                                        href: `http://${s.domains[0]?.domain}/admin/weizhen-manager`,
                                        target: "_blank",
                                        className:
                                          "inline-flex items-center p-1.5 text-gray-400 hover:text-purple-400 rounded-md hover:bg-gray-800/50 transition-colors",
                                        title: "Acessar Admin",
                                        children: e.jsx("svg", {
                                          className: "w-4 h-4",
                                          fill: "none",
                                          stroke: "currentColor",
                                          viewBox: "0 0 24 24",
                                          children: e.jsx("path", {
                                            strokeLinecap: "round",
                                            strokeLinejoin: "round",
                                            strokeWidth: 2,
                                            d: "M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14",
                                          }),
                                        }),
                                      }),
                                      e.jsx("a", {
                                        href: route("tenants.exportSql", s.id),
                                        className:
                                          "inline-flex items-center p-1.5 text-gray-400 hover:text-yellow-400 rounded-md hover:bg-gray-800/50 transition-colors",
                                        title: "Exportar SQL",
                                        download: !0,
                                        children: e.jsx("svg", {
                                          className: "w-4 h-4",
                                          fill: "none",
                                          stroke: "currentColor",
                                          viewBox: "0 0 24 24",
                                          children: e.jsx("path", {
                                            strokeLinecap: "round",
                                            strokeLinejoin: "round",
                                            strokeWidth: 2,
                                            d: "M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z",
                                          }),
                                        }),
                                      }),
                                      e.jsx("button", {
                                        onClick: () => M(s),
                                        className:
                                          "inline-flex items-center p-1.5 text-gray-400 hover:text-blue-400 rounded-md hover:bg-gray-800/50 transition-colors",
                                        title: "Editar",
                                        children: e.jsx("svg", {
                                          className: "w-4 h-4",
                                          fill: "none",
                                          stroke: "currentColor",
                                          viewBox: "0 0 24 24",
                                          children: e.jsx("path", {
                                            strokeLinecap: "round",
                                            strokeLinejoin: "round",
                                            strokeWidth: 2,
                                            d: "M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z",
                                          }),
                                        }),
                                      }),
                                      e.jsx("button", {
                                        onClick: () => A(s),
                                        className:
                                          "inline-flex items-center p-1.5 text-gray-400 hover:text-red-400 rounded-md hover:bg-gray-800/50 transition-colors",
                                        title: "Remover",
                                        children: e.jsx("svg", {
                                          className: "w-4 h-4",
                                          fill: "none",
                                          stroke: "currentColor",
                                          viewBox: "0 0 24 24",
                                          children: e.jsx("path", {
                                            strokeLinecap: "round",
                                            strokeLinejoin: "round",
                                            strokeWidth: 2,
                                            d: "M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16",
                                          }),
                                        }),
                                      }),
                                    ],
                                  }),
                                }),
                              ],
                            },
                            s.id
                          )
                        ),
                      ],
                    }),
                  ],
                }),
              }),
            ],
          }),
        ],
      }),
      e.jsx(V, { open: k, onClose: () => h(!1), tenantId: b }),
      e.jsx(w, {
        open: a === "create",
        onClose: () => r(null),
        title: "Criar Novo Tenant",
        children: e.jsxs("form", {
          onSubmit: T,
          className: "space-y-6",
          children: [
            e.jsxs("div", {
              children: [
                e.jsx("label", {
                  htmlFor: "create-id",
                  className: "block text-sm font-medium text-gray-300 mb-2",
                  children: "ID do Tenant",
                }),
                e.jsx("input", {
                  id: "create-id",
                  type: "text",
                  value: g.id,
                  onChange: (s) => j("id", s.target.value),
                  className:
                    "w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent",
                  placeholder: "ex: empresa1",
                }),
                f.id &&
                  e.jsx("p", {
                    className: "mt-2 text-sm text-red-400",
                    children: f.id,
                  }),
              ],
            }),
            e.jsxs("div", {
              children: [
                e.jsx("label", {
                  htmlFor: "create-domain",
                  className: "block text-sm font-medium text-gray-300 mb-2",
                  children: "Domínio",
                }),
                e.jsx("input", {
                  id: "create-domain",
                  type: "text",
                  value: g.domain,
                  onChange: (s) => j("domain", s.target.value),
                  className:
                    "w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent",
                  placeholder: "ex: empresa1.exemplo.com",
                }),
                f.domain &&
                  e.jsx("p", {
                    className: "mt-2 text-sm text-red-400",
                    children: f.domain,
                  }),
              ],
            }),
            e.jsxs("div", {
              className: "flex justify-end space-x-3 pt-4",
              children: [
                e.jsx("button", {
                  type: "button",
                  onClick: () => r(null),
                  className:
                    "px-4 py-2 text-sm font-medium text-gray-300 bg-gray-700 border border-gray-600 rounded-lg hover:bg-gray-600 transition-colors",
                  children: "Cancelar",
                }),
                e.jsx("button", {
                  type: "submit",
                  disabled: N,
                  className:
                    "px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors",
                  children: N ? "Criando..." : "Criar Tenant",
                }),
              ],
            }),
          ],
        }),
      }),
      e.jsx(w, {
        open: a === "edit",
        onClose: () => r(null),
        title: "Editar Tenant",
        children: e.jsxs("form", {
          onSubmit: W,
          className: "space-y-6",
          children: [
            e.jsxs("div", {
              children: [
                e.jsx("label", {
                  className: "block text-sm font-medium text-gray-300 mb-2",
                  children: "ID do Tenant",
                }),
                e.jsx("input", {
                  type: "text",
                  value: g.id,
                  disabled: !0,
                  className:
                    "w-full px-3 py-2 bg-gray-800/50 border border-gray-600 rounded-lg text-gray-400",
                }),
              ],
            }),
            e.jsxs("div", {
              children: [
                e.jsx("label", {
                  htmlFor: "edit-domain",
                  className: "block text-sm font-medium text-gray-300 mb-2",
                  children: "Domínio",
                }),
                e.jsx("input", {
                  id: "edit-domain",
                  type: "text",
                  value: g.domain,
                  onChange: (s) => j("domain", s.target.value),
                  className:
                    "w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent",
                }),
                f.domain &&
                  e.jsx("p", {
                    className: "mt-2 text-sm text-red-400",
                    children: f.domain,
                  }),
              ],
            }),
            e.jsxs("div", {
              className: "flex justify-end space-x-3 pt-4",
              children: [
                e.jsx("button", {
                  type: "button",
                  onClick: () => r(null),
                  className:
                    "px-4 py-2 text-sm font-medium text-gray-300 bg-gray-700 border border-gray-600 rounded-lg hover:bg-gray-600 transition-colors",
                  children: "Cancelar",
                }),
                e.jsx("button", {
                  type: "submit",
                  disabled: N,
                  className:
                    "px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors",
                  children: N ? "Salvando..." : "Salvar Alterações",
                }),
              ],
            }),
          ],
        }),
      }),
      e.jsx(w, {
        open: a === "delete",
        onClose: () => r(null),
        title: "Remover Tenant",
        children: e.jsxs("div", {
          className: "space-y-4",
          children: [
            e.jsxs("div", {
              className: "flex items-center space-x-3",
              children: [
                e.jsx("div", {
                  className: "flex-shrink-0",
                  children: e.jsx("svg", {
                    className: "h-10 w-10 text-red-400",
                    fill: "none",
                    viewBox: "0 0 24 24",
                    stroke: "currentColor",
                    children: e.jsx("path", {
                      strokeLinecap: "round",
                      strokeLinejoin: "round",
                      strokeWidth: 2,
                      d: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z",
                    }),
                  }),
                }),
                e.jsxs("div", {
                  children: [
                    e.jsx("h3", {
                      className: "text-lg font-medium text-white",
                      children: "Confirmar remoção",
                    }),
                    e.jsxs("p", {
                      className: "text-sm text-gray-400",
                      children: [
                        "Tem certeza que deseja remover o tenant ",
                        e.jsx("span", {
                          className: "font-semibold text-white",
                          children: m?.id,
                        }),
                        "? Esta ação não pode ser desfeita.",
                      ],
                    }),
                  ],
                }),
              ],
            }),
            e.jsxs("div", {
              className: "flex justify-end space-x-3 pt-4",
              children: [
                e.jsx("button", {
                  type: "button",
                  onClick: () => r(null),
                  className:
                    "px-4 py-2 text-sm font-medium text-gray-300 bg-gray-700 border border-gray-600 rounded-lg hover:bg-gray-600 transition-colors",
                  children: "Cancelar",
                }),
                e.jsx("button", {
                  type: "button",
                  onClick: S,
                  className:
                    "px-4 py-2 text-sm font-medium text-white bg-red-600 border border-transparent rounded-lg hover:bg-red-700 transition-colors",
                  children: "Remover Tenant",
                }),
              ],
            }),
          ],
        }),
      }),
    ],
  });
}
export { q as default };
