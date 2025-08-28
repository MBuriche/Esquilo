import { r as i, c as D, j as e, b as se, R as W } from "./app-ISxEiS1S.js";
function ae({ isOpen: w, onClose: z, user: m }) {
  const [j, t] = i.useState([]),
    [d, g] = i.useState(null),
    [h, u] = i.useState(null),
    [l, c] = i.useState(!1),
    [C, v] = i.useState(1);
  i.useEffect(() => {
    w && N(1);
  }, [w]);
  const N = async (a = 1) => {
      c(!0);
      try {
        const s = await D.get(`/game-history?page=${a}`);
        t(a === 1 ? s.data.histories : (n) => [...n, ...s.data.histories]),
          g(s.data.statistics),
          u(s.data.pagination),
          v(a);
      } catch (s) {
        console.error("Error fetching history:", s);
      } finally {
        c(!1);
      }
    },
    x = () => {
      h && h.has_more && !l && N(C + 1);
    },
    b = (a) => `BRL ${parseFloat(a).toFixed(2)}`,
    _ = (a) =>
      new Date(a).toLocaleString("pt-BR", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }),
    M = (a) =>
      parseFloat(a.win) > 0
        ? e.jsx("svg", {
            width: "16",
            height: "16",
            viewBox: "0 0 24 24",
            fill: "#4caf50",
            children: e.jsx("path", {
              d: "M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z",
            }),
          })
        : e.jsx("svg", {
            width: "16",
            height: "16",
            viewBox: "0 0 24 24",
            fill: "#f44336",
            children: e.jsx("path", {
              d: "M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z",
            }),
          }),
    o = (a) => {
      const s = parseFloat(a.win) - parseFloat(a.amount),
        n = s > 0;
      return {
        amount: Math.abs(s),
        isPositive: n,
        formatted: `${n ? "+" : "-"}${b(Math.abs(s))}`,
      };
    };
  return w
    ? e.jsx("div", {
        className: "profile-modal-overlay",
        onClick: z,
        children: e.jsxs("div", {
          className: "profile-modal history-modal",
          onClick: (a) => a.stopPropagation(),
          children: [
            e.jsxs("div", {
              className: "profile-modal-header",
              children: [
                e.jsx("h2", { children: "Histórico de Partidas" }),
                e.jsx("button", {
                  className: "profile-modal-close",
                  onClick: z,
                  children: "✕",
                }),
              ],
            }),
            d &&
              e.jsx("div", {
                className: "history-statistics",
                children: e.jsxs("div", {
                  className: "stats-grid",
                  children: [
                    e.jsxs("div", {
                      className: "stat-item",
                      children: [
                        e.jsx("span", {
                          className: "stat-label",
                          children: "Total de Jogos",
                        }),
                        e.jsx("span", {
                          className: "stat-value",
                          children: d.total_games,
                        }),
                      ],
                    }),
                    e.jsxs("div", {
                      className: "stat-item",
                      children: [
                        e.jsx("span", {
                          className: "stat-label",
                          children: "Taxa de Vitória",
                        }),
                        e.jsxs("span", {
                          className: "stat-value win-rate",
                          children: [d.win_rate, "%"],
                        }),
                      ],
                    }),
                    e.jsxs("div", {
                      className: "stat-item",
                      children: [
                        e.jsx("span", {
                          className: "stat-label",
                          children: "Taxa de Derrota",
                        }),
                        e.jsxs("span", {
                          className: "stat-value loss-rate",
                          children: [d.loss_rate, "%"],
                        }),
                      ],
                    }),
                    e.jsxs("div", {
                      className: "stat-item",
                      children: [
                        e.jsx("span", {
                          className: "stat-label",
                          children: "Lucro Líquido",
                        }),
                        e.jsxs("span", {
                          className: `stat-value ${
                            d.net_profit >= 0 ? "profit" : "loss"
                          }`,
                          children: [
                            d.net_profit >= 0 ? "+" : "",
                            b(d.net_profit),
                          ],
                        }),
                      ],
                    }),
                  ],
                }),
              }),
            e.jsx("div", {
              className: "history-content",
              children:
                l && j.length === 0
                  ? e.jsxs("div", {
                      className: "history-loading",
                      children: [
                        e.jsx("div", { className: "loading-spinner" }),
                        e.jsx("span", { children: "Carregando histórico..." }),
                      ],
                    })
                  : j.length === 0
                  ? e.jsxs("div", {
                      className: "history-empty",
                      children: [
                        e.jsx("center", {
                          children: e.jsx("div", {
                            className: "empty-icon center",
                            children: e.jsx("svg", {
                              width: "48",
                              height: "48",
                              viewBox: "0 0 24 24",
                              fill: "rgba(255,255,255,0.3)",
                              children: e.jsx("path", {
                                d: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z",
                              }),
                            }),
                          }),
                        }),
                        e.jsx("h3", {
                          children: "Nenhum histórico encontrado",
                        }),
                        e.jsx("p", {
                          children:
                            "Você ainda não jogou nenhuma partida. Comece a jogar para ver seu histórico aqui!",
                        }),
                      ],
                    })
                  : e.jsxs(e.Fragment, {
                      children: [
                        e.jsx("div", {
                          className: "history-list",
                          children: j.map((a, s) => {
                            const n = o(a);
                            return e.jsxs(
                              "div",
                              {
                                className: "history-item",
                                children: [
                                  e.jsxs("div", {
                                    className: "history-item-header",
                                    children: [
                                      e.jsx("div", {
                                        className: "result-indicator",
                                        children: M(a),
                                      }),
                                      e.jsxs("div", {
                                        className: "history-details",
                                        children: [
                                          e.jsx("div", {
                                            className: "history-date",
                                            children: _(a.created_at),
                                          }),
                                          e.jsx("div", {
                                            className: "history-status",
                                            children:
                                              parseFloat(a.win) > 0
                                                ? "Vitória"
                                                : "Derrota",
                                          }),
                                        ],
                                      }),
                                      e.jsxs("div", {
                                        className: "history-amounts",
                                        children: [
                                          e.jsxs("div", {
                                            className: "bet-amount",
                                            children: ["Aposta: ", b(a.amount)],
                                          }),
                                          e.jsx("div", {
                                            className: `net-result ${
                                              n.isPositive ? "profit" : "loss"
                                            }`,
                                            children: n.formatted,
                                          }),
                                        ],
                                      }),
                                    ],
                                  }),
                                  a.result &&
                                    e.jsxs("div", {
                                      className: "history-result",
                                      style: { display: "none" },
                                      children: [
                                        e.jsx("span", {
                                          className: "result-label",
                                          children: "Resultado:",
                                        }),
                                        e.jsx("span", {
                                          className: "result-value",
                                          children: a.result,
                                        }),
                                      ],
                                    }),
                                ],
                              },
                              s
                            );
                          }),
                        }),
                        h &&
                          h.has_more &&
                          e.jsx("div", {
                            className: "history-load-more",
                            children: e.jsx("button", {
                              className: "load-more-btn",
                              onClick: x,
                              disabled: l,
                              children: l
                                ? e.jsxs(e.Fragment, {
                                    children: [
                                      e.jsx("div", {
                                        className: "loading-spinner small",
                                      }),
                                      "Carregando...",
                                    ],
                                  })
                                : "Carregar Mais",
                            }),
                          }),
                      ],
                    }),
            }),
          ],
        }),
      })
    : null;
}
function te({ isOpen: w, onClose: z, user: m }) {
  const [j, t] = i.useState({
      current_password: "",
      password: "",
      password_confirmation: "",
    }),
    [d, g] = i.useState({}),
    [h, u] = i.useState(!1),
    [l, c] = i.useState(!1),
    C = (b) => {
      const { name: _, value: M } = b.target;
      t((o) => ({ ...o, [_]: M })), d[_] && g((o) => ({ ...o, [_]: void 0 }));
    },
    v = async (b) => {
      b.preventDefault(), u(!0), g({}), c(!1);
      try {
        (await D.post("/change-password", j)).data.success &&
          (c(!0),
          t({ current_password: "", password: "", password_confirmation: "" }),
          setTimeout(() => {
            z(), c(!1);
          }, 2e3));
      } catch (_) {
        _.response?.status === 422
          ? g(_.response.data.errors || {})
          : g({ general: ["Ocorreu um erro inesperado. Tente novamente."] });
      } finally {
        u(!1);
      }
    },
    N = () => {
      t({ current_password: "", password: "", password_confirmation: "" }),
        g({}),
        c(!1);
    },
    x = () => {
      N(), z();
    };
  return w
    ? e.jsx("div", {
        className: "profile-modal-overlay",
        onClick: x,
        children: e.jsxs("div", {
          className: "profile-modal change-password-modal",
          onClick: (b) => b.stopPropagation(),
          children: [
            e.jsxs("div", {
              className: "profile-modal-header",
              children: [
                e.jsx("h2", { children: "Alterar Senha" }),
                e.jsx("button", {
                  className: "profile-modal-close",
                  onClick: x,
                  children: "✕",
                }),
              ],
            }),
            e.jsxs("div", {
              className: "profile-user-info",
              children: [
                e.jsx("div", {
                  className: "profile-avatar",
                  children: m.name.charAt(0).toUpperCase(),
                }),
                e.jsxs("div", {
                  className: "change-password-info",
                  children: [
                    e.jsx("h3", { children: m.name }),
                    e.jsx("p", {
                      children:
                        "Digite sua senha atual e escolha uma nova senha segura",
                    }),
                  ],
                }),
              ],
            }),
            e.jsx("div", {
              className: "change-password-content",
              children: l
                ? e.jsxs("div", {
                    className: "change-password-success",
                    children: [
                      e.jsx("div", {
                        className: "success-icon",
                        children: e.jsx("svg", {
                          width: "48",
                          height: "48",
                          viewBox: "0 0 24 24",
                          fill: "#4caf50",
                          children: e.jsx("path", {
                            d: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z",
                          }),
                        }),
                      }),
                      e.jsx("h3", { children: "Senha alterada com sucesso!" }),
                      e.jsx("p", {
                        children:
                          "Sua senha foi atualizada. Este modal será fechado automaticamente.",
                      }),
                    ],
                  })
                : e.jsxs("form", {
                    onSubmit: v,
                    className: "change-password-form",
                    children: [
                      d.general &&
                        e.jsx("div", {
                          className: "form-error-general",
                          children: d.general[0],
                        }),
                      e.jsxs("div", {
                        className: "form-group",
                        children: [
                          e.jsx("label", {
                            htmlFor: "current_password",
                            children: "Senha Atual",
                          }),
                          e.jsx("input", {
                            type: "password",
                            id: "current_password",
                            name: "current_password",
                            value: j.current_password,
                            onChange: C,
                            placeholder: "Digite sua senha atual",
                            disabled: h,
                            autoComplete: "current-password",
                          }),
                          d.current_password &&
                            e.jsx("div", {
                              className: "form-error",
                              children: d.current_password[0],
                            }),
                        ],
                      }),
                      e.jsxs("div", {
                        className: "form-group",
                        children: [
                          e.jsx("label", {
                            htmlFor: "password",
                            children: "Nova Senha",
                          }),
                          e.jsx("input", {
                            type: "password",
                            id: "password",
                            name: "password",
                            value: j.password,
                            onChange: C,
                            placeholder: "Digite sua nova senha",
                            disabled: h,
                            autoComplete: "new-password",
                          }),
                          d.password &&
                            e.jsx("div", {
                              className: "form-error",
                              children: d.password[0],
                            }),
                        ],
                      }),
                      e.jsxs("div", {
                        className: "form-group",
                        children: [
                          e.jsx("label", {
                            htmlFor: "password_confirmation",
                            children: "Confirmar Nova Senha",
                          }),
                          e.jsx("input", {
                            type: "password",
                            id: "password_confirmation",
                            name: "password_confirmation",
                            value: j.password_confirmation,
                            onChange: C,
                            placeholder: "Confirme sua nova senha",
                            disabled: h,
                            autoComplete: "new-password",
                          }),
                          d.password_confirmation &&
                            e.jsx("div", {
                              className: "form-error",
                              children: d.password_confirmation[0],
                            }),
                        ],
                      }),
                      e.jsxs("div", {
                        className: "form-actions",
                        children: [
                          e.jsx("button", {
                            type: "button",
                            className: "cancel-btn",
                            onClick: x,
                            disabled: h,
                            children: "Cancelar",
                          }),
                          e.jsx("button", {
                            type: "submit",
                            className: "submit-btn",
                            disabled: h,
                            children: h
                              ? e.jsxs(e.Fragment, {
                                  children: [
                                    e.jsx("div", {
                                      className: "loading-spinner small",
                                    }),
                                    "Alterando...",
                                  ],
                                })
                              : "Alterar Senha",
                          }),
                        ],
                      }),
                    ],
                  }),
            }),
          ],
        }),
      })
    : null;
}
function re({ isOpen: w, onClose: z, user: m, onUserUpdate: j }) {
  const [t, d] = i.useState(null),
    [g, h] = i.useState(!1),
    [u, l] = i.useState(!1),
    [c, C] = i.useState(m);
  i.useEffect(() => {
    w && v();
  }, [w]),
    i.useEffect(() => {
      C(m);
    }, [m]);
  const v = async () => {
      h(!0);
      try {
        const o = await D.get("/api/referral-data");
        d(o.data.settings),
          o.data.user &&
            C((a) => ({
              ...a,
              chest_level: o.data.user.chest_level,
              chest_open: o.data.user.chest_open,
              balance: o.data.user.balance,
            }));
      } catch (o) {
        console.error("Error fetching referral data:", o);
      } finally {
        h(!1);
      }
    },
    N = async (o) => {
      try {
        const a = await D.post("/api/open-chest", { chest_level: o });
        if (a.data.success) {
          if (a.data.user) {
            const s = {
              ...c,
              chest_level: a.data.user.chest_level,
              chest_open: a.data.user.chest_open,
              balance: a.data.user.balance,
            };
            C(s), j && j(s);
          }
          v();
        }
      } catch (a) {
        console.error("Error opening chest:", a),
          a.response?.data?.message && alert(a.response.data.message);
      }
    },
    x = async () => {
      const o = `${window.location.origin}/?ref=${c.id}`;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(o),
            l(!0),
            setTimeout(() => l(!1), 2e3);
          return;
        }
        const a = document.createElement("textarea");
        if (
          ((a.value = o),
          (a.style.position = "fixed"),
          (a.style.left = "-999999px"),
          (a.style.top = "-999999px"),
          document.body.appendChild(a),
          a.focus(),
          a.select(),
          navigator.userAgent.match(/ipad|iphone/i))
        ) {
          const n = document.createRange();
          n.selectNodeContents(a);
          const F = window.getSelection();
          F.removeAllRanges(), F.addRange(n), a.setSelectionRange(0, 999999);
        }
        const s = document.execCommand("copy");
        if ((document.body.removeChild(a), s))
          l(!0), setTimeout(() => l(!1), 2e3);
        else throw new Error("Copy command failed");
      } catch (a) {
        console.error("Failed to copy: ", a), prompt("Copie o link abaixo:", o);
      }
    },
    b = (o) => {
      const a = t?.chests_rules[o] || 0,
        s = c.chest_level || 0,
        n = o + 1;
      return c.chest_open >= n
        ? "opened"
        : c.chest_open < n - 1
        ? "unavailable"
        : s >= a
        ? "available"
        : "locked";
    },
    _ = (o) => `BRL ${parseFloat(o).toFixed(2)}`,
    M = () =>
      t?.chests_rules && t?.chests_prizes
        ? t.chests_rules.map((o, a) => ({
            rule: o,
            prize: t.chests_prizes[a] || 0,
          }))
        : [
            { rule: 5, prize: 5 },
            { rule: 50, prize: 50 },
            { rule: 100, prize: 200 },
            { rule: 200, prize: 250 },
            { rule: 250, prize: 300 },
            { rule: 500, prize: 500 },
          ];
  return w
    ? e.jsx("div", {
        className: "profile-modal-overlay",
        onClick: z,
        children: e.jsxs("div", {
          className: "profile-modal share-modal",
          onClick: (o) => o.stopPropagation(),
          children: [
            e.jsxs("div", {
              className: "profile-modal-header",
              children: [
                e.jsx("h2", { children: "Convide Amigos & Ganhe Prêmios" }),
                e.jsx("button", {
                  className: "profile-modal-close",
                  onClick: z,
                  children: "✕",
                }),
              ],
            }),
            g
              ? e.jsxs("div", {
                  className: "share-loading",
                  children: [
                    e.jsx("div", { className: "loading-spinner" }),
                    e.jsx("span", { children: "Carregando..." }),
                  ],
                })
              : e.jsxs(e.Fragment, {
                  children: [
                    e.jsxs("div", {
                      className: "share-referral-section",
                      style: { border: 0 },
                      children: [
                        e.jsx("h3", { children: "Seu Link de Convite" }),
                        e.jsxs("div", {
                          className: "referral-link-container",
                          children: [
                            e.jsxs("div", {
                              className: "referral-link",
                              children: [
                                window.location.origin,
                                "/?ref=",
                                c.id,
                              ],
                            }),
                            e.jsxs("button", {
                              className: "copy-link-btn",
                              onClick: x,
                              children: [
                                e.jsx("svg", {
                                  width: "16",
                                  height: "16",
                                  viewBox: "0 0 24 24",
                                  fill: "currentColor",
                                  children: e.jsx("path", {
                                    d: "M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z",
                                  }),
                                }),
                                u ? "Copiado!" : "Copiar",
                              ],
                            }),
                          ],
                        }),
                      ],
                    }),
                    e.jsxs("div", {
                      className: "share-chests-section",
                      style: { marginTop: -30 },
                      children: [
                        e.jsx("h3", { children: "Baús de Recompensa" }),
                        e.jsx("p", {
                          className: "chests-description",
                          children:
                            "Convide amigos que façam depósitos para aumentar seu nível e desbloquear baús!",
                        }),
                        e.jsx("div", {
                          className: "chests-grid",
                          children: M().map((o, a) => {
                            const s = b(a),
                              n = a + 1;
                            return e.jsxs(
                              "div",
                              {
                                className: `chest-item ${s}`,
                                children: [
                                  e.jsx("div", {
                                    className: "chest-icon",
                                    children:
                                      s === "opened"
                                        ? e.jsx("img", {
                                            src: "https://cdn-icons-png.flaticon.com/64/210/210594.png",
                                            alt: "Baú Aberto",
                                            width: "40",
                                            height: "40",
                                            style: { filter: "none" },
                                          })
                                        : e.jsx("img", {
                                            src: "https://cdn-icons-png.flaticon.com/64/1907/1907938.png",
                                            alt: "Baú Fechado",
                                            width: "40",
                                            height: "40",
                                            style: {
                                              filter:
                                                s === "available"
                                                  ? "brightness(1.2) drop-shadow(0 0 8px rgba(255, 152, 0, 0.6))"
                                                  : s === "unavailable"
                                                  ? "grayscale(100%) brightness(0.7)"
                                                  : "grayscale(50%) brightness(0.8)",
                                            },
                                          }),
                                  }),
                                  e.jsxs("div", {
                                    className: "chest-details",
                                    children: [
                                      e.jsxs("div", {
                                        className: "chest-title",
                                        children: ["Baú ", n],
                                      }),
                                      e.jsx("div", {
                                        className: "chest-prize",
                                        children: _(o.prize),
                                      }),
                                      e.jsxs("div", {
                                        className: "chest-requirement",
                                        children: [
                                          "Nível ",
                                          o.rule,
                                          " necessário",
                                        ],
                                      }),
                                      s === "available" &&
                                        e.jsx("button", {
                                          className: "open-chest-btn",
                                          onClick: () => N(n),
                                          children: "Abrir Baú",
                                        }),
                                      s === "opened" &&
                                        e.jsx("div", {
                                          className: "chest-opened",
                                          children: "✓ Aberto",
                                        }),
                                      s === "locked" &&
                                        e.jsxs("div", {
                                          className: "chest-progress",
                                          children: [
                                            "Nível ",
                                            c.chest_level || 0,
                                            "/",
                                            o.rule,
                                          ],
                                        }),
                                      s === "unavailable" &&
                                        e.jsx("div", {
                                          className: "chest-unavailable",
                                          children: "🔒 Bloqueado",
                                        }),
                                    ],
                                  }),
                                ],
                              },
                              a
                            );
                          }),
                        }),
                      ],
                    }),
                    e.jsxs("div", {
                      className: "share-instructions",
                      children: [
                        e.jsx("h4", { children: "Como Funciona:" }),
                        e.jsxs("ol", {
                          children: [
                            e.jsx("li", {
                              children:
                                "Compartilhe seu link de convite com amigos",
                            }),
                            e.jsx("li", {
                              children:
                                "Quando um amigo se cadastrar e fizer depósito, você ganha 1 nível",
                            }),
                            e.jsx("li", {
                              children:
                                "Use seus níveis para desbloquear baús com prêmios",
                            }),
                            e.jsx("li", {
                              children:
                                "Abra os baús em ordem para receber prêmios em dinheiro!",
                            }),
                          ],
                        }),
                      ],
                    }),
                  ],
                }),
          ],
        }),
      })
    : null;
}
function ie({ isOpen: w, onClose: z, user: m, onSuccess: j }) {
  const [t, d] = i.useState(null),
    [g, h] = i.useState({ amount: "", pix_key: "", pix_type: "cpf", cpf: "", name: "" }),
    [u, l] = i.useState({}),
    [c, C] = i.useState(!1),
    [v, N] = i.useState(!1),
    [x, b] = i.useState(!1),
    _ = i.useRef(!1),
    [M, o] = i.useState(!1),
    [a, s] = i.useState([]),
    [n, F] = i.useState(!1),
    [p, S] = i.useState(1),
    q = 5,
    [R, E] = i.useState(1);

  i.useEffect(() => {
    w &&
      (V(),
      b(!1),
      (_.current = !0),
      setTimeout(() => {
        _.current = !1;
      }, 200));
  }, [w]),
    i.useEffect(() => {
      M && f();
    }, [M, p]);

  const V = async () => {
      try {
        const r = await D.get("/withdrawal-data");
        d(r.data);
        if (r.data.user && r.data.user.pix_document) {
          const doc = r.data.user.pix_document;
          let detected = "cpf";
          if (X(doc)) detected = "email";
          else if (O(doc)) detected = "cpf";
          else if (U(doc)) detected = "phone";
          h((y) => ({ ...y, pix_key: doc, pix_type: detected }));
        }
      } catch (r) {
        console.error("Error fetching withdrawal data:", r);
      }
    },
    f = async () => {
      F(!0);
      try {
        const r = await D.get(`/withdrawal-history?page=${p}&per_page=${q}`);
        s(r.data.data || []), S(r.data.current_page || 1), E(r.data.last_page || 1);
      } catch (r) {
        console.error("Erro ao buscar histórico:", r), s([]);
      } finally {
        F(!1);
      }
    },
    L = () => {
      o(!0), p !== 1 && S(1);
    },
    B = () => {
      o(!1), s([]), S(1), E(1);
    },
    X = (r) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(r),
    O = (r) => {
      if (((r = r.replace(/[^\d]+/g, "")), r.length !== 11 || r.match(/(\d)\1{10}/))) return !1;
      let y = 0, P;
      for (let k = 1; k <= 9; k++) y += parseInt(r.substring(k - 1, k)) * (11 - k);
      P = (y * 10) % 11; if (P === 10 || P === 11) P = 0; if (P !== parseInt(r.substring(9, 10))) return !1;
      y = 0; for (let k = 1; k <= 10; k++) y += parseInt(r.substring(k - 1, k)) * (12 - k);
      P = (y * 10) % 11; if (P === 10 || P === 11) P = 0; return P === parseInt(r.substring(10, 11));
    },
    U = (r) => /^\(?\d{2}\)?[\s-]?\d{4,5}-?\d{4}$/.test(r),

    // ===== Helpers de máscara/validação/sanitização =====
    formatPhoneBR = (value) => {
      if (!value) return "";
      let dgt = value.replace(/\D/g, "").slice(0, 11);
      if (dgt.length <= 2) return `(${dgt}`;
      if (dgt.length <= 6) return `(${dgt.slice(0,2)}) ${dgt.slice(2)}`;
      if (dgt.length <= 10) return `(${dgt.slice(0,2)}) ${dgt.slice(2,6)}-${dgt.slice(6)}`;
      return `(${dgt.slice(0,2)}) ${dgt.slice(2,7)}-${dgt.slice(7)}`;
    },
    formatPixByType = (val, type) => {
      if (!val) return "";
      switch (type) {
        case "cpf":   return formatCPF(val);
        case "phone": return formatPhoneBR(val);
        case "email": return val.trim().toLowerCase();
        default:       return val;
      }
    },
    onlyDigits = (v) => (v || "").replace(/\D/g, ""),
    sanitizeAmount = (v) => {
      const digits = onlyDigits(v);
      if (!digits) return "0.00";
      return (parseInt(digits, 10) / 100).toFixed(2);
    },
    sanitizePixKey = (key, type) => {
      if (!key) return "";
      if (type === "cpf" || type === "phone") return onlyDigits(key);
      if (type === "email") return key.trim().toLowerCase();
      return key.trim();
    },
    G = (value, type) => {
      if (!value) return "Chave PIX é obrigatória.";
      if (type === "email") return X(value) ? null : "E-mail inválido.";
      if (type === "cpf")   return O(value) ? null : "CPF inválido.";
      if (type === "phone") return U(value) ? null : "Telefone inválido.";
      return "Formato de Chave PIX inválido (use CPF, e-mail ou telefone).";
    },

    I = (r) => {
      let { name: y, value: P } = r.target;
      if (y === "amount") {
        P = formatCurrency(P);
        h((k) => ({ ...k, amount: P }));
      } else if (y === "cpf") {
        P = formatCPF(P);
        h((k) => ({ ...k, cpf: P }));
      } else if (y === "pix_type") {
        h((prev) => ({
          ...prev,
          pix_type: P,
          pix_key: formatPixByType(prev.pix_key, P),
        }));
      } else if (y === "pix_key") {
        h((prev) => ({
          ...prev,
          pix_key: formatPixByType(P, prev.pix_type),
        }));
      } else {
        h((k) => ({ ...k, [y]: P }));
      }
      u[y] && l((k) => ({ ...k, [y]: void 0 }));
    },

    J = async (r) => {
      r.preventDefault();
      if (!t?.user?.pix_document) {
        const errPix = G(g.pix_key, g.pix_type);
        if (errPix) {
          l((P) => ({ ...P, pix_key: [errPix] }));
          return;
        }
      }
      C(!0), l({}), N(!1);
      try {
        const payload = {
          amount: sanitizeAmount(g.amount),
          pix_key: sanitizePixKey(g.pix_key, g.pix_type),
          pix_type: g.pix_type,
          cpf: onlyDigits(g.cpf || ""),
          name: g.name
        };
        const resp = await D.post("/withdrawal", payload);
        if (resp.data.success) {
          N(!0);
          const k = g.pix_key; // mantemos exibido com máscara
          const ee = parseFloat(payload.amount);
          h({ amount: "", pix_key: k, pix_type: g.pix_type, cpf: g.cpf });
          const T = {
            ...m,
            balance: (parseFloat(m.balance) - ee).toFixed(2),
            pix_document: k,
          };
          t &&
            d(($) => ({
              ...$,
              user: { ...$.user, balance: T.balance, pix_document: k },
            })),
            j && j(T),
            setTimeout(() => {
              z(), N(!1);
            }, 3e3);
        }
      } catch (y) {
        console.error("Withdrawal error:", y),
          y.response?.status === 422
            ? l(y.response.data.errors || {})
            : l({ general: ["Ocorreu um erro inesperado. Tente novamente."] });
      } finally {
        C(!1);
      }
    },

    formatCurrency = (value) => {
      if (!value) return "";
      let digits = value.replace(/\D/g, "");
      if (!digits) return "";
      let number = (parseInt(digits, 10) / 100).toFixed(2);
      return "R$ " + number.replace(".", ",");
    },
    formatCPF = (value) => {
      if (!value) return "";
      let digits = value.replace(/\D/g, "");
      digits = digits.slice(0, 11);
      if (digits.length <= 3) return digits;
      if (digits.length <= 6) return digits.replace(/(\d{3})(\d+)/, "$1.$2");
      if (digits.length <= 9) return digits.replace(/(\d{3})(\d{3})(\d+)/, "$1.$2.$3");
      return digits.replace(/(\d{3})(\d{3})(\d{3})(\d{1,2})/, "$1.$2.$3-$4");
    },

    Q = () => {
      h({ amount: "", pix_key: t?.user?.pix_document || "", pix_type: g.pix_type || "cpf", cpf: ""  || "", name: g.name }),
      l({}),
      N(!1),
      b(!1);
    },
    A = () => { Q(), z(); },
    K = () => { _.current || A(); },
    H = (r) => `R$ ${parseFloat(r).toFixed(2).replace(".", ",")}`,
    Z = () => { p < R && S((r) => r + 1); },
    Y = () => { p > 1 && S((r) => r - 1); };

  return M
    ? e.jsx("div", {
        className: "profile-modal-overlay",
        onClick: B,
        children: e.jsxs("div", {
          className: "profile-modal",
          onClick: (r) => r.stopPropagation(),
          children: [
            e.jsxs("div", {
              className: "profile-modal-header",
              children: [
                e.jsx("h2", { children: "Histórico de Saques" }),
                e.jsx("button", { className: "profile-modal-close", onClick: B, children: "✕" }),
              ],
            }),
            e.jsx("div", {
              className: "profile-modal-content",
              children: n
                ? e.jsxs("div", { className: "text-center py-12", children: [
                    e.jsx("div", { className: "loading-spinner mx-auto mb-4" }),
                    e.jsx("p", { className: "text-zinc-400", children: "Carregando histórico..." }),
                  ] })
                : a.length === 0
                ? e.jsxs("div", { className: "text-center py-12", children: [
                    e.jsx("svg", { className: "mx-auto h-16 w-16 text-zinc-500 mb-4", fill: "none", viewBox: "0 0 24 24", stroke: "currentColor", children: e.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 1.5, d: "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" }) }),
                    e.jsx("h3", { className: "text-lg font-semibold text-zinc-100 mb-2", children: "Nenhum saque encontrado" }),
                    e.jsx("p", { className: "text-zinc-400", children: "Você ainda não fez nenhuma solicitação de saque." }),
                  ] })
                : e.jsxs(e.Fragment, { children: [
                    e.jsx("div", { className: "space-y-3 mb-6", children:
                      a.map((r, y) => e.jsx("div", {
                        className: "bg-zinc-800/50 rounded-lg p-4",
                        style: { zoom: 0.8, marginTop: 15, width: "96%", left: "50%", background: "#231504", marginBottom: -5, position: "relative", transform: "translate(-50%)" },
                        children: e.jsxs("div", { className: "flex items-center justify-between", children: [
                          e.jsxs("div", { children: [
                            e.jsx("h4", { className: "text-lg font-semibold text-zinc-100", children: H(r.amount) }),
                            e.jsx("p", { className: "text-sm text-zinc-400 mt-1", children: new Date(r.created_at).toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" }) }),
                          ] }),
                          e.jsxs("div", { children: [
                            r.status === 0 && e.jsx("span", { className: "inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-400", children: "Pendente" }),
                            r.status === 1 && e.jsx("span", { className: "inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-500/20 text-green-400", children: "Aprovado" }),
                            r.status === 2 && e.jsxs("span", { className: "inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-red-500/20 text-red-400", children: [
                              e.jsx("span", { className: "mr-1", children: "Recusado" }),
                              r.rejection_reason && e.jsx("span", { title: r.rejection_reason, className: "cursor-help", children: "⚠️" }),
                            ] }),
                          ] }),
                        ] }),
                      }, r.id || y))
                    }),
                    R > 1 && e.jsxs("div", { className: "flex items-center justify-between py-3 border-t border-zinc-700 p-4", children: [
                      e.jsx("button", { onClick: Y, disabled: p <= 1, className: "profile-btn-secondary disabled:opacity-50 disabled:cursor-not-allowed", children: "← Anterior" }),
                      e.jsxs("span", { className: "text-sm text-zinc-400", children: ["Página ", p, " de ", R] }),
                      e.jsx("button", { onClick: Z, disabled: p >= R, className: "profile-btn-secondary disabled:opacity-50 disabled:cursor-not-allowed", children: "Próxima →" }),
                    ] }),
                    a.some((r) => r.status === 2) && e.jsx("div", { className: "mt-4 p-4 bg-red-900/30 border border-red-500/30 rounded-lg", children:
                      e.jsxs("div", { className: "flex items-start", children: [
                        e.jsx("div", { className: "flex-shrink-0", children: e.jsx("svg", { className: "h-5 w-5 text-red-400", fill: "currentColor", viewBox: "0 0 20 20", children: e.jsx("path", { fillRule: "evenodd", d: "M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z", clipRule: "evenodd" }) }) }),
                        e.jsxs("div", { className: "ml-3", children: [
                          e.jsx("h4", { className: "text-sm font-medium text-red-300", children: "Atenção: Saques Recusados" }),
                          e.jsx("p", { className: "text-sm text-red-400 mt-1", children: "Você possui saques recusados. Verifique se a chave PIX está correta e tente novamente." }),
                        ] }),
                      ] })
                    }),
                  ] }),
            }),
          ],
        }),
      })
    : w
    ? e.jsx("div", {
        className: "profile-modal-overlay",
        onClick: K,
        children: e.jsxs("div", {
          className: "profile-modal withdrawal-modal",
          onClick: (r) => r.stopPropagation(),
          children: [
            e.jsxs("div", { className: "profile-modal-header", children: [
              e.jsx("h2", { children: "Solicitar Saque" }),
              e.jsx("button", { className: "profile-modal-close", onClick: A, children: "✕" }),
            ] }),
            e.jsxs("div", { className: "profile-modal-content", children: [
              e.jsxs("div", { className: "flex items-center justify-between mb-6", style: { padding: 34, marginBottom: -34 }, children: [
                e.jsxs("div", { children: [
                  e.jsx("span", { className: "text-zinc-400 text-sm", children: "Saldo disponível:" }),
                  e.jsx("h3", { className: "text-2xl font-bold text-green-400", children: H(m.balance || 0) }),
                ] }),
                e.jsxs("button", { type: "button", onClick: L, className: "px-4 py-2 rounded-lg text-sm font-semibold bg-orange-500 text-white hover:bg-orange-600 transition-colors shadow-sm flex items-center gap-2", children: [
                  e.jsx("svg", { xmlns: "http://www.w3.org/2000/svg", width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: e.jsx("path", { d: "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" }) }),
                  "Histórico",
                ] }),
              ] }),
              e.jsxs("div", { className: "withdrawal-content", children: [
                t && t.user.rollover > 0 && e.jsxs("div", { className: "rollover-warning", children: [
                  e.jsx("div", { className: "warning-icon", children: e.jsx("svg", { width: "20", height: "20", viewBox: "0 0 24 24", fill: "#ff9800", children: e.jsx("path", { d: "M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z" }) }) }),
                  e.jsxs("div", { className: "warning-content", children: [
                    e.jsx("strong", { children: "Rollover Pendente" }),
                    e.jsxs("p", { children: ["Você ainda precisa apostar ", e.jsx("b", { children: H(t.user.rollover) }), " antes de poder sacar."] }),
                  ] }),
                ] }),
                t && t.limits && e.jsxs("div", { className: "withdrawal-limits", children: [
                  e.jsx("h4", { children: "Limites de Saque" }),
                  e.jsxs("div", { className: "limits-grid", children: [
                    e.jsxs("div", { className: "limit-item", children: [
                      e.jsx("span", { className: "limit-label", children: "Mínimo:" }),
                      e.jsx("span", { className: "limit-value", children: H(t.limits.min) }),
                    ] }),
                    e.jsxs("div", { className: "limit-item", children: [
                      e.jsx("span", { className: "limit-label", children: "Máximo:" }),
                      e.jsx("span", { className: "limit-value", children: H(t.limits.max) }),
                    ] }),
                  ] }),
                ] }),
                v
                  ? e.jsxs("div", { className: "withdrawal-success", children: [
                      e.jsx("div", { className: "success-icon", children: e.jsx("svg", { width: "48", height: "48", viewBox: "0 0 24 24", fill: "#4caf50", children: e.jsx("path", { d: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" }) }) }),
                      e.jsx("h3", { children: "Saque solicitado com sucesso!" }),
                      e.jsx("p", { children: "Sua solicitação foi enviada e está sendo analisada. Você receberá uma notificação quando for processada." }),
                    ] })
                  : e.jsxs("form", { onSubmit: J, className: "withdrawal-form", children: [
                      u.general && e.jsx("div", { className: "form-error-general", children: u.general[0] }),
                      u.rollover && e.jsx("div", { className: "form-error-general", children: u.rollover[0] }),

                      e.jsxs("div", { className: "form-group", children: [
                        e.jsx("label", { htmlFor: "amount", children: "Valor do Saque" }),
                        e.jsx("input", { type: "text", id: "amount", name: "amount", value: g.amount, onChange: I, placeholder: "Digite o valor desejado", disabled: c || (t && !t.can_withdraw), step: "0.01", min: t?.limits?.min || 0, max: Math.min(t?.limits?.max || 0, m.balance || 0) }),
                        t && e.jsxs("div", { className: "input-help", children: [
                          "Mín: ", H(t.limits.min), " - Máx: ", H(Math.min(t.limits.max, m.balance || 0)),
                        ] }),
                        u.amount && e.jsx("div", { className: "form-error", children: u.amount[0] }),
                      ] }),

                      e.jsxs("div", { className: "form-group", children: [
                        e.jsx("label", { htmlFor: "pix_type", children: "Tipo da Chave PIX" }),
                        e.jsxs("select", { id: "pix_type", name: "pix_type", value: g.pix_type, onChange: I, disabled: c || (t && !t.can_withdraw), children: [
                          e.jsx("option", { value: "cpf", children: "CPF" }),
                          e.jsx("option", { value: "email", children: "E-mail" }),
                          e.jsx("option", { value: "phone", children: "Telefone" }),
                        ] }),
                      ] }),

                      e.jsxs("div", { className: "form-group", children: [
                        e.jsx("label", { htmlFor: "cpf", children: "CPF" }),
                        e.jsx("input", { type: "text", id: "cpf", name: "cpf", value: g.cpf, onChange: I, placeholder: "000.000.000-00", disabled: c || (t && !t.can_withdraw) }),
                        u.cpf && e.jsx("div", { className: "form-error", children: u.cpf[0] }),
                      ] }),

                      e.jsxs("div", { className: "form-group", children: [
                        e.jsx("label", { htmlFor: "pix_key", children: "Chave PIX" }),
                        e.jsx("input", { type: "text", id: "pix_key", name: "pix_key", value: g.pix_key, onChange: I, placeholder: g.pix_type === "email" ? "email@dominio.com" : g.pix_type === "phone" ? "(11) 98888-7777" : "000.000.000-00", disabled: c || (t && !t.can_withdraw) }),
                        u.pix_key && e.jsx("div", { className: "form-error", children: u.pix_key[0] }),
                      ] }),
                      e.jsxs("div", { className: "form-group", children: [
                        e.jsx("label", { htmlFor: "name", children: "Nome completo" }),
                        e.jsx("input", { type: "text", id: "name", name: "name", value: g.name, onChange: I, placeholder: "Nome completo", disabled: c || (t && !t.can_withdraw) }),
                        u.pix_key && e.jsx("div", { className: "form-error", children: u.name[0] }),
                      ] }),

                      e.jsxs("div", { className: "form-actions", children: [
                        e.jsx("button", { type: "button", className: "cancel-btn", onClick: A, disabled: c, children: "Cancelar" }),
                        e.jsx("button", { type: "submit", className: "submit-btn", disabled: c || (t && !t.can_withdraw), children: c ? e.jsxs(e.Fragment, { children: [ e.jsx("div", { className: "loading-spinner small" }), "Processando..." ] }) : "Solicitar Saque" }),
                      ] }),
                    ] }),
              ] }),
            ] }),
          ],
        }),
      })
    : null;
}

function ne({
  isOpen: w,
  onClose: z,
  user: m,
  onLogout: j,
  playButtonClickSound: t,
  onWithdrawalSuccess: d,
}) {
  const [g, h] = i.useState(!1),
    [u, l] = i.useState(!1),
    [c, C] = i.useState(!1),
    [v, N] = i.useState(!1),
    x = i.useRef(!1);
  if (
    (i.useEffect(() => {
      w &&
        ((x.current = !0),
        setTimeout(() => {
          x.current = !1;
        }, 200));
    }, [w]),
    !w)
  )
    return null;
  const b = () => {
      t && t(), z();
    },
    _ = () => {
      x.current || b();
    },
    M = () => {
      t && t(), h(!0);
    },
    o = () => {
      t && t(), l(!0);
    },
    a = () => {
      t && t(), C(!0);
    },
    s = () => {
      t && t(), N(!0);
    },
    n = async () => {
      t && t(),
        se.post(
          "/logout",
          {},
          {
            onSuccess: () => {
              window.location.href = "/";
            },
            onError: (p) => {
              console.error("Logout error:", p),
                alert("Erro ao sair. Tente novamente.");
            },
          }
        );
    },
    F = [
      {
        icon: e.jsx("svg", {
          width: "20",
          height: "20",
          viewBox: "0 0 24 24",
          fill: "currentColor",
          children: e.jsx("path", {
            d: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z",
          }),
        }),
        label: "Histórico de Partidas",
        action: M,
        color: "#4caf50",
      },
      {
        icon: e.jsx("svg", {
          width: "20",
          height: "20",
          viewBox: "0 0 24 24",
          fill: "currentColor",
          children: e.jsx("path", {
            d: "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11V12z",
          }),
        }),
        label: "Alterar Senha",
        action: o,
        color: "#ff9800",
      },
      {
        icon: e.jsx("svg", {
          width: "20",
          height: "20",
          viewBox: "0 0 24 24",
          fill: "currentColor",
          children: e.jsx("path", {
            d: "M12 4c-4.41 0-8 1.79-8 4v8c0 2.21 3.59 4 8 4s8-1.79 8-4v-8c0-2.21-3.59-4-8-4zm0 2c3.87 0 7 1.13 7 2.5S15.87 11 12 11s-7-1.13-7-2.5S8.13 6 12 6zm0 12c-3.87 0-7-1.13-7-2.5V12c1.74 1.07 5.03 1.5 7 1.5s5.26-.43 7-1.5v3.5c0 1.37-3.13 2.5-7 2.5z",
          }),
        }),
        label: "Sacar",
        action: s,
        color: "#00bcd4",
      },
      {
        icon: e.jsx("svg", {
          width: "20",
          height: "20",
          viewBox: "0 0 24 24",
          fill: "currentColor",
          children: e.jsx("path", {
            d: "M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92s2.92-1.31 2.92-2.92S19.61 16.08 18 16.08z",
          }),
        }),
        label: "Baú de prêmios (Share)",
        action: a,
        color: "#2196f3",
      },
      {
        icon: e.jsx("svg", {
          width: "20",
          height: "20",
          viewBox: "0 0 24 24",
          fill: "currentColor",
          children: e.jsx("path", {
            d: "M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.59L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z",
          }),
        }),
        label: "Sair",
        action: n,
        color: "#f44336",
      },
    ];
  return e.jsxs(e.Fragment, {
    children: [
      e.jsx("div", {
        className: "profile-modal-overlay",
        onClick: _,
        children: e.jsxs("div", {
          className: "profile-modal",
          onClick: (p) => p.stopPropagation(),
          children: [
            e.jsxs("div", {
              className: "profile-modal-header",
              children: [
                e.jsx("h2", { children: "Perfil do Jogador" }),
                e.jsx("button", {
                  className: "profile-modal-close",
                  onClick: b,
                  children: "✕",
                }),
              ],
            }),
            e.jsxs("div", {
              className: "profile-user-info",
              children: [
                e.jsx("div", {
                  className: "profile-avatar",
                  children: m.name.charAt(0).toUpperCase(),
                }),
                e.jsxs("div", {
                  className: "profile-details",
                  children: [
                    e.jsxs("div", {
                      className: "profile-detail-item",
                      children: [
                        e.jsx("span", {
                          className: "detail-label",
                          children: "ID:",
                        }),
                        e.jsxs("span", {
                          className: "detail-value",
                          children: ["#", m.id],
                        }),
                      ],
                    }),
                    e.jsxs("div", {
                      className: "profile-detail-item",
                      children: [
                        e.jsx("span", {
                          className: "detail-label",
                          children: "Conta:",
                        }),
                        e.jsx("span", {
                          className: "detail-value",
                          children: m.name,
                        }),
                      ],
                    }),
                    e.jsxs("div", {
                      className: "profile-detail-item",
                      children: [
                        e.jsx("span", {
                          className: "detail-label",
                          children: "Telefone:",
                        }),
                        e.jsx("span", {
                          className: "detail-value",
                          children: m.phone,
                        }),
                      ],
                    }),
                    e.jsxs("div", {
                      className: "profile-detail-item balance-item",
                      style: { marginTop: -2 },
                      children: [
                        e.jsx("span", {
                          className: "detail-label",
                          children: "Saldo:",
                        }),
                        e.jsx("span", {
                          className: "detail-value balance-value",
                          children: new Intl.NumberFormat("pt-BR", {
                            style: "currency",
                            currency: "BRL",
                          }).format(m.balance || 0),
                        }),
                      ],
                    }),
                  ],
                }),
              ],
            }),
            e.jsx("div", {
              className: "profile-menu",
              children: F.map((p, S) =>
                e.jsxs(
                  "button",
                  {
                    className: "profile-menu-item",
                    onClick: p.action,
                    style: { "--item-color": p.color },
                    children: [
                      e.jsx("div", {
                        className: "menu-item-icon",
                        style: { color: p.color },
                        children: p.icon,
                      }),
                      e.jsx("span", {
                        className: "menu-item-label",
                        children: p.label,
                      }),
                      e.jsx("div", {
                        className: "menu-item-arrow",
                        children: e.jsx("svg", {
                          width: "16",
                          height: "16",
                          viewBox: "0 0 24 24",
                          fill: "currentColor",
                          children: e.jsx("path", {
                            d: "M8.59 16.59L13.17 12 8.59 7.41 10 6l6 6-6 6-1.41-1.41z",
                          }),
                        }),
                      }),
                    ],
                  },
                  S
                )
              ),
            }),
          ],
        }),
      }),
      e.jsx(ae, { isOpen: g, onClose: () => h(!1), user: m }),
      e.jsx(te, { isOpen: u, onClose: () => l(!1), user: m }),
      e.jsx(re, {
        isOpen: c,
        onClose: () => C(!1),
        user: m,
        onUserUpdate: (p) => {
          console.log("ProfileModal received user update from ShareModal:", p),
            d && d(p);
        },
      }),
      e.jsx(ie, {
        isOpen: v,
        onClose: () => N(!1),
        user: m,
        onSuccess: (p) => {
          console.log("ProfileModal received withdrawal success:", p),
            d && d(p);
        },
      }),
    ],
  });
}
function oe({ isOpen: w, onClose: z, user: m, onSuccess: j }) {
  const [t, d] = i.useState(null),
    [g, h] = i.useState(""),
    [y, r] = i.useState(""),
    [u, l] = i.useState({}),
    [c, C] = i.useState(!1),
    [v, N] = i.useState(null),
    [x, b] = i.useState("form"),
    [_, M] = i.useState(!1),
    o = i.useRef(null),
    a = i.useRef(!1);
  i.useEffect(
    () => (
      w &&
        (s(),
        b("form"),
        N(null),
        h(""),
        r(""),
        l({}),
        (a.current = !0),
        setTimeout(() => {
          a.current = !1;
        }, 200)),
      () => {
        o.current && clearInterval(o.current);
      }
    ),
    [w]
  );
  const unmaskCurrency = (value) => {
    if (!value) return 0;
    return parseFloat(
        value.replace(/\D/g, "") 
            .replace(/(\d{2})$/, ".$1") 
    );
    };
  const s = async () => {
      try {
        const f = await D.get("/deposit-data");
        d(f.data);
      } catch (f) {
        console.error("Error fetching deposit data:", f);
      }
    },
    n = async (f) => {
      f.preventDefault(), C(!0), l({});
      try {
        const L = await D.post("/deposit", { amount: unmaskCurrency(g), cpf: y.replace(/\D/g, "") });
        L.data.success &&
          (N(L.data.data), b("payment"), F(L.data.data.transaction_id));
      } catch (L) {
        L.response?.status === 422
          ? l(L.response.data.errors || {})
          : l({ general: ["Ocorreu um erro inesperado. Tente novamente."] });
      } finally {
        C(!1);
      }
    },
    F = (f) => {
      M(!0),
        (o.current = setInterval(async () => {
          try {
            const L = await D.post("/check-payment-status", {
              transaction_id: f,
            });
            L.data.success &&
              L.data.paid &&
              (clearInterval(o.current),
              M(!1),
              b("success"),
              await p(),
              setTimeout(() => {
                z();
              }, 3e3));
          } catch (L) {
            console.error("Error checking payment status:", L);
          }
        }, 3e3));
    },
    p = async () => {
      try {
        const f = await D.get("/api/user/refresh");
        f.data.success && j && j(f.data.user);
      } catch (f) {
        console.error("Error fetching updated user data:", f),
          j &&
            v &&
            j({ ...m, balance: parseFloat(m.balance) + parseFloat(v.amount) });
      }
    },
    formatCurrency = (value) => {
        if (!value) return "";

        let digits = value.replace(/\D/g, "");

        if (!digits) return "";

        let number = (parseInt(digits, 10) / 100).toFixed(2);

        return "R$ " + number.replace(".", ",");
    },
    formatCPF = (value) => {
        if (!value) return "";
        let digits = value.replace(/\D/g, "");
        digits = digits.slice(0, 11);

        if (digits.length <= 3) return digits;
        if (digits.length <= 6) return digits.replace(/(\d{3})(\d+)/, "$1.$2");
        if (digits.length <= 9)
            return digits.replace(/(\d{3})(\d{3})(\d+)/, "$1.$2.$3");
        return digits.replace(/(\d{3})(\d{3})(\d{3})(\d{1,2})/, "$1.$2.$3-$4");
    },
    S = (f) => {
    f = f * 100;
     h(formatCurrency(f.toString()));
    
      if (u.amount) {
        l((L) => {
          console.log(L)
          return {
            ...L,          // mantém todas as outras propriedades de L
            amount: undefined  // sobrescreve amount para "undefined"
          };
        });
      }
    },
    q = (f) => {
      navigator.clipboard.writeText(f).then(() => {
        alert("PIX copiado para a área de transferência!");
      });
    },
    R = () => {
      o.current && clearInterval(o.current),
        M(!1),
        b("form"),
        N(null),
        h(""),
        l({}),
        z();
    },
    E = () => {
      a.current || R();
    },
    V = (f) => `R$ ${parseFloat(f).toFixed(2).replace(".", ",")}`;
  return w
    ? e.jsx("div", {
        className: "profile-modal-overlay",
        onClick: E,
        children: e.jsxs("div", {
          className: "profile-modal deposit-modal",
          onClick: (f) => f.stopPropagation(),
          children: [
            e.jsxs("div", {
              className: "profile-modal-header",
              children: [
                e.jsxs("h2", {
                  children: [
                    x === "form" && "Fazer Depósito",
                    x === "payment" && "Aguardando Pagamento",
                    x === "success" && "Depósito Confirmado",
                  ],
                }),
                e.jsx("button", {
                  className: "profile-modal-close",
                  onClick: R,
                  children: "✕",
                }),
              ],
            }),
            e.jsxs("div", {
              className: "deposit-content",
              children: [
                x === "form" &&
                  e.jsxs(e.Fragment, {
                    children: [
                      t &&
                        t.limits &&
                        e.jsxs("div", {
                          className: "deposit-limits",
                          children: [
                            e.jsx("h4", { children: "Limites de Depósito" }),
                            e.jsxs("div", {
                              className: "limits-grid",
                              children: [
                                e.jsxs("div", {
                                  className: "limit-item",
                                  children: [
                                    e.jsx("span", {
                                      className: "limit-label",
                                      children: "Mínimo:",
                                    }),
                                    e.jsx("span", {
                                      className: "limit-value",
                                      children: V(t.limits.min),
                                    }),
                                  ],
                                }),
                                e.jsxs("div", {
                                  className: "limit-item",
                                  children: [
                                    e.jsx("span", {
                                      className: "limit-label",
                                      children: "Máximo:",
                                    }),
                                    e.jsx("span", {
                                      className: "limit-value",
                                      children: V(t.limits.max),
                                    }),
                                  ],
                                }),
                              ],
                            }),
                          ],
                        }),
                      t &&
                        t.recommended_amounts &&
                        e.jsxs("div", {
                          className: "recommended-amounts",
                          children: [
                            e.jsx("h4", { children: "Valores Recomendados" }),
                            e.jsx("div", {
                              className: "amounts-grid",
                              children: t.recommended_amounts.map((f, L) =>
                                e.jsx(
                                  "button",
                                  {
                                    type: "button",
                                    className: `amount-card ${
                                      g === f.toString() ? "selected" : ""
                                    }`,
                                    onClick: () => S(f),
                                    children: V(f),
                                  },
                                  L
                                )
                              ),
                            }),
                          ],
                        }),
                      e.jsxs("form", {
                        onSubmit: n,
                        className: "deposit-form",
                        children: [
                          u.general &&
                            e.jsx("div", {
                              className: "form-error-general",
                              children: u.general[0],
                            }),
                          e.jsxs("div", {
                            className: "form-group",
                            children: [
                              e.jsx("label", {
                                htmlFor: "amount",
                                children: "Valor do Depósito",
                              }),
                              e.jsx("input", {
                                type: "text",
                                id: "amount",
                                name: "amount",
                                value: g,
                                onChange: (f) => h(formatCurrency(f.target.value)),
                                placeholder: "Digite o valor desejado",
                                disabled: c,
                                step: "0.01",
                                min: t?.limits?.min || 0,
                                max: t?.limits?.max || 0,
                              }),
                              t &&
                                e.jsxs("div", {
                                  className: "input-help",
                                  children: [
                                    "Entre ",
                                    V(t.limits.min),
                                    " e ",
                                    V(t.limits.max),
                                  ],
                                }),
                              u.amount &&
                                e.jsx("div", {
                                  className: "form-error",
                                  children: u.amount[0],
                                }),
                            ],
                          }),
                          e.jsxs("div", {
                            className: "form-group",
                            children: [
                              e.jsx("label", {
                                htmlFor: "cpf",
                                children: "CPF",
                              }),
                              e.jsx("input", {
                                type: "text",
                                id: "cpf",
                                name: "cpf",
                                value: y,
                                onChange: (f) => r(formatCPF(f.target.value)),
                                placeholder: "Digite o seu CPF",
                                disabled: c,
                               
                              }),
                             
                              u.cpf &&
                                e.jsx("div", {
                                  className: "form-error",
                                  children: u.cpf[0],
                                }),
                            ],
                          }),
                          e.jsxs("div", {
                            className: "form-actions",
                            children: [
                              e.jsx("button", {
                                type: "button",
                                className: "cancel-btn",
                                onClick: R,
                                disabled: c,
                                children: "Cancelar",
                              }),
                              e.jsx("button", {
                                type: "submit",
                                className: "submit-btn",
                                disabled: c || !g,
                                children: c
                                  ? e.jsxs(e.Fragment, {
                                      children: [
                                        e.jsx("div", {
                                          className: "loading-spinner small",
                                        }),
                                        "Gerando PIX...",
                                      ],
                                    })
                                  : "Gerar PIX",
                              }),
                            ],
                          }),
                        ],
                      }),
                    ],
                  }),
                x === "payment" &&
                  v &&
                  e.jsxs("div", {
                    className: "payment-content",
                    children: [
                      e.jsxs("div", {
                        className: "payment-status",
                        children: [
                          e.jsx("div", {
                            className: "status-icon",
                            children: _
                              ? e.jsx("div", { className: "loading-spinner" })
                              : e.jsx("svg", {
                                  width: "24",
                                  height: "24",
                                  viewBox: "0 0 24 24",
                                  fill: "#ff9800",
                                  children: e.jsx("path", {
                                    d: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z",
                                  }),
                                }),
                          }),
                          e.jsxs("p", {
                            children: [
                              "Aguardando confirmação do pagamento de ",
                              e.jsx("strong", { children: V(v.amount) }),
                            ],
                          }),
                        ],
                      }),
                      e.jsxs("div", {
                        className: "qr-code-section",
                        children: [
                          e.jsx("div", {
                            className: "qr-code-container",
                            children: e.jsx("img", {
                              src: "data:image/png;base64," + v.qr_code,

                              alt: "QR Code PIX",
                              className: "qr-code-image",
                            }),
                          }),
                          e.jsxs("div", {
                            className: "pix-key-section",
                            children: [
                              e.jsx("label", {
                                children: "Chave PIX (Copia e Cola):",
                              }),
                              e.jsxs("div", {
                                className: "pix-key-container",
                                children: [
                                  e.jsx("input", {
                                    type: "text",
                                    value: v.pix_key,
                                    readOnly: !0,
                                    className: "pix-key-input",
                                  }),
                                  e.jsx("button", {
                                    type: "button",
                                    className: "copy-btn",
                                    onClick: () => q(v.pix_key),
                                    children: e.jsx("svg", {
                                      width: "16",
                                      height: "16",
                                      viewBox: "0 0 24 24",
                                      fill: "currentColor",
                                      children: e.jsx("path", {
                                        d: "M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z",
                                      }),
                                    }),
                                  }),
                                ],
                              }),
                            ],
                          }),
                        ],
                      }),
                      e.jsxs("div", {
                        className: "payment-instructions",
                        children: [
                          e.jsx("h4", { children: "Instruções:" }),
                          e.jsxs("ol", {
                            children: [
                              e.jsx("li", {
                                children:
                                  "Escaneie o QR Code com seu app do banco",
                              }),
                              e.jsx("li", {
                                children: "Ou copie e cole a chave PIX",
                              }),
                              e.jsxs("li", {
                                children: [
                                  "Confirme o pagamento de ",
                                  V(v.amount),
                                ],
                              }),
                              e.jsx("li", {
                                children: "Aguarde a confirmação automática",
                              }),
                            ],
                          }),
                        ],
                      }),
                    ],
                  }),
                x === "success" &&
                  e.jsxs("div", {
                    className: "deposit-success",
                    children: [
                      e.jsx("div", {
                        className: "success-icon",
                        children: e.jsx("svg", {
                          width: "48",
                          height: "48",
                          viewBox: "0 0 24 24",
                          fill: "#4caf50",
                          children: e.jsx("path", {
                            d: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z",
                          }),
                        }),
                      }),
                      e.jsx("h3", { children: "Depósito confirmado!" }),
                      e.jsxs("p", {
                        children: [
                          "Seu depósito de ",
                          e.jsx("strong", { children: v && V(v.amount) }),
                          " foi processado com sucesso.",
                        ],
                      }),
                    ],
                  }),
              ],
            }),
          ],
        }),
      })
    : null;
}
function ce({
  show: w,
  onClose: z,
  onSuccess: m,
  referralId: j,
  hidePhoneLogin: t,
}) {
  const [d, g] = i.useState(!1),
    [h, u] = i.useState(!1),
    [l, c] = i.useState({}),
    [C, v] = i.useState({ email: "", password: "" }),
    [N, x] = i.useState({
      name: "",
      phone: "",
      password: "",
      password_confirmation: "",
      referral_id: j || "",
    });
  W.useEffect(() => {
    x((s) => ({ ...s, referral_id: j || "" }));
  }, [j]);
  function b() {
    let s = "";
    for (let n = 0; n < 13; n++) s += Math.floor(Math.random() * 10);
    return s;
  }
  W.useEffect(() => {
    t && x((s) => ({ ...s, phone: b() }));
  }, [t, w]);
  function _(s) {
    return (
      (s = s.replace(/\D/g, "")),
      s.length > 11 && (s = s.slice(0, 11)),
      s.length > 6
        ? `(${s.slice(0, 2)}) ${s.slice(2, 7)}-${s.slice(7)}`
        : s.length > 2
        ? `(${s.slice(0, 2)}) ${s.slice(2)}`
        : s.length > 0
        ? `(${s}`
        : ""
    );
  }
  const M = async (s) => {
      s.preventDefault(), u(!0), c({});
      try {
        const n = await D.post(route("login-to-game.store"), C, {
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
          },
        });
        n.status === 200 &&
          n.data.success &&
          (m(n.data.user), z(), v({ email: "", password: "" }));
      } catch (n) {
        n.response?.status === 422
          ? c(n.response.data.errors || {})
          : c({ general: n.response?.data?.message || "Erro ao fazer login" });
      } finally {
        u(!1);
      }
    },
    o = async (s) => {
      s.preventDefault(), u(!0), c({});
      let n = "";
      const p = new URLSearchParams(window.location.search).get("ref");
      p && (n = p);
      try {
        const S = await D.post(
          "/register",
          { ...N, referral_id: n || N.referral_id },
          {
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
              "X-Requested-With": "XMLHttpRequest",
            },
          }
        );
        (S.status === 200 || S.status === 201) &&
        S.data.success &&
        S.data.user &&
        S.data.user.id
          ? (m(S.data.user),
            z(),
            x({
              name: "",
              phone: "",
              password: "",
              password_confirmation: "",
              referral_id: j || "",
            }))
          : c({
              general:
                S.data?.message || "Erro ao criar conta, tente novamente.",
            });
      } catch (S) {
        S.response?.status === 422
          ? c(S.response.data.errors || {})
          : c({ general: S.response?.data?.message || "Erro ao criar conta" });
      } finally {
        u(!1);
      }
    },
    a = () => {
      c({}),
        v({ email: "", password: "" }),
        x({
          name: "",
          phone: "",
          password: "",
          password_confirmation: "",
          referral_id: j || "",
        }),
        z();
    };
  return w
    ? e.jsx("div", {
        className: "profile-modal-overlay",
        onClick: a,
        children: e.jsxs("div", {
          className: "profile-modal auth-modal",
          onClick: (s) => s.stopPropagation(),
          children: [
            e.jsxs("div", {
              className: "profile-modal-header",
              children: [
                e.jsx("h2", {
                  children: d ? "Acesse sua conta" : "Criar nova conta",
                }),
                e.jsx("button", {
                  className: "profile-modal-close",
                  onClick: a,
                  children: "✕",
                }),
              ],
            }),
            l.general &&
              e.jsx("div", {
                className: "auth-error-message",
                children: l.general,
              }),
            e.jsxs("div", {
              className: "auth-content p-4",
              children: [
                d
                  ? e.jsxs("form", {
                      onSubmit: M,
                      className: "auth-form",
                      children: [
                        e.jsxs("div", {
                          className: "form-group",
                          children: [
                            e.jsx("label", {
                              children: "Nome da conta (login)",
                            }),
                            e.jsxs("div", {
                              className: "input-with-icon",
                              children: [
                                e.jsx("svg", {
                                  xmlns: "http://www.w3.org/2000/svg",
                                  width: "16",
                                  height: "16",
                                  fill: "currentColor",
                                  viewBox: "0 0 16 16",
                                  children: e.jsx("path", {
                                    d: "M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0zm4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4zm-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10c-2.29 0-3.516.68-4.168 1.332-.678.678-.83 1.418-.832 1.664h10z",
                                  }),
                                }),
                                e.jsx("input", {
                                  type: "text",
                                  value: C.email,
                                  onChange: (s) =>
                                    v((n) => ({ ...n, email: s.target.value })),
                                  placeholder: "Digite seu nome de conta",
                                  required: !0,
                                  className: l.email ? "error" : "",
                                }),
                              ],
                            }),
                            l.email &&
                              e.jsx("span", {
                                className: "field-error",
                                children: l.email[0],
                              }),
                          ],
                        }),
                        e.jsxs("div", {
                          className: "form-group",
                          children: [
                            e.jsx("label", { children: "Senha" }),
                            e.jsxs("div", {
                              className: "input-with-icon",
                              children: [
                                e.jsx("svg", {
                                  xmlns: "http://www.w3.org/2000/svg",
                                  width: "16",
                                  height: "16",
                                  fill: "currentColor",
                                  viewBox: "0 0 16 16",
                                  children: e.jsx("path", {
                                    d: "M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2zM5 8h6a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z",
                                  }),
                                }),
                                e.jsx("input", {
                                  type: "password",
                                  value: C.password,
                                  onChange: (s) =>
                                    v((n) => ({
                                      ...n,
                                      password: s.target.value,
                                    })),
                                  placeholder: "Digite sua senha",
                                  required: !0,
                                  className: l.password ? "error" : "",
                                }),
                              ],
                            }),
                            l.password &&
                              e.jsx("span", {
                                className: "field-error",
                                style: { color: "#ef4444" },
                                children:
                                  l.password[0] ===
                                  "The password field must be at least 8 characters."
                                    ? "A senha deve ter pelo menos 8 caracteres."
                                    : l.password[0],
                              }),
                          ],
                        }),
                        e.jsx("div", {
                          className: "auth-actions",
                          style: { width: "100%", display: "flex" },
                          children: e.jsx("button", {
                            type: "submit",
                            className: "confirm-bet-btn",
                            disabled: h,
                            children: h ? "Entrando..." : "Entrar",
                          }),
                        }),
                      ],
                    })
                  : e.jsxs("form", {
                      onSubmit: o,
                      className: "auth-form",
                      children: [
                        e.jsxs("div", {
                          className: "form-group",
                          children: [
                            e.jsx("label", {
                              children: "Nome da conta (login)",
                            }),
                            e.jsxs("div", {
                              className: "input-with-icon",
                              children: [
                                e.jsx("svg", {
                                  xmlns: "http://www.w3.org/2000/svg",
                                  width: "16",
                                  height: "16",
                                  fill: "currentColor",
                                  viewBox: "0 0 16 16",
                                  children: e.jsx("path", {
                                    d: "M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0zm4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4zm-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10c-2.29 0-3.516.68-4.168 1.332-.678.678-.83 1.418-.832 1.664h10z",
                                  }),
                                }),
                                e.jsx("input", {
                                  type: "text",
                                  value: N.name,
                                  onChange: (s) =>
                                    x((n) => ({
                                      ...n,
                                      name: s.target.value.replace(
                                        /[^a-zA-Z0-9]/g,
                                        ""
                                      ),
                                    })),
                                  placeholder: "Crie um nome de usuário",
                                  required: !0,
                                  maxLength: "20",
                                  className: l.name ? "error" : "",
                                }),
                              ],
                            }),
                            l.name &&
                              e.jsx("span", {
                                className: "field-error",
                                children: l.name[0],
                              }),
                          ],
                        }),
                        !t &&
                          e.jsxs("div", {
                            className: "form-group",
                            children: [
                              e.jsx("label", { children: "Telefone" }),
                              e.jsxs("div", {
                                className: "input-with-icon",
                                children: [
                                  e.jsxs("svg", {
                                    xmlns: "http://www.w3.org/2000/svg",
                                    width: "16",
                                    height: "16",
                                    fill: "currentColor",
                                    viewBox: "0 0 16 16",
                                    children: [
                                      e.jsx("path", {
                                        d: "M11 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h6zM5 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2H5z",
                                      }),
                                      e.jsx("path", {
                                        d: "M8 14a1 1 0 1 0 0-2 1 1 0 0 0 0 2z",
                                      }),
                                    ],
                                  }),
                                  e.jsx("input", {
                                    type: "tel",
                                    value: N.phone,
                                    onChange: (s) => {
                                      const n = _(s.target.value);
                                      x((F) => ({ ...F, phone: n }));
                                    },
                                    placeholder: "Digite seu telefone",
                                    required: !0,
                                    className: l.phone ? "error" : "",
                                  }),
                                ],
                              }),
                              l.phone &&
                                e.jsx("span", {
                                  className: "field-error",
                                  children: l.phone[0],
                                }),
                            ],
                          }),
                        e.jsxs("div", {
                          className: "form-group",
                          children: [
                            e.jsx("label", { children: "Senha" }),
                            e.jsxs("div", {
                              className: "input-with-icon",
                              children: [
                                e.jsx("svg", {
                                  xmlns: "http://www.w3.org/2000/svg",
                                  width: "16",
                                  height: "16",
                                  fill: "currentColor",
                                  viewBox: "0 0 16 16",
                                  children: e.jsx("path", {
                                    d: "M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2zM5 8h6a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z",
                                  }),
                                }),
                                e.jsx("input", {
                                  type: "password",
                                  value: N.password,
                                  onChange: (s) =>
                                    x((n) => ({
                                      ...n,
                                      password: s.target.value,
                                    })),
                                  placeholder: "Crie uma senha segura",
                                  required: !0,
                                  className: l.password ? "error" : "",
                                }),
                              ],
                            }),
                            l.password &&
                              e.jsx("span", {
                                className: "field-error",
                                style: { color: "#ef4444" },
                                children:
                                  l.password[0] ===
                                  "The password field must be at least 8 characters."
                                    ? "A senha deve ter pelo menos 8 caracteres."
                                    : l.password[0],
                              }),
                          ],
                        }),
                        e.jsxs("div", {
                          className: "form-group",
                          children: [
                            e.jsx("label", { children: "Confirmar Senha" }),
                            e.jsxs("div", {
                              className: "input-with-icon",
                              children: [
                                e.jsx("svg", {
                                  xmlns: "http://www.w3.org/2000/svg",
                                  width: "16",
                                  height: "16",
                                  fill: "currentColor",
                                  viewBox: "0 0 16 16",
                                  children: e.jsx("path", {
                                    d: "M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2zM5 8h6a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z",
                                  }),
                                }),
                                e.jsx("input", {
                                  type: "password",
                                  value: N.password_confirmation,
                                  onChange: (s) =>
                                    x((n) => ({
                                      ...n,
                                      password_confirmation: s.target.value,
                                    })),
                                  "data-form-type": "other",
                                  placeholder: "Confirme sua senha",
                                  required: !0,
                                }),
                              ],
                            }),
                          ],
                        }),
                        e.jsx("div", {
                          className: "auth-actions",
                          children: e.jsx("button", {
                            type: "submit",
                            style: { width: "100%" },
                            className: "confirm-bet-btn",
                            disabled: h,
                            children: h
                              ? "Criando conta..."
                              : "Criar conta gratuita",
                          }),
                        }),
                      ],
                    }),
                e.jsx("div", {
                  className: "auth-switch w-full mt-2",
                  children: e.jsx("button", {
                    className: "auth-switch-btn",
                    style: { width: "100%", cursor: "pointer" },
                    onClick: () => {
                      g(!d), c({});
                    },
                    disabled: h,
                    children: d
                      ? "Não tem conta? Criar agora"
                      : "Já tem conta? Fazer login",
                  }),
                }),
              ],
            }),
          ],
        }),
      })
    : null;
}
export { ce as A, oe as D, ne as P, re as S, ie as W };
