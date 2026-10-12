"""Alertas SIEM -> Telegram con un dashboard visual (CPU / RAM / Disco).

Uso:
  1) En tu bucle de monitorización, guarda una muestra por agente en cada vuelta:
         record_sample(ip, cpu=..., ram=..., disk=...)
     (así las alertas pueden dibujar el histórico).
  2) Al detectar un hallazgo, llama a send_alert(...) pasando también ram=...
     La alerta muestra SIEMPRE el estado actual de CPU, RAM y disco, y resalta
     el recurso al que se refiere la alerta (detectado por título/descripción,
     o forzado con metric="cpu" | "ram" | "disk").
"""

import html
import io
import math
import numbers
import re
import statistics
import threading
import time
from collections import deque
from datetime import datetime, timedelta

import numpy as np
import requests
from matplotlib.colors import to_rgb, to_rgba
from matplotlib.figure import Figure
from matplotlib.patches import Arc, Circle, FancyBboxPatch, Polygon, Rectangle

# Importas tus variables desde tu settings.py
from server.config.settings import botTOKEN, chatID

# ─────────────────────────── Estilo ───────────────────────────
W, M, GAP = 1280, 30, 20  # ancho del dashboard, margen y separación (px)
WARN, CRIT = 75, 90  # umbrales de uso (%)

BG, CARD, EDGE = "#0b0f19", "#131a2b", "#232d45"
TEXT, MUTED, TRACK = "#eef2ff", "#8590ad", "#222c45"
OK, WARNING, DANGER = "#34d399", "#fbbf24", "#fb7185"
C_CPU, C_RAM, C_DISK = "#22d3ee", "#c084fc", "#f472b6"
MONO = "DejaVu Sans Mono"

_SEVERITY = {
    "CRITICAL": ("#ff4d6d", "🔴"), "CRITICA": ("#ff4d6d", "🔴"), "CRÍTICA": ("#ff4d6d", "🔴"),
    "HIGH": ("#ff8a3d", "🟠"), "ALTA": ("#ff8a3d", "🟠"),
    "WARNING": ("#ffc23d", "🟡"), "MEDIUM": ("#ffc23d", "🟡"), "MEDIA": ("#ffc23d", "🟡"),
}
_DEFAULT_SEVERITY = ("#38bdf8", "🔵")

# Palabras que delatan de qué recurso trata la alerta
_METRIC_PATTERNS = {
    "cpu": r"\b(cpu|procesador\w*|processor\w*|load\s*avg\w*|load average)\b",
    "ram": r"\b(ram|mem|memoria\w*|memory|swap|oom)\b",
    "disk": r"\b(disco\w*|disk\w*|almacenamiento|storage|filesystem|partici[oó]n\w*|inodes?)\b|/dev/\w+",
}
_METRIC_NAMES = {"cpu": "CPU", "ram": "RAM", "disk": "DISCO"}


def _detect_metric(*texts):
    """Mira primero el título y luego la descripción. Solo decide si hay UN recurso claro."""
    for text in texts:
        found = [k for k, pat in _METRIC_PATTERNS.items() if re.search(pat, str(text or ""), re.I)]
        if len(found) == 1:
            return found[0]
    return None


# ───────────────────── Parseo de métricas ─────────────────────
_PCT = re.compile(r"(-?\d+(?:[.,]\d+)?)\s*%")
_PLAIN = re.compile(r"^\s*-?\d+(?:[.,]\d+)?\s*$")
_LEAD = re.compile(r"^\s*(\d+(?:[.,]\d+)?)\s*([A-Za-z]*)")
_RATIO = re.compile(r"(\d+(?:[.,]\d+)?)\s*([KMGTP]i?B?)\s*(?:/|de|of)\s*(\d+(?:[.,]\d+)?)\s*([KMGTP]i?B?)", re.I)
_PCT_KEYS = ("usage", "percent", "used_percent", "percent_used", "pct", "uso", "porcentaje", "value")


def _is_num(v):
    return isinstance(v, numbers.Real) and not isinstance(v, bool) and not math.isnan(float(v))


def _human_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _fmt_amount(v, as_bytes=None):
    if _is_num(v):
        if as_bytes is None:
            as_bytes = abs(v) >= 1024
        return _human_bytes(v) if as_bytes else f"{v:g}"
    return str(v)


def _summarize_dict(d, limit=3):
    """Cifras clave de un dict sin porcentaje (p.ej. contadores de I/O): primero los bytes."""
    items = [(k, v) for k, v in d.items() if _is_num(v)]
    if not items:  # dict de dicts (p.ej. un dispositivo por clave): resume el primero
        for k, v in d.items():
            if isinstance(v, dict):
                inner = _summarize_dict(v, limit - 1)
                if inner:
                    return [str(k)] + inner
        return []
    items.sort(key=lambda kv: "byte" not in str(kv[0]).lower())
    return [f"{str(k).replace('_', ' ')} {_fmt_amount(v, 'byte' in str(k).lower())}" for k, v in items[:limit]]


def _ratio_percent(used, total):
    """'118 GB' y '250 GB' -> 47.2 (solo si las unidades coinciden)."""
    mu, mt = _LEAD.match(str(used)), _LEAD.match(str(total))
    if not (mu and mt) or mu.group(2).lower() != mt.group(2).lower():
        return None
    u, t = float(mu.group(1).replace(",", ".")), float(mt.group(1).replace(",", "."))
    return u / t * 100 if t > 0 else None


def _to_float(v):
    """Número, "73", "73%", "118GB / 250GB" -> porcentaje (float). Otra cosa -> None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, numbers.Real):
        f = float(v)
        return None if math.isnan(f) else f
    if isinstance(v, str):
        m = _PCT.search(v)
        if m:
            return float(m.group(1).replace(",", "."))
        if _PLAIN.match(v):
            return float(v.replace(",", "."))
        m = _RATIO.search(v)
        if m:
            return _ratio_percent(m.group(1) + m.group(2), m.group(3) + m.group(4))
    return None


_NESTED_PREFS = ("virtual_memory", "memory", "ram", "mem", "usage")


def _from_psutil_list(kind, seq):
    """virtual_memory / swap_memory serializados como lista (namedtuple de psutil)."""
    if not isinstance(seq, (list, tuple)) or not seq or not all(_is_num(x) for x in seq):
        return None
    swap = "swap" in str(kind).lower()
    idx = 3 if swap else 2  # svmem: total, available, percent, ... | sswap: total, used, free, percent, ...
    if len(seq) <= idx + (0 if swap else 2) or not (seq[0] >= seq[1] >= 0 and 0 <= seq[idx] <= 100):
        return None
    return float(seq[idx])


def _parse_metric(value):
    """Devuelve (serie_en_porcentaje, texto_extra).

    Acepta: número, "73%", "118GB / 250GB", lista de números, o dict con
    percent/usage/value, history/series, used+total o total+available (estilo psutil),
    incluso anidados (p.ej. {"virtual_memory": {...}, "swap_memory": {...}}).
    Si un dict no trae porcentaje (p.ej. contadores de I/O), `texto_extra` resume sus cifras.
    """
    note = ""
    if isinstance(value, dict):
        raw = value.get("history") or value.get("series") or []
        series = [f for f in (_to_float(v) for v in raw) if f is not None] if isinstance(raw, (list, tuple)) else []
        if not series:
            for key in _PCT_KEYS:
                f = _to_float(value.get(key))
                if f is not None:
                    series = [f]
                    break
        if not series:  # claves tipo "disk_percent", "mem_usage"...
            for key, v in value.items():
                if re.search(r"percent|pct|usage|uso", str(key), re.I):
                    f = _to_float(v)
                    if f is not None:
                        series = [f]
                        break
        used, total = value.get("used"), value.get("total")
        if used is not None and total is not None:
            note = f"{_fmt_amount(used)} / {_fmt_amount(total)}"
            if not series:
                f = _ratio_percent(used, total)
                series = [f] if f is not None else []
        if not series and _is_num(total) and total > 0:  # total + available/free
            free = next((value[k] for k in ("available", "free") if _is_num(value.get(k))), None)
            if free is not None:
                series = [(1 - free / total) * 100]
        if not series:  # estructura anidada: {"virtual_memory": {...}, "swap_memory": {...}}
            nested = [(k, v) for k, v in value.items()
                      if isinstance(v, (dict, list, tuple)) and "swap" not in str(k).lower()]
            nested.sort(key=lambda kv: next((i for i, p in enumerate(_NESTED_PREFS) if p in str(kv[0]).lower()), 99))
            for key, sub in nested:
                if isinstance(sub, dict):
                    s_, n_ = _parse_metric(sub)
                    if s_:
                        series, note = s_, n_
                        break
                elif re.search(r"mem|ram", str(key), re.I):
                    f = _from_psutil_list(key, sub)
                    if f is not None:
                        series = [f]
                        break
        if series:  # swap como dato extra
            swap = next((v for k, v in value.items() if "swap" in str(k).lower()), None)
            sp = (next(iter(_parse_metric(swap)[0]), None) if isinstance(swap, dict)
                  else _from_psutil_list("swap", swap) if swap is not None else None)
            if sp is not None:
                note = f"{note}\nswap {sp:.0f}%".strip("\n")
        if not series and not note:
            note = "\n".join(_summarize_dict(value))
    elif isinstance(value, (list, tuple)):
        series = [f for f in (_to_float(v) for v in value) if f is not None]
    else:
        f = _to_float(value)
        series = [f] if f is not None else []
        if f is None and value not in (None, ""):
            note = str(value)  # p.ej. "OK" o "N/A"
    return [min(max(v, 0.0), 100.0) for v in series], note


class _Metric:
    def __init__(self, name, color, value, history=None):
        self.name, self.color = name, color
        self.series, self.note = _parse_metric(value)
        history = history or []
        if len(self.series) < 2 and len(history) >= 2:  # histórico guardado con record_sample()
            cur = self.series[-1] if self.series else None
            self.series = list(history) + ([cur] if cur is not None and abs(cur - history[-1]) > 1e-9 else [])
        self.current = self.series[-1] if self.series else None


def _status(p):
    if p is None:
        return MUTED, "SIN DATOS"
    if p >= CRIT:
        return DANGER, "CRÍTICO"
    if p >= WARN:
        return WARNING, "ELEVADO"
    return OK, "NORMAL"


def _trunc(text, n):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: max(n - 1, 0)].rstrip() + "…"


def _fmt_network(network):
    if network is None or (isinstance(network, str) and not network.strip()):
        return "Sin datos"
    if isinstance(network, dict):
        def pick(pattern):
            return next((v for k, v in network.items() if re.search(pattern, str(k), re.I) and _is_num(v)), None)

        up = pick(r"sent|(^|_)tx|upload|(^|_)up($|_)")
        down = pick(r"recv|(^|_)rx|download|(^|_)down($|_)")
        if up is not None or down is not None:
            fmt = lambda x: "—" if x is None else _human_bytes(x)
            return f"↑ {fmt(up)}  ↓ {fmt(down)}"
        parts = _summarize_dict(network, 2)
        return " · ".join(parts) if parts else _trunc(network, 60)
    return str(network)


# ───────────────── Histórico de muestras por agente ─────────────────
class MetricHistory:
    """Últimas muestras de CPU / RAM / disco de cada agente, para dibujar el histórico."""

    def __init__(self, maxlen=90):
        self._maxlen = maxlen
        self._data = {}
        self._lock = threading.Lock()

    def record(self, ip, **values):
        now = time.time()
        with self._lock:
            for name, value in values.items():
                series, _ = _parse_metric(value)
                if series:
                    self._data.setdefault((str(ip), name), deque(maxlen=self._maxlen)).append((now, series[-1]))

    def values(self, ip, name):
        with self._lock:
            return [v for _, v in self._data.get((str(ip), name), ())]

    def interval(self, ip):
        """Segundos medios entre muestras de ese agente (None si aún hay pocas)."""
        with self._lock:
            buffers = [b for (i, _), b in self._data.items() if i == str(ip)]
            if not buffers:
                return None
            stamps = [t for t, _ in max(buffers, key=len)]
        if len(stamps) < 2:
            return None
        return statistics.median(b - a for a, b in zip(stamps, stamps[1:]))


HISTORY = MetricHistory()


def record_sample(ip, cpu=None, ram=None, disk=None):
    """Guarda una muestra del agente. Llámala en cada vuelta de tu bucle de monitorización."""
    HISTORY.record(ip, cpu=cpu, ram=ram, disk=disk)


# ───────────────────── Piezas de dibujo ─────────────────────
def _glow(ax, h, cx, cy, radius, color, strength):
    """Resplandor radial suave para dar profundidad al fondo."""
    yy, xx = np.mgrid[0:h, 0:W]
    d = np.clip(1 - np.hypot(xx - cx, yy - cy) / radius, 0, 1)
    img = np.zeros((h, W, 4))
    img[..., :3] = to_rgb(color)
    img[..., 3] = strength * d**2
    ax.imshow(img, extent=(0, W, 0, h), origin="lower", aspect="auto", zorder=0)


def _card(ax, x, y, w, h, edge=EDGE, lw=1):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0,rounding_size=18",
        fc=CARD, ec=edge, lw=lw, zorder=1))


def _gradient_fill(ax, x, y, color, alpha=0.20):
    """Relleno bajo la curva que se desvanece hacia abajo."""
    rgba = np.zeros((128, 1, 4))
    rgba[..., :3] = to_rgb(color)
    rgba[:, 0, 3] = np.linspace(alpha, 0, 128)
    im = ax.imshow(rgba, extent=(x[0], x[-1], 0, max(float(np.max(y)), 1.0)),
                   origin="upper", aspect="auto", zorder=2)
    clip = Polygon(np.column_stack([[x[0], *x, x[-1]], [0, *y, 0]]),
                   closed=True, transform=ax.transData)
    im.set_clip_path(clip)


def _ring(ax, cx, cy, r, pct, color, lw=11):
    """Medidor circular de 270° con halo de neón."""
    def arc(t1, t2, c, width, alpha=1.0, z=4):
        ax.add_patch(Arc((cx, cy), 2 * r, 2 * r, theta1=t1, theta2=t2, color=c,
                         lw=width, alpha=alpha, capstyle="round", zorder=z))

    arc(-45, 225, TRACK, lw, z=3)
    if pct is None or pct <= 0:
        return
    start = 225 - 270 * pct / 100
    arc(start, 225, color, lw + 10, 0.07)
    arc(start, 225, color, lw + 5, 0.13)
    arc(start, 225, color, lw)


def _metric_card(ax, x, y, w, h, m, focus=False, accent=TEXT):
    nodata = m.current is None
    if focus:  # halo alrededor del recurso al que se refiere la alerta
        ax.add_patch(FancyBboxPatch((x - 3, y - 3), w + 6, h + 6, boxstyle="round,pad=0,rounding_size=21",
                                    fc="none", ec=accent, lw=5, alpha=0.14, zorder=1))
    _card(ax, x, y, w, h, edge=accent if focus else EDGE, lw=1.6 if focus else 1)
    color, status = _status(m.current)
    if nodata and m.note:
        status = "SIN % DE USO"
    cx, cy, r = x + 92, y + h / 2, 54
    _ring(ax, cx, cy, r, m.current, color)
    ax.text(cx, cy, "N/D" if nodata else f"{m.current:.0f}%",
            ha="center", va="center", color=MUTED if nodata else TEXT, weight="bold", family=MONO,
            fontsize=13 if nodata else 17, zorder=6)

    tx = cx + r + 34
    ax.add_patch(Circle((tx + 5, y + h - 36), 5, color=m.color, alpha=0.4 if nodata else 1, zorder=5))
    ax.text(tx + 20, y + h - 36, m.name, color=MUTED if nodata else TEXT, fontsize=14,
            weight="bold", va="center", zorder=5)
    if focus:
        ax.text(x + w - 22, y + h - 36, "● ALERTA", color=accent, fontsize=8.5, weight="bold",
                ha="right", va="center", family=MONO, zorder=5)

    pw = 9 * len(status) + 24
    ax.add_patch(FancyBboxPatch((tx, y + h - 82), pw, 24, boxstyle="round,pad=0,rounding_size=12",
                                fc=to_rgba(color, 0.15), ec=color, lw=1, zorder=4))
    ax.text(tx + pw / 2, y + h - 70, status, color=color, fontsize=9, weight="bold",
            ha="center", va="center", family=MONO, zorder=5)

    note_lines = m.note.split("\n") if m.note else []
    lines = []
    if len(m.series) > 1:
        lines.append(f"Prom {np.mean(m.series):.0f}%  Máx {max(m.series):.0f}%")
    lines += note_lines
    if nodata and not note_lines:
        lines = ["Sin dato del agente"]
    elif not lines:
        lines = ["Muestra actual"]
    for i, line in enumerate(lines[:3]):
        ax.text(tx, y + h - 108 - i * 22, _trunc(line, 26), color=MUTED, fontsize=9.5, family=MONO,
                va="center", zorder=5)


def _chip(ax, x, y, w, h, label, value):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=14",
                                fc=CARD, ec=EDGE, lw=1, zorder=2))
    ax.text(x + 18, y + h - 17, label.upper(), color=MUTED, fontsize=8, weight="bold", va="center", zorder=4)
    ax.text(x + 18, y + 17, _trunc(value, int((w - 36) / 9.2)), color=TEXT, fontsize=11,
            weight="bold", family=MONO, va="center", zorder=4)


def _draw_history(fig, ax_bg, h_fig, box, metrics, sample_interval, now):
    x0, y0, w, h = box
    _card(ax_bg, x0, y0, w, h)
    ty = y0 + h - 30
    ax_bg.text(x0 + 26, ty, "Rendimiento reciente" if len(metrics) > 1 else f"Evolución de {metrics[0].name}",
               color=TEXT, fontsize=12.5,
               weight="bold", va="center", zorder=5)

    # Leyenda (derecha) con el último valor de cada serie
    rx = x0 + w - 26
    for m in reversed(metrics):
        label = f"{m.name}  {m.current:.0f}%"
        tw = len(label) * 8.8
        ax_bg.text(rx, ty, label, ha="right", va="center", color=TEXT, fontsize=10.5, family=MONO, zorder=5)
        ax_bg.add_patch(Circle((rx - tw - 14, ty), 5, color=m.color, zorder=5))
        rx -= tw + 44

    ax = fig.add_axes([(x0 + 66) / W, (y0 + 44) / h_fig, (w - 66 - 96) / W, (h - 44 - 66) / h_fig])
    ax.patch.set_alpha(0)
    n = max(len(m.series) for m in metrics)
    ax.set_xlim(0, n - 1)
    ax.set_ylim(0, 100)

    # Zonas de riesgo
    ax.axhspan(WARN, CRIT, color=WARNING, alpha=0.06, lw=0)
    ax.axhspan(CRIT, 100, color=DANGER, alpha=0.09, lw=0)
    for lvl, col, txt in ((WARN, WARNING, "WARN"), (CRIT, DANGER, "CRIT")):
        ax.axhline(lvl, color=col, lw=1, ls=(0, (4, 4)), alpha=0.55)
        ax.text(1.035, lvl, f"{txt} {lvl}", transform=ax.get_yaxis_transform(),
                color=col, fontsize=8, va="center", ha="left", alpha=0.9)

    highest = max(metrics, key=lambda m: m.current)
    for m in metrics:
        y = np.array(m.series)
        x = np.arange(n - len(y), n)
        for lw, a in ((11, 0.05), (7, 0.09), (4, 0.15)):  # halo neón
            ax.plot(x, y, color=m.color, lw=lw, alpha=a, solid_capstyle="round",
                    solid_joinstyle="round", zorder=3)
        ax.plot(x, y, color=m.color, lw=2.2, solid_capstyle="round", solid_joinstyle="round", zorder=4)
        _gradient_fill(ax, x, y, m.color)
        ax.scatter([x[-1]], [y[-1]], s=340, color=m.color, alpha=0.18, zorder=5, clip_on=False)
        ax.scatter([x[-1]], [y[-1]], s=60, color=m.color, edgecolor=CARD, linewidth=2, zorder=6, clip_on=False)
        ax.annotate(f"{y[-1]:.0f}%", (x[-1], y[-1]), xytext=(-16, 17 if m is highest else -17),
                    textcoords="offset points", ha="right", va="center", fontsize=9, weight="bold",
                    color=BG, zorder=8, bbox=dict(boxstyle="round,pad=0.3", fc=m.color, ec="none"))

    # Ejes
    ax.set_xlim(0, n - 1)
    ax.set_ylim(0, 100)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_yticklabels([f"{t}%" for t in (0, 25, 50, 75, 100)])
    idx = list(range(n)) if n <= 10 else sorted({int(i) for i in np.linspace(0, n - 1, 7).round()})
    labels = []
    for i in idx:
        if sample_interval:
            t = now - timedelta(seconds=(n - 1 - i) * sample_interval)
            labels.append("ahora" if i == n - 1 else t.strftime("%H:%M" if sample_interval >= 60 else "%H:%M:%S"))
        else:
            labels.append("ahora" if i == n - 1 else f"-{n - 1 - i}")
    ax.set_xticks(idx)
    ax.set_xticklabels(labels)
    ax.tick_params(colors=MUTED, labelsize=9, length=0, pad=8)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.grid(axis="y", color="#ffffff", alpha=0.06, lw=1)
    ax.set_axisbelow(True)


# ─────────────────────── Dashboard completo ───────────────────────
def build_chart(metrics, severity, title, description, chips, sample_interval=None, now=None, focus=None):
    """Genera el dashboard y devuelve un BytesIO con el PNG."""
    now = now or datetime.now()
    sev = str(severity).upper()
    sev_color, _ = _SEVERITY.get(sev, _DEFAULT_SEVERITY)
    plotted = [m for m in metrics if len(m.series) > 1]

    card_h, hist_h, chip_h, head_h = 170, 300, 58, 80
    H = M + head_h + GAP + card_h + GAP + (hist_h + GAP if plotted else 0) + chip_h + M
    y_cards = H - M - head_h - GAP - card_h

    fig = Figure(figsize=(W / 100, H / 100), dpi=100, facecolor=BG)
    bg = fig.add_axes([0, 0, 1, 1])
    bg.axis("off")
    _glow(bg, H, 120, H, 760, sev_color, 0.20)
    _glow(bg, H, W - 80, 0, 620, C_RAM, 0.10)
    bg.set_xlim(0, W)
    bg.set_ylim(0, H)

    # Cabecera
    bg.add_patch(Rectangle((0, H - 5), W, 5, color=sev_color, lw=0, zorder=5))
    yt = H - M - 22
    pw = 10 * len(sev) + 32
    bg.add_patch(FancyBboxPatch((M, yt - 17), pw, 34, boxstyle="round,pad=0,rounding_size=17",
                                fc=to_rgba(sev_color, 0.16), ec=sev_color, lw=1.4, zorder=3))
    bg.text(M + pw / 2, yt, sev, color=sev_color, fontsize=11, weight="bold", family=MONO,
            ha="center", va="center", zorder=4)
    bg.text(M + pw + 18, yt, _trunc(title, 58), color=TEXT, fontsize=19, weight="bold", va="center", zorder=4)
    bg.text(W - M, yt, "SIEM · ALERTA", color=MUTED, fontsize=9, weight="bold", ha="right", va="center", zorder=4)
    bg.text(M + 4, yt - 42, _trunc(description, 125), color=MUTED, fontsize=11, va="center", zorder=4)

    # Tarjetas de métricas
    cw = (W - 2 * M - 2 * GAP) / 3
    for i, m in enumerate(metrics):
        _metric_card(bg, M + i * (cw + GAP), y_cards, cw, card_h, m, focus=(m.name == focus), accent=sev_color)

    # Histórico
    if plotted:
        y_hist = y_cards - GAP - hist_h
        _draw_history(fig, bg, H, (M, y_hist, W - 2 * M, hist_h), plotted, sample_interval, now)

    # Chips de información
    chips = chips[:6]
    weights = [max(len(v), len(l), 9) for l, v in chips]
    usable = W - 2 * M - GAP * (len(chips) - 1)
    cx = M
    for (label, value), wt in zip(chips, weights):
        cw_i = usable * wt / sum(weights)
        _chip(bg, cx, M, cw_i, chip_h, label, value)
        cx += cw_i + GAP

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, facecolor=BG)
    buf.seek(0)
    return buf


# ───────────────────────── Telegram ─────────────────────────
def _bar(pct, width=10):
    filled = round(pct / 100 * width)
    return "▰" * filled + "▱" * (width - filled)


def _build_caption(severity, title, description, metrics, ip, network, hostname, now, focus=None):
    esc = html.escape
    icon = _SEVERITY.get(str(severity).upper(), _DEFAULT_SEVERITY)[1]

    rows = []
    for m in metrics:
        mark = "  ◀" if m.name == focus else ""
        rows.append(f"{m.name:<6}{'N/D':>14}{mark}" if m.current is None
                    else f"{m.name:<6}{_bar(m.current)} {m.current:>3.0f}%{mark}")
        if m.note:
            rows.append("      " + _trunc(m.note.replace("\n", " · "), 30))

    def make(desc_limit):
        parts = [f"{icon} <b>{esc(str(severity).upper())}</b> · <i>SIEM</i>", f"<b>{esc(_trunc(title, 150))}</b>"]
        if desc_limit:
            parts.append(f"<blockquote>{esc(_trunc(description, desc_limit))}</blockquote>")
        parts.append("<pre>" + esc("\n".join(rows)) + "</pre>")
        host = f"🖥 <code>{esc(str(hostname))}</code>  " if hostname else ""
        parts.append(f"{host}🌐 <code>{esc(str(ip))}</code>\n🔌 {esc(_trunc(_fmt_network(network), 80))}\n"
                     f"🕒 {now.strftime('%d/%m/%Y %H:%M:%S')}")
        return "\n".join(parts)

    for limit in (350, 200, 100, 0):  # Telegram limita el caption a 1024 caracteres
        caption = make(limit)
        if len(caption) <= 1024:
            break
    return caption


def _telegram(method, data, files=None):
    return requests.post(f"https://api.telegram.org/bot{botTOKEN}/{method}",
                         data=data, files=files, timeout=20)


_SEEN = set()
_LAST_SENT, _LAST_LOCK = {}, threading.Lock()


def _shape(v, depth=0, max_depth=3, values=False):
    """Descripción compacta de una estructura: claves y tipos (y valores de ejemplo si values=True)."""
    if isinstance(v, dict):
        if depth >= max_depth:
            return "{…}"
        body = ", ".join(f"{k}: {_shape(x, depth + 1, max_depth, values)}" for k, x in list(v.items())[:8])
        return "{" + body + (", …" if len(v) > 8 else "") + "}"
    if isinstance(v, (list, tuple)):
        first = f" de {_shape(v[0], depth + 1, max_depth, values)}" if v and depth < max_depth else ""
        return f"list[{len(v)}]{first}"
    if v is None:
        return "None"
    if _is_num(v):
        return f"{type(v).__name__}({v:g})" if values else type(v).__name__
    return repr(v)[:24] if values else type(v).__name__


def peek(obj, max_depth=3):
    """Imprime/devuelve la estructura de un agente o dict (nombres, tipos y valores de ejemplo).

    Úsalo una vez para ver qué datos tiene realmente:  print(peek(self.get_agent(ip)))
    """
    data = obj
    if not isinstance(obj, dict):
        for attr in ("model_dump", "dict", "_asdict"):
            fn = getattr(obj, attr, None)
            if callable(fn):
                try:
                    data = fn()
                    break
                except Exception:
                    pass
        else:
            data = getattr(obj, "__dict__", obj)
    if isinstance(data, dict):
        return "\n".join(f"{k}: {_shape(v, 1, max_depth, True)}" for k, v in data.items())
    return _shape(data, 0, max_depth, True)


def first_available(getter, ip, names):
    """Prueba varios nombres de dispositivo/interfaz y devuelve el primer dato que exista."""
    for name in names:
        try:
            value = getter(ip, name)
        except Exception:
            continue
        if value is not None and value != {} and value != "":
            return value
    return None


def _once(msg):
    if msg not in _SEEN:
        _SEEN.add(msg)
        print(msg)


def _diagnose(name, value):
    """Avisos en consola (una sola vez por tipo de problema) para ver qué llega del agente."""
    if value is None:
        _once(f"[!] '{name}' llegó vacío (None): ¿el agente lo reporta? ¿el nombre de dispositivo/interfaz es el correcto?")
    elif name != "network" and not _parse_metric(value)[0]:
        if isinstance(value, (dict, list, tuple)):
            _once(f"[i] '{name}' sin porcentaje. Estructura: {_shape(value)}")
        else:
            _once(f"[!] '{name}' = {value!r} no contiene un porcentaje utilizable.")


def send_alert(ip, network, cpu, disk, severity, title, description,
               ram=None, hostname=None, uptime=None, sample_interval=None, extra=None,
               metric=None, history=None, cooldown=0):
    """Genera el dashboard y envía la alerta a Telegram.

    cpu / ram / disk: estado ACTUAL de cada recurso. Aceptan un número (73), texto ("73%"),
        una lista de muestras o un dict ({"percent": 73, "used": ..., "total": ...}).
    metric: "cpu" | "ram" | "disk". Resalta ese recurso en el dashboard. Si no se indica,
        se detecta por el título/descripción. No modifica ningún dato.
    history: MetricHistory a usar (por defecto el global alimentado con record_sample()).
    cooldown: segundos mínimos entre alertas iguales (misma IP y mismo título, ignorando números).
        Con 0 (por defecto) se envían todas. Recomendado: 300.
    sample_interval: segundos entre muestras; si se omite se calcula del histórico.
    extra: dict opcional con datos adicionales, p.ej. {"Usuario": "root"}.
    """
    now = datetime.now()
    key = (str(ip), re.sub(r"\d+(?:[.,]\d+)?", "#", str(title)).strip().lower())
    if cooldown:
        with _LAST_LOCK:
            last = _LAST_SENT.get(key)
        if last is not None and time.time() - last < cooldown:
            return False  # alerta repetida dentro del periodo de enfriamiento

    history = history or HISTORY
    raw = {"cpu": cpu, "ram": ram, "disk": disk}
    for name, val in (*raw.items(), ("network", network)):
        _diagnose(name, val)

    metrics = [_Metric(label, color, raw[key], history.values(ip, key))
               for key, label, color in (("cpu", "CPU", C_CPU), ("ram", "RAM", C_RAM), ("disk", "DISCO", C_DISK))]
    sample_interval = sample_interval or history.interval(ip)
    focus_name = _METRIC_NAMES.get(str(metric).lower() if metric else _detect_metric(title, description))

    chips = []
    if hostname:
        chips.append(("Host", str(hostname)))
    chips.append(("IP del agente", str(ip)))
    chips.append(("Red", _fmt_network(network)))
    if uptime:
        chips.append(("Uptime", str(uptime)))
    chips.append(("Hora", now.strftime("%d/%m %H:%M:%S")))
    chips += [(str(k), str(v)) for k, v in (extra or {}).items()]

    caption = _build_caption(severity, title, description, metrics, ip, network, hostname, now, focus_name)

    try:
        image = build_chart(metrics, severity, title, description, chips, sample_interval, now, focus_name)
    except Exception as e:  # una alerta nunca debe perderse por un fallo del gráfico
        print(f"[-] No se pudo generar el gráfico, enviando solo texto: {e}")
        image = None

    try:
        if image:
            response = _telegram(
                "sendPhoto",
                {"chat_id": chatID, "caption": caption, "parse_mode": "HTML"},
                {"photo": ("alert_chart.png", image, "image/png")},
            )
        else:
            response = _telegram("sendMessage", {"chat_id": chatID, "text": caption, "parse_mode": "HTML"})

        if response.status_code == 200:
            with _LAST_LOCK:
                _LAST_SENT[key] = time.time()
            print(f"[+] Alerta enviada a Telegram para la IP: {ip}")
            return True
        print(f"[-] Error al enviar a Telegram. Código: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error de conexión con la API de Telegram: {e}")
    return False