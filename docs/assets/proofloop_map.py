"""Draw the Proofloop map shown at the top of the README, in a light and a dark version.

    python docs/assets/proofloop_map.py docs/assets

writes proofloop-map-light.svg and proofloop-map-dark.svg from one layout. Change the words or the
colours here and run it again; do not edit the two files by hand, or they drift apart. The files
use the reader's own system font and load nothing from outside.
"""
import sys, os, math

FONT = "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif"
W, H = 900, 620
COLS = [200, 450, 700]
TOP, BOT, R = 230, 410, 90
CY = (TOP + BOT) // 2

PAL = {
  'light': dict(bg='#ffffff', border='#e2e8f0', rail='#ccfbf1', chev='#0d9488', node='#0d9488', nodetx='#ffffff',
                ring='#ffffff', eyebrow='#0f766e', title='#0f172a', body='#475569', muted='#64748b',
                inner='#f5fdfb', chip='#ffffff', chipbd='#d5e3e1', chiptx='#1e293b', hair='#e2e8f0',
                det='#0d9488', prev='#3b82f6', miss='#dc2626', unp='#94a3b8'),
  'dark': dict(bg='#0d1117', border='#30363d', rail='#123f3b', chev='#2dd4bf', node='#2dd4bf', nodetx='#04201d',
               ring='#0d1117', eyebrow='#2dd4bf', title='#f0f6fc', body='#9da7b3', muted='#8b949e',
               inner='#0f171b', chip='#161b22', chipbd='#30363d', chiptx='#e6edf3', hair='#21262d',
               det='#2dd4bf', prev='#58a6ff', miss='#f85149', unp='#8b949e'),
}

STATIONS = [  # n, cx, row, title, two caption lines
  (1, COLS[0], 'top', 'Pick',   ['Untested and overdue', 'rules go first']),
  (2, COLS[1], 'top', 'Attack', ['A real technique runs on', 'a lab machine you own']),
  (3, COLS[2], 'top', 'Wait',   ['Until the rule has had', 'its turn to run']),
  (4, COLS[2], 'bot', 'Ask',    ['Is the alert there, on that', 'machine, in that window?']),
  (5, COLS[1], 'bot', 'Judge',  ['Fixed rules decide,', 'never a guess or a model']),
  (6, COLS[0], 'bot', 'Record', ['Kept in a ledger that is', 'only ever added to']),
]
CHIPS = [('Detected', 'det', 106), ('Prevented', 'prev', 113), ('Missed', 'miss', 93), ('Unproven', 'unp', 109)]
DESC = ("Six steps on a loop, repeated every night. 1 Pick: untested and overdue rules go first. 2 Attack: a real "
        "technique runs on a lab machine you own. 3 Wait: until the rule has had its turn to run. 4 Ask: is the "
        "alert there, on that machine, in that window? 5 Judge: fixed rules decide, never a guess or a model. "
        "6 Record: kept in a ledger that is only ever added to. Each run ends as detected, prevented, missed or "
        "unproven. A miss is checked again the next night.")

def chevron(x, y, deg, c):
    return (f'<polyline points="-3.5,-5 3,0 -3.5,5" transform="translate({x},{y}) rotate({deg})" fill="none" '
            f'stroke="{c}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>')

def build(mode):
    p = PAL[mode]; o = []
    o.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
             f'aria-labelledby="t d" font-family="{FONT}">')
    o.append('<title id="t">How Zybur Proofloop works: one night, six steps</title>')
    o.append(f'<desc id="d">{DESC}</desc>')
    o.append(f'<rect x="0.5" y="0.5" width="{W-1}" height="{H-1}" rx="16" fill="{p["bg"]}" stroke="{p["border"]}"/>')
    # header
    o.append(f'<text x="48" y="52" font-size="13" font-weight="700" letter-spacing="1.5" fill="{p["eyebrow"]}">ZYBUR PROOFLOOP</text>')
    o.append(f'<text x="{W-48}" y="52" font-size="14" text-anchor="end" fill="{p["muted"]}">One night, six steps</text>')
    # the loop
    x0, x1 = COLS[0], COLS[2]
    o.append(f'<path d="M{x0},{TOP} H{x1} A{R},{R} 0 0 1 {x1},{BOT} H{x0} A{R},{R} 0 0 1 {x0},{TOP} Z" fill="{p["inner"]}" '
             f'stroke="{p["rail"]}" stroke-width="12"/>')
    for x in (325, 575): o.append(chevron(x, TOP, 0, p['chev']))
    o.append(chevron(x1 + R, CY, 90, p['chev']))
    for x in (575, 325): o.append(chevron(x, BOT, 180, p['chev']))
    o.append(chevron(x0 - R, CY, 270, p['chev']))
    # stations
    for n, cx, row, title, cap in STATIONS:
        cy = TOP if row == 'top' else BOT
        o.append(f'<circle cx="{cx}" cy="{cy}" r="24" fill="{p["node"]}" stroke="{p["ring"]}" stroke-width="4"/>')
        o.append(f'<text x="{cx}" y="{cy+6.5}" font-size="19" font-weight="700" text-anchor="middle" fill="{p["nodetx"]}">{n}</text>')
        ty = 140 if row == 'top' else 478
        o.append(f'<text x="{cx}" y="{ty}" font-size="22" font-weight="700" text-anchor="middle" fill="{p["title"]}">{title}</text>')
        for i, line in enumerate(cap):
            o.append(f'<text x="{cx}" y="{ty+25+i*20}" font-size="15" text-anchor="middle" fill="{p["body"]}">{line}</text>')
    # centre
    o.append(f'<text x="450" y="287" font-size="12.5" font-weight="700" letter-spacing="1.6" text-anchor="middle" fill="{p["eyebrow"]}">EVERY NIGHT</text>')
    o.append(f'<text x="450" y="319" font-size="24" font-weight="700" text-anchor="middle" fill="{p["title"]}">Did the alert really fire?</text>')
    gap = 10; total = sum(w for _, _, w in CHIPS) + gap * (len(CHIPS) - 1); x = 450 - total / 2
    for label, key, w in CHIPS:
        o.append(f'<rect x="{x:.1f}" y="337" width="{w}" height="28" rx="14" fill="{p["chip"]}" stroke="{p["chipbd"]}"/>')
        o.append(f'<circle cx="{x+17:.1f}" cy="351" r="4.5" fill="{p[key]}"/>')
        o.append(f'<text x="{x+29:.1f}" y="355.6" font-size="13.5" font-weight="600" fill="{p["chiptx"]}">{label}</text>')
        x += w + gap
    # footer
    o.append(f'<line x1="48" y1="566" x2="{W-48}" y2="566" stroke="{p["hair"]}"/>')
    o.append(f'<text x="450" y="595" font-size="14" text-anchor="middle" fill="{p["muted"]}">A miss is checked again the next night. '
             f'A rule that has not had its turn is pending, never missed.</text>')
    o.append('</svg>')
    return '\n'.join(o) + '\n'

out = sys.argv[1]; os.makedirs(out, exist_ok=True)
for mode in PAL:
    open(os.path.join(out, f'proofloop-map-{mode}.svg'), 'w', encoding='utf-8').write(build(mode))
    print(mode, 'ok')
