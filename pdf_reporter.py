import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import config

GREEN      = colors.HexColor('#00bb55')
RED        = colors.HexColor('#cc3333')
ORANGE     = colors.HexColor('#dd6600')
YELLOW     = colors.HexColor('#aa8800')
LIGHT_GREY = colors.HexColor('#555555')
MID_GREY   = colors.HexColor('#888888')
RULE_GREY  = colors.HexColor('#cccccc')
BLACK      = colors.HexColor('#111111')

SEVERITY_COLOURS = {
    'critical': RED,
    'high':     ORANGE,
    'medium':   YELLOW,
    'low':      GREEN,
}
RATING_COLOURS = {
    'CRITICAL': RED,
    'POOR':     ORANGE,
    'MODERATE': YELLOW,
    'GOOD':     GREEN,
}

def load_data(base_dir):
    with open(os.path.join(base_dir, 'analysis_results.json')) as f:
        analysis = json.load(f)
    report_text = None
    p = os.path.join(base_dir, 'llm_report.txt')
    if os.path.exists(p):
        with open(p) as f:
            report_text = f.read()

    hosts = []
    scan_path = os.path.join(base_dir, 'scan_results.json')
    if os.path.exists(scan_path):
        with open(scan_path) as f:
            scan_data = json.load(f)
        if isinstance(scan_data, dict):
            hosts = scan_data.get('hosts', [])

    return analysis, report_text, hosts

def make_style(name, font, size, colour, align=TA_LEFT, bold=False, leading=None):
    fn = f'{font}-Bold' if bold else font
    return ParagraphStyle(
        name=name,
        fontName=fn,
        fontSize=size,
        textColor=colour,
        alignment=align,
        leading=leading or round(size * 1.35),
        spaceBefore=0,
        spaceAfter=0,
    )

def generate_pdf(base_dir=None):
    # Default to the project's own directory rather than relying on
    # whatever the current working directory happens to be.
    if base_dir is None:
        base_dir = config.BASE_DIR

    now = datetime.now()
    timestamp_file   = now.strftime('%Y-%m-%d_%H-%M-%S')
    timestamp_display = now.strftime('%d %B %Y at %H:%M')
    output_path = os.path.join(base_dir, f'security_report_{timestamp_file}.pdf')

    analysis, report_text, hosts = load_data(base_dir)
    score    = analysis['score']
    rating   = analysis['rating']
    findings = analysis['findings']

    score_col  = RATING_COLOURS.get(rating, BLACK)
    sty_title  = make_style('T1',  'Helvetica', 16, GREEN,      TA_CENTER, bold=True,  leading=20)
    sty_sub    = make_style('T2',  'Helvetica',  9, MID_GREY,   TA_CENTER,             leading=13)
    sty_score  = make_style('T3',  'Helvetica', 42, score_col,  TA_CENTER, bold=True,  leading=50)
    sty_rating = make_style('T4',  'Helvetica', 12, score_col,  TA_CENTER, bold=True,  leading=16)
    sty_sect   = make_style('T5',  'Helvetica',  8, MID_GREY,   TA_LEFT,   bold=True,  leading=11)
    sty_fname  = make_style('T6',  'Helvetica', 10, BLACK,      TA_LEFT,   bold=True,  leading=14)
    sty_fmeta  = make_style('T7',  'Helvetica',  8, MID_GREY,   TA_LEFT,               leading=12)
    sty_fdevice = make_style('T7b', 'Helvetica', 8, GREEN,      TA_LEFT,               leading=12)
    sty_fdesc  = make_style('T8',  'Helvetica',  9, LIGHT_GREY, TA_LEFT,               leading=13)
    sty_ffix   = make_style('T9',  'Helvetica',  9, GREEN,      TA_LEFT,               leading=13)
    sty_badge  = make_style('T10', 'Helvetica',  7, BLACK,      TA_CENTER, bold=True,  leading=10)
    sty_ai     = make_style('T11', 'Helvetica',  9, LIGHT_GREY, TA_LEFT,               leading=14)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm,  bottomMargin=20*mm,
    )

    S = Spacer
    HR = lambda: HRFlowable(width='100%', thickness=0.75, color=RULE_GREY, spaceAfter=0, spaceBefore=0)

    story = []

    # ── Header ───────────────────────────────────────────────
    story += [
        Paragraph('NETWORK VULNERABILITY SCANNER', sty_title),
        S(1, 3*mm),
        Paragraph('Portable Security Audit — Raspberry Pi 4', sty_sub),
        S(1, 1*mm),
        Paragraph(f'Downloaded: {timestamp_display}', sty_sub),
        S(1, 5*mm),
        HR(),
        S(1, 8*mm),
    ]

    # ── Score block ──────────────────────────────────────────
    story += [
        Paragraph(str(score), sty_score),
        S(1, 3*mm),
        Paragraph(rating, sty_rating),
        S(1, 2*mm),
        Paragraph(f'{len(findings)} finding(s) detected', sty_sub),
        S(1, 8*mm),
        HR(),
    ]

    # ── Discovered Hosts ─────────────────────────────────────
    # Every scanned device, regardless of whether it has any
    # findings — a device inventory, not just a vulnerable-devices
    # list (matches the dashboard's "Discovered Hosts" section).
    if hosts:
        story += [S(1, 5*mm), Paragraph('DISCOVERED HOSTS', sty_sect), S(1, 3*mm)]

        host_header_sty = make_style('HH', 'Helvetica', 7, MID_GREY, TA_LEFT, bold=True, leading=9)
        host_cell_sty   = make_style('HC', 'Helvetica', 7, BLACK,    TA_LEFT,             leading=9)

        table_rows = [[
            Paragraph('IP', host_header_sty),
            Paragraph('Hostname', host_header_sty),
            Paragraph('Vendor', host_header_sty),
            Paragraph('Device (OS)', host_header_sty),
            Paragraph('Ports', host_header_sty),
        ]]

        for host in hosts:
            port_count = sum(len(ports) for ports in host.get('protocols', {}).values())
            vendor   = host.get('vendor', '')
            os_guess = host.get('os', '')
            table_rows.append([
                Paragraph(host.get('ip', ''), host_cell_sty),
                Paragraph(host.get('hostname', '') or '—', host_cell_sty),
                Paragraph(vendor if vendor and vendor != 'Unknown' else '—', host_cell_sty),
                Paragraph(os_guess if os_guess and os_guess != 'Unknown' else '—', host_cell_sty),
                Paragraph(str(port_count), host_cell_sty),
            ])

        hosts_table = Table(table_rows, colWidths=['16%', '22%', '18%', '34%', '10%'])
        hosts_table.setStyle(TableStyle([
            ('VALIGN',        (0,0), (-1,-1), 'TOP'),
            ('LINEBELOW',     (0,0), (-1,0), 0.75, RULE_GREY),
            ('TOPPADDING',    (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))

        story += [hosts_table, S(1, 5*mm), HR()]

    # ── Findings ─────────────────────────────────────────────
    if findings:
        story += [S(1, 5*mm), Paragraph('FINDINGS', sty_sect), S(1, 3*mm)]

        for f in findings:
            sev       = f['severity'].lower()
            sev_col   = SEVERITY_COLOURS.get(sev, BLACK)
            badge_sty = make_style(f'B_{sev}', 'Helvetica', 7, sev_col, TA_CENTER, bold=True, leading=10)

            header = Table(
                [[Paragraph(f['name'], sty_fname), Paragraph(f['severity'].upper(), badge_sty)]],
                colWidths=['82%', '18%'],
            )
            header.setStyle(TableStyle([
                ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
                ('LEFTPADDING',   (0,0), (-1,-1), 0),
                ('RIGHTPADDING',  (0,0), (-1,-1), 0),
                ('TOPPADDING',    (0,0), (-1,-1), 0),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LINEBELOW',     (0,0), (-1,-1), 0.75, sev_col),
            ]))

            vendor = f.get('vendor', '')
            vendor_str = f" — {vendor}" if vendor and vendor != 'Unknown' else ''

            block = [
                header,
                S(1, 2*mm),
                Paragraph(f"{f['host']} ({f['hostname']}){vendor_str} — Port {f['port']}", sty_fmeta),
            ]

            # Device/detected-product line — only added when at least
            # one of the two is present, same rule the dashboard uses.
            device_os = f.get('os', '')
            product   = f.get('product', '')
            if (device_os and device_os != 'Unknown') or product:
                parts = []
                if device_os and device_os != 'Unknown':
                    parts.append(f"Device: {device_os}")
                if product:
                    parts.append(f"Detected: {product}")
                block += [
                    S(1, 1*mm),
                    Paragraph(' — '.join(parts), sty_fdevice),
                ]

            block += [
                S(1, 1.5*mm),
                Paragraph(f['description'], sty_fdesc),
                S(1, 1.5*mm),
                Paragraph(f"<b>Fix:</b> {f['remediation']}", sty_ffix),
                S(1, 5*mm),
            ]
            story.append(KeepTogether(block))

    story += [HR(), S(1, 5*mm)]

    # ── AI Report ────────────────────────────────────────────
    if report_text:
        story += [Paragraph('AI GENERATED REPORT', sty_sect), S(1, 3*mm)]
        for line in report_text.split('\n'):
            line = line.strip().replace('**', '')
            if not line:
                story.append(S(1, 3*mm))
            else:
                story += [Paragraph(line, sty_ai), S(1, 1.5*mm)]

    # ── Footer ───────────────────────────────────────────────
    story += [
        S(1, 6*mm),
        HR(),
        S(1, 2*mm),
        Paragraph(
            f'Generated by Sentinel — Downloaded {timestamp_display} — For authorised use only',
            sty_sub
        ),
    ]

    doc.build(story)
    print(f'[+] PDF saved to {output_path}')
    return output_path

if __name__ == '__main__':
    # Generates a test PDF into the project's own directory using
    # whatever analysis_results.json / llm_report.txt already exist there.
    generate_pdf()
