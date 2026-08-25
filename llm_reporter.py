import json
import urllib.request
import config


# ============================================================
# LOAD ANALYSIS RESULTS
# ============================================================

def load_analysis(filepath=None):
    """
    Load the analysed scan results from JSON.
    """
    if filepath is None:
        filepath = config.ANALYSIS_RESULTS_PATH

    with open(filepath) as f:
        return json.load(f)


# ============================================================
# BUILD DETERMINISTIC REPORT DATA
# ============================================================

def build_report_data(analysis):
    """
    Prepare the report information in Python.
    """

    score = analysis.get('score', 0)
    rating = analysis.get('rating', 'Unknown')
    findings = analysis.get('findings', [])

    rule_findings = [
        f for f in findings
        if not f.get('cve_id')
    ]

    cve_findings = [
        f for f in findings
        if f.get('cve_id')
    ]

    severity_order = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3
    }

    sorted_findings = sorted(
        rule_findings,
        key=lambda x: severity_order.get(
            str(x.get('severity', 'low')).lower(),
            3
        )
    )

    most_critical = (
        sorted_findings[0]
        if sorted_findings
        else None
    )

    if most_critical:
        critical_name = most_critical.get(
            'name',
            'Unknown issue'
        )

        critical_host = most_critical.get(
            'host',
            'Unknown host'
        )

    else:
        critical_name = 'No findings'
        critical_host = 'None'

    recommended_fixes = []

    for finding in rule_findings:

        name = finding.get(
            'name',
            'Unknown finding'
        )

        severity = finding.get(
            'severity',
            'unknown'
        )

        host = finding.get(
            'host',
            'Unknown host'
        )

        remediation = finding.get(
            'remediation',
            'No remediation provided.'
        )

        recommended_fixes.append({
            'name': name,
            'severity': severity,
            'host': host,
            'remediation': remediation
        })

    cve_summary = []

    for cve in cve_findings:

        cve_id = cve.get(
            'cve_id',
            'Unknown CVE'
        )

        cvss_score = cve.get(
            'cvss_score',
            'Unknown'
        )

        host = cve.get(
            'host',
            'Unknown host'
        )

        remediation = cve.get(
            'remediation',
            'Review and patch this vulnerability.'
        )

        cve_summary.append({
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'host': host,
            'remediation': remediation
        })

    return {
        'score': score,
        'rating': rating,
        'critical_name': critical_name,
        'critical_host': critical_host,
        'recommended_fixes': recommended_fixes,
        'cve_summary': cve_summary
    }


# ============================================================
# BUILD LLM PROMPT
# ============================================================

def build_prompt(report_data):
    """
    Build a small prompt for the LLM.
    """

    score = report_data['score']
    rating = report_data['rating']

    critical_name = report_data[
        'critical_name'
    ]

    critical_host = report_data[
        'critical_host'
    ]

    fix_count = len(
        report_data['recommended_fixes']
    )

    cve_count = len(
        report_data['cve_summary']
    )

    prompt = f"""
Write only the following two parts of a network security report.

Do not write the findings list.
Do not write the CVE list.
Do not add headings other than the two headings specified below.
Do not invent any information.
Do not add hosts, IP addresses, CVEs, vulnerabilities, services,
ports, remediation steps, or security issues that are not provided.

EXECUTIVE SUMMARY

Write exactly two sentences.

Sentence 1:
State that the network security score is {score}/100
and state the rating as {rating}.

Sentence 2:
State that the most critical issue is
"{critical_name}" on "{critical_host}".

Do not add any other security issue to the Executive Summary.

CONCLUSION

Write exactly two sentences.

Sentence 1:
State the overall urgency of remediation based on the
critical finding and the overall security rating.

Sentence 2:
State that the most critical finding should be addressed first.

Do not invent additional findings or recommendations.

FACTS FOR CONTEXT:

Security score: {score}/100
Rating: {rating}
Most critical finding: {critical_name}
Most critical host: {critical_host}
Number of non-CVE findings: {fix_count}
Number of CVEs: {cve_count}

OUTPUT EXACTLY:

EXECUTIVE SUMMARY
[two sentences]

CONCLUSION
[two sentences]
"""

    return prompt


# ============================================================
# QUERY OLLAMA
# ============================================================

def query_ollama(prompt, model='phi3:mini'):
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": 250,
            "temperature": 0.1,
            "num_ctx": 2048
        },
        "keep_alive": -1
    }).encode('utf-8')

    req = urllib.request.Request(
        'http://localhost:11434/api/generate',
        data=payload,
        headers={
            'Content-Type': 'application/json'
        },
        method='POST'
    )

    with urllib.request.urlopen(req) as response:

        result = json.loads(
            response.read().decode('utf-8')
        )

        return result.get(
            'response',
            ''
        ).strip()


# ============================================================
# STREAM OLLAMA
# ============================================================

def stream_ollama(prompt, model='phi3:mini'):
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": True,
        "options": {
            "num_predict": 250,
            "temperature": 0.1,
            "num_ctx": 2048
        },
        "keep_alive": -1
    }).encode('utf-8')

    req = urllib.request.Request(
        'http://localhost:11434/api/generate',
        data=payload,
        headers={
            'Content-Type': 'application/json'
        },
        method='POST'
    )

    with urllib.request.urlopen(req) as response:

        for line in response:

            if not line:
                continue

            chunk = json.loads(
                line.decode('utf-8')
            )

            token = chunk.get(
                'response',
                ''
            )

            if token:
                yield token

            if chunk.get(
                'done',
                False
            ):
                break


# ============================================================
# FORMAT DETERMINISTIC FINDINGS
# ============================================================

def format_recommended_fixes(report_data):
    lines = []

    for finding in report_data[
        'recommended_fixes'
    ]:

        name = finding['name']
        host = finding['host']
        remediation = finding['remediation']

        lines.append(
            f"- {name} on {host}: {remediation}"
        )

    if not lines:
        lines.append(
            "- No findings requiring remediation."
        )

    return "\n".join(lines)


# ============================================================
# FORMAT DETERMINISTIC CVE SUMMARY
# ============================================================

def format_cve_summary(report_data):
    lines = []

    for cve in report_data[
        'cve_summary'
    ]:

        cve_id = cve['cve_id']
        cvss_score = cve['cvss_score']
        host = cve['host']
        remediation = cve['remediation']

        lines.append(
            f"- {cve_id} "
            f"(CVSS {cvss_score}) "
            f"on {host}: "
            f"{remediation}"
        )

    if not lines:
        lines.append(
            "- No CVEs found."
        )

    return "\n".join(lines)


# ============================================================
# COMBINE FINAL REPORT
# ============================================================

def build_final_report(ai_text, report_data):
    executive_summary = ""
    conclusion = ""

    lines = ai_text.splitlines()

    current_section = None

    executive_lines = []
    conclusion_lines = []

    for line in lines:

        stripped = line.strip()

        if not stripped:
            continue

        if stripped.upper() == 'EXECUTIVE SUMMARY':
            current_section = 'executive'
            continue

        if stripped.upper() == 'CONCLUSION':
            current_section = 'conclusion'
            continue

        if current_section == 'executive':
            executive_lines.append(stripped)

        elif current_section == 'conclusion':
            conclusion_lines.append(stripped)

    executive_summary = " ".join(
        executive_lines
    ).strip()

    conclusion = " ".join(
        conclusion_lines
    ).strip()

    if not executive_summary:

        executive_summary = (
            f"The network security score is "
            f"{report_data['score']}/100 with a "
            f"{report_data['rating']} rating. "
            f"The most critical issue is "
            f"{report_data['critical_name']} "
            f"on {report_data['critical_host']}."
        )

    if not conclusion:

        conclusion = (
            "Immediate remediation should be prioritised "
            "based on the severity of the identified issues. "
            f"The {report_data['critical_name']} finding "
            "should be addressed first."
        )

    recommended_fixes = (
        format_recommended_fixes(
            report_data
        )
    )

    cve_summary = (
        format_cve_summary(
            report_data
        )
    )

    final_report = (
        "EXECUTIVE SUMMARY\n"
        f"{executive_summary}\n\n"

        "RECOMMENDED FIXES\n"
        f"{recommended_fixes}\n\n"

        "CVE SUMMARY\n"
        f"{cve_summary}\n\n"

        "CONCLUSION\n"
        f"{conclusion}\n"
    )

    return final_report.strip()


# ============================================================
# SAVE REPORT
# ============================================================

def save_report(
    report_text,
    filepath=None
):
    if filepath is None:
        filepath = config.LLM_REPORT_PATH

    with open(filepath, 'w') as f:
        f.write(report_text)

    print(
        f"[+] Report saved to {filepath}"
    )
