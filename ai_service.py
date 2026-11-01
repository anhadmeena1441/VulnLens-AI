from offline_explainer import explain_finding as offline_explain


def explain_finding(finding: dict) -> str:
    result = offline_explain(finding)

    return f"""
1. WHAT WAS DETECTED

{result['title']}

Bandit Rule: {finding.get('test_id', 'Unknown')}
Severity: {finding.get('issue_severity', 'Unknown')}
Confidence: {finding.get('issue_confidence', 'Unknown')}
File: {finding.get('filename', 'Unknown')}
Line: {finding.get('line_number', 'Unknown')}

2. WHY IT MAY BE RISKY

{result['risk']}

3. POTENTIAL ATTACK SCENARIO

{result['attack']}

4. RECOMMENDED REMEDIATION

{result['recommendation']}

5. SAFER CODE EXAMPLE

{result['example']}

6. LIMITATIONS

This explanation is generated from a local rule-based knowledge base.
Validate the finding against the surrounding code and test any proposed fix.
"""
