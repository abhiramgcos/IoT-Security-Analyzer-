
import os
import json
from datetime import datetime
from typing import Dict, List
from backend.config import settings
from backend.logger import Logger
from backend.database import Database

logger = Logger('report_generator').get_logger()

# HTML Template for reports
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Security Report - {subnet}</title>
    <style>
        :root {{
            --primary: #2563eb;
            --danger: #dc2626;
            --warning: #f59e0b;
            --success: #10b981;
            --bg: #f8fafc;
            --card: #ffffff;
            --text: #1e293b;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, var(--primary), #1d4ed8);
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }}
        .header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
        .header p {{ opacity: 0.9; }}
        .card {{
            background: var(--card);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .card h2 {{
            font-size: 1.25rem;
            margin-bottom: 1rem;
            color: var(--primary);
            border-bottom: 2px solid var(--primary);
            padding-bottom: 0.5rem;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}
        .metric {{
            background: var(--bg);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }}
        .metric .value {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary);
        }}
        .metric .label {{ color: #64748b; font-size: 0.875rem; }}
        .score-good {{ color: var(--success) !important; }}
        .score-medium {{ color: var(--warning) !important; }}
        .score-bad {{ color: var(--danger) !important; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background: var(--bg);
            font-weight: 600;
            color: #475569;
        }}
        tr:hover {{ background: #f1f5f9; }}
        .severity {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .severity-critical {{ background: #fef2f2; color: var(--danger); }}
        .severity-high {{ background: #fff7ed; color: #ea580c; }}
        .severity-medium {{ background: #fefce8; color: #ca8a04; }}
        .severity-low {{ background: #f0fdf4; color: var(--success); }}
        .recommendations ul {{ list-style: none; }}
        .recommendations li {{
            padding: 0.75rem;
            background: #eff6ff;
            border-left: 4px solid var(--primary);
            margin-bottom: 0.5rem;
            border-radius: 0 8px 8px 0;
        }}
        .footer {{
            text-align: center;
            padding: 2rem;
            color: #64748b;
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 IoT Security Report</h1>
            <p>Network: {subnet} | Generated: {generated_at}</p>
        </div>
        
        <div class="metrics">
            <div class="metric">
                <div class="value">{device_count}</div>
                <div class="label">Devices Found</div>
            </div>
            <div class="metric">
                <div class="value">{vuln_count}</div>
                <div class="label">Vulnerabilities</div>
            </div>
            <div class="metric">
                <div class="value {score_class}">{health_score}/100</div>
                <div class="label">Health Score</div>
            </div>
        </div>
        
        <div class="card">
            <h2>📊 Vulnerability Summary</h2>
            <div class="metrics">
                <div class="metric">
                    <div class="value score-bad">{critical_count}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="metric">
                    <div class="value" style="color:#ea580c">{high_count}</div>
                    <div class="label">High</div>
                </div>
                <div class="metric">
                    <div class="value score-medium">{medium_count}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="metric">
                    <div class="value score-good">{low_count}</div>
                    <div class="label">Low</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🖥️ Discovered Devices</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Manufacturer</th>
                        <th>Type</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {device_rows}
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <h2>⚠️ Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Component</th>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows}
                </tbody>
            </table>
        </div>
        
        <div class="card recommendations">
            <h2>💡 Recommendations</h2>
            <ul>
                {recommendation_items}
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by IoT Security Analyzer v1.0</p>
            <p>Report ID: {report_id}</p>
        </div>
    </div>
</body>
</html>
"""


class ReportGenerator:
    def __init__(self):
        self.report_dir = settings.REPORT_DIR
        os.makedirs(self.report_dir, exist_ok=True)
        self.db = Database()

    def _get_report_data(self, subnet: str, options: dict) -> Dict:
        """Collect all data for the report"""
        # 1. Fetch Devices
        devices = self.db.get_all_devices()
        device_count = len(devices)
        
        # 2. Aggregated Vulnerabilities
        vuln_details = []
        critical = high = medium = low = 0
        
        for dev in devices:
            dev_vulns = self.db.get_device_vulnerabilities(dev['id'])
            for vuln in dev_vulns:
                vuln['device_ip'] = dev.get('ip_address')
                vuln_details.append(vuln)
                
                severity = vuln.get('severity', 'LOW').upper()
                if severity == 'CRITICAL':
                    critical += 1
                elif severity == 'HIGH':
                    high += 1
                elif severity == 'MEDIUM':
                    medium += 1
                else:
                    low += 1
        
        total_vulns = len(vuln_details)
        
        # 3. Calculate Health Score
        health_score = 100
        health_score -= critical * 20
        health_score -= high * 10
        health_score -= medium * 5
        health_score -= low * 1
        health_score = max(0, health_score)
        
        # 4. Generate recommendations
        recommendations = []
        if critical > 0:
            recommendations.append("🚨 URGENT: Patch critical vulnerabilities immediately")
        if high > 0:
            recommendations.append("⚠️ Address high-severity vulnerabilities within 7 days")
        if medium > 0:
            recommendations.append("📋 Schedule remediation for medium-severity issues")
        
        # Check for common issues
        for dev in devices:
            ports = dev.get('open_ports', [])
            if 23 in ports:
                recommendations.append(f"🔒 Disable Telnet on {dev.get('ip_address')} - use SSH instead")
                break
        
        if health_score >= 80:
            recommendations.append("✅ Maintain current security posture with regular scans")
        else:
            recommendations.append("📊 Schedule weekly security assessments")
        
        recommendations.append("🔄 Keep all device firmware updated to latest versions")
        
        return {
            "report_id": int(datetime.now().timestamp()),
            "generated_at": datetime.now().isoformat(),
            "subnet": subnet,
            "options": options,
            "summary": {
                "devices_found": device_count,
                "vulnerabilities": total_vulns,
                "health_score": health_score,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low
            },
            "devices": devices,
            "vulnerabilities": vuln_details,
            "recommendations": recommendations
        }

    def generate(self, subnet: str, options: dict, format: str = "json") -> str:
        """Generate security report for subnet in specified format"""
        logger.info(f"Generating {format} report for {subnet}")
        
        report_data = self._get_report_data(subnet, options)
        report_id = report_data["report_id"]
        
        # Save JSON (always)
        json_path = os.path.join(self.report_dir, f"report_{report_id}.json")
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        if format == "html" or format == "pdf":
            self._generate_html(report_data, report_id)
        
        if format == "pdf":
            self._generate_pdf(report_data, report_id)
        
        return str(report_id)

    def _generate_html(self, data: Dict, report_id: int) -> str:
        """Generate HTML report"""
        summary = data["summary"]
        
        # Determine score class
        score = summary["health_score"]
        if score >= 80:
            score_class = "score-good"
        elif score >= 50:
            score_class = "score-medium"
        else:
            score_class = "score-bad"
        
        # Build device rows
        device_rows = ""
        for dev in data["devices"]:
            device_rows += f"""
            <tr>
                <td>{dev.get('ip_address', '')}</td>
                <td>{dev.get('hostname', 'Unknown')}</td>
                <td>{dev.get('manufacturer', 'Unknown')}</td>
                <td>{dev.get('device_type', 'Unknown')}</td>
                <td>{dev.get('status', 'unknown')}</td>
            </tr>
            """
        
        # Build vulnerability rows
        vuln_rows = ""
        for vuln in data["vulnerabilities"][:50]:  # Limit to 50
            severity = vuln.get('severity', 'LOW').upper()
            severity_class = f"severity-{severity.lower()}"
            description = vuln.get('description', '')[:100]
            if len(vuln.get('description', '')) > 100:
                description += "..."
                
            vuln_rows += f"""
            <tr>
                <td>{vuln.get('cve_id', '')}</td>
                <td>{vuln.get('component', '')}</td>
                <td><span class="severity {severity_class}">{severity}</span></td>
                <td>{vuln.get('cvss_score', 0)}</td>
                <td>{description}</td>
            </tr>
            """
        
        if not vuln_rows:
            vuln_rows = "<tr><td colspan='5' style='text-align:center'>No vulnerabilities found</td></tr>"
        
        # Build recommendation items
        recommendation_items = ""
        for rec in data["recommendations"]:
            recommendation_items += f"<li>{rec}</li>"
        
        # Fill template
        html_content = HTML_TEMPLATE.format(
            subnet=data["subnet"],
            generated_at=data["generated_at"],
            device_count=summary["devices_found"],
            vuln_count=summary["vulnerabilities"],
            health_score=summary["health_score"],
            score_class=score_class,
            critical_count=summary["critical"],
            high_count=summary["high"],
            medium_count=summary["medium"],
            low_count=summary["low"],
            device_rows=device_rows,
            vuln_rows=vuln_rows,
            recommendation_items=recommendation_items,
            report_id=report_id
        )
        
        html_path = os.path.join(self.report_dir, f"report_{report_id}.html")
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved: {html_path}")
        return html_path

    def _generate_pdf(self, data: Dict, report_id: int) -> str:
        """Generate PDF report using reportlab"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4, letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            logger.warning("reportlab not installed, falling back to HTML-only")
            return self._generate_html(data, report_id)
        
        pdf_path = os.path.join(self.report_dir, f"report_{report_id}.pdf")
        doc = SimpleDocTemplate(pdf_path, pagesize=A4)
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2563eb'),
            alignment=TA_CENTER
        )
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#1e293b')
        )
        
        elements = []
        summary = data["summary"]
        
        # Title
        elements.append(Paragraph("🔐 IoT Security Report", title_style))
        elements.append(Paragraph(f"Network: {data['subnet']} | Generated: {data['generated_at']}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Summary metrics
        elements.append(Paragraph("Executive Summary", heading_style))
        
        summary_data = [
            ['Metric', 'Value'],
            ['Devices Found', str(summary['devices_found'])],
            ['Total Vulnerabilities', str(summary['vulnerabilities'])],
            ['Health Score', f"{summary['health_score']}/100"],
            ['Critical', str(summary['critical'])],
            ['High', str(summary['high'])],
            ['Medium', str(summary['medium'])],
            ['Low', str(summary['low'])]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))
        
        # Devices
        elements.append(Paragraph("Discovered Devices", heading_style))
        
        devices = data.get('devices', [])[:20]  # Limit for PDF
        if devices:
            device_data = [['IP Address', 'Hostname', 'Manufacturer', 'Type']]
            for dev in devices:
                device_data.append([
                    dev.get('ip_address', ''),
                    dev.get('hostname', 'Unknown')[:20],
                    dev.get('manufacturer', 'Unknown')[:15],
                    dev.get('device_type', 'Unknown')[:15]
                ])
            
            device_table = Table(device_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
            device_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0'))
            ]))
            elements.append(device_table)
        else:
            elements.append(Paragraph("No devices found", styles['Normal']))
        
        elements.append(Spacer(1, 20))
        
        # Recommendations
        elements.append(Paragraph("Recommendations", heading_style))
        for rec in data.get('recommendations', []):
            elements.append(Paragraph(f"• {rec}", styles['Normal']))
            elements.append(Spacer(1, 5))
        
        # Footer
        elements.append(Spacer(1, 40))
        elements.append(Paragraph(
            f"Generated by IoT Security Analyzer v1.0 | Report ID: {report_id}",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey, alignment=TA_CENTER)
        ))
        
        doc.build(elements)
        logger.info(f"PDF report saved: {pdf_path}")
        return pdf_path

    def get_available_formats(self, report_id: str) -> List[str]:
        """Check which formats are available for a report"""
        formats = []
        for fmt in ['json', 'html', 'pdf']:
            path = os.path.join(self.report_dir, f"report_{report_id}.{fmt}")
            if os.path.exists(path):
                formats.append(fmt)
        return formats

