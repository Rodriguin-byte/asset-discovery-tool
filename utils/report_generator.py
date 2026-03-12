"""
Gerador de relatórios HTML - Versão Corrigida
"""

import json
import time
import os
from datetime import datetime
import base64

class ReportGenerator:
    def __init__(self, output_dir='./output/reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_html(self, data):
        """
        Gera HTML diretamente sem usar arquivos de template
        """
        
        # Estatísticas
        stats = data.get('statistics', {})
        subdomains = data.get('subdomains', [])
        technologies = data.get('technologies', [])
        open_ports = data.get('open_ports', [])
        vulnerabilities = data.get('vulnerabilities', [])
        screenshots = data.get('screenshots', [])
        
        # Gerar linhas da tabela de subdomínios
        subdomain_rows = ""
        for sub in subdomains[:50]:  # Limitar a 50 para performance
            status_class = "badge-success" if sub.get('status') == 200 else "badge-warning" if sub.get('status') and sub.get('status') < 400 else "badge-danger"
            status_text = sub.get('status', 'No HTTP') if sub.get('status') else 'No HTTP'
            subdomain_rows += f"""
            <tr>
                <td>{sub.get('name', 'N/A')}</td>
                <td>{sub.get('ip', 'N/A')}</td>
                <td><span class="badge {status_class}">{status_text}</span></td>
                <td>{sub.get('source', 'N/A')}</td>
            </tr>
            """
        
        # Gerar linhas da tabela de tecnologias
        tech_rows = ""
        for tech_data in technologies[:30]:
            url = tech_data.get('url', 'N/A')
            for tech in tech_data.get('technologies', [])[:5]:
                confidence_class = "badge-success" if tech.get('confidence') == 'high' else "badge-warning" if tech.get('confidence') == 'medium' else "badge-info"
                tech_rows += f"""
                <tr>
                    <td>{url}</td>
                    <td>{tech.get('technology', 'N/A')}</td>
                    <td>{tech.get('version', 'Unknown')}</td>
                    <td><span class="badge {confidence_class}">{tech.get('confidence', 'low')}</span></td>
                </tr>
                """
        
        # Gerar linhas da tabela de portas
        port_rows = ""
        for port in open_ports[:30]:
            port_rows += f"""
            <tr>
                <td>{port.get('host', 'N/A')}</td>
                <td>{port.get('port', 'N/A')}</td>
                <td>{port.get('service', 'unknown')}</td>
                <td>{port.get('banner', '')[:50]}</td>
            </tr>
            """
        
        # Gerar linhas da tabela de vulnerabilidades
        vuln_rows = ""
        for vuln in vulnerabilities:
            risk_class = f"vulnerability-{vuln.get('risk', 'low').lower()}"
            vuln_rows += f"""
            <tr>
                <td>{vuln.get('type', 'N/A')}</td>
                <td>{vuln.get('target', 'N/A')}</td>
                <td class="{risk_class}">{vuln.get('risk', 'N/A')}</td>
                <td>{vuln.get('description', 'N/A')}</td>
            </tr>
            """
        
        # Gerar grid de screenshots
        screenshot_grid = ""
        for shot in screenshots[:12]:
            img_data = ""
            if shot.get('image'):
                img_data = f'<img src="data:image/png;base64,{shot["image"]}" alt="{shot.get("url", "N/A")}">'
            else:
                img_data = f'<img src="{shot.get("filepath", "#")}" alt="{shot.get("url", "N/A")}">'
            
            screenshot_grid += f"""
            <div class="screenshot-card">
                {img_data}
                <div class="screenshot-info">
                    <h4>{shot.get('url', 'N/A')}</h4>
                    <p>Captured: {shot.get('timestamp', 'N/A')}</p>
                </div>
            </div>
            """
        
        # Template HTML completo (embutido diretamente no código)
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{data.get('target', 'Asset Discovery')} - Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            text-align: center;
            transition: transform 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 1.1em;
        }}
        
        .section {{
            padding: 40px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .section-title {{
            font-size: 1.8em;
            color: #333;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 3px solid #667eea;
            display: inline-block;
        }}
        
        .table-container {{
            overflow-x: auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 500;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
            color: #555;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .badge {{
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 500;
        }}
        
        .badge-success {{
            background: #28a745;
            color: white;
        }}
        
        .badge-warning {{
            background: #ffc107;
            color: #333;
        }}
        
        .badge-danger {{
            background: #dc3545;
            color: white;
        }}
        
        .badge-info {{
            background: #17a2b8;
            color: white;
        }}
        
        .vulnerability-high {{
            color: #dc3545;
            font-weight: bold;
        }}
        
        .vulnerability-medium {{
            color: #ffc107;
            font-weight: bold;
        }}
        
        .vulnerability-low {{
            color: #28a745;
            font-weight: bold;
        }}
        
        .screenshot-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }}
        
        .screenshot-card {{
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s;
        }}
        
        .screenshot-card:hover {{
            transform: translateY(-5px);
        }}
        
        .screenshot-card img {{
            width: 100%;
            height: 200px;
            object-fit: cover;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .screenshot-info {{
            padding: 15px;
        }}
        
        .screenshot-info h4 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 1.1em;
            word-break: break-all;
        }}
        
        .screenshot-info p {{
            color: #666;
            font-size: 0.9em;
        }}
        
        .footer {{
            background: #333;
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .footer p {{
            opacity: 0.8;
            font-size: 0.9em;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 2em;
            }}
            
            .section {{
                padding: 20px;
            }}
            
            .stat-number {{
                font-size: 2em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Asset Discovery Report</h1>
            <p>{data.get('target', 'Unknown')}</p>
            <p>Generated on {data.get('date', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{stats.get('total_subdomains', 0)}</div>
                <div class="stat-label">Total Subdomains</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number">{stats.get('resolved_hosts', 0)}</div>
                <div class="stat-label">Resolved Hosts</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number">{stats.get('open_ports', 0)}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number">{stats.get('vulnerabilities', 0)}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
        </div>
        
        {f'''
        <div class="section">
            <h2 class="section-title">🌐 Discovered Subdomains</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>IP Address</th>
                            <th>Status</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody>
                        {subdomain_rows}
                    </tbody>
                </table>
            </div>
            {f'<p><em>Showing {min(len(subdomains), 50)} of {len(subdomains)} subdomains</em></p>' if len(subdomains) > 50 else ''}
        </div>
        ''' if subdomains else ''}
        
        {f'''
        <div class="section">
            <h2 class="section-title">🔧 Detected Technologies</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Technology</th>
                            <th>Version</th>
                            <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {tech_rows}
                    </tbody>
                </table>
            </div>
        </div>
        ''' if technologies else ''}
        
        {f'''
        <div class="section">
            <h2 class="section-title">🔌 Open Ports</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Banner</th>
                        </tr>
                    </thead>
                    <tbody>
                        {port_rows}
                    </tbody>
                </table>
            </div>
        </div>
        ''' if open_ports else ''}
        
        {f'''
        <div class="section">
            <h2 class="section-title">⚠️ Vulnerabilities Found</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Target</th>
                            <th>Risk</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {vuln_rows}
                    </tbody>
                </table>
            </div>
        </div>
        ''' if vulnerabilities else ''}
        
        {f'''
        <div class="section">
            <h2 class="section-title">📸 Screenshots</h2>
            <div class="screenshot-grid">
                {screenshot_grid}
            </div>
        </div>
        ''' if screenshots else ''}
        
        <div class="footer">
            <p>Generated by Asset Discovery Tool v3.0</p>
            <p>For authorized security testing only</p>
        </div>
    </div>
</body>
</html>"""
        
        return html_content
    
    def generate_report(self, data):
        """Gera relatório completo"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/report_{timestamp}.html"
        
        # Preparar dados para o template
        template_data = {
            'target': data.get('target', 'Unknown'),
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'statistics': data.get('statistics', {}),
            'subdomains': data.get('subdomains', []),
            'technologies': data.get('technologies', []),
            'open_ports': data.get('open_ports', []),
            'vulnerabilities': data.get('vulnerabilities', []),
            'screenshots': data.get('screenshots', [])
        }
        
        # Gerar HTML
        html_content = self.generate_html(template_data)
        
        # Salvar arquivo
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\n[+] HTML report generated: {filename}")
        return filename
    