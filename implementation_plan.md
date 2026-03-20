# Phase 1 MVP – Infrastructure Security Auditor

Construir el esqueleto profesional completo del proyecto y los cuatro módulos core (Scanner, Analyzer, Reporter, CLI) tal como se define en [CLAUDE.md](file:///d:/Proyectos/infrastructure-security-auditor/CLAUDE.md) y el prompt de tarea.

---

## Proposed Changes

### Project Skeleton & Config

#### [NEW] `src/__init__.py`
Package marker.

#### [NEW] `src/scanner/__init__.py`, `src/analyzer/__init__.py`, `src/reporter/__init__.py`, `src/remediator/__init__.py`
Package markers + public API exports.

#### [NEW] `src/scanner/scripts/` (empty directory)
Placeholder para scripts auxiliares de PowerShell/WinRM futura integración.

#### [NEW] `pyproject.toml`
Metadata del paquete (nombre, versión, autores, dependencias, entry points).  
Dependencias: `click>=8.0`, `jinja2>=3.0`, `anthropic>=0.20`, `winrm>=0.4`, `python-dotenv>=1.0`, `rich>=13.0`, `pytest`, `flake8`, `black`.

#### [NEW] `setup.py`
Wrapper mínimo que lee `pyproject.toml` para compatibilidad con `pip install -e .`.

#### [NEW] `requirements.txt`
Pin de dependencias para instalación rápida con `pip install -r requirements.txt`.

#### [NEW] `.env.example`
Template con variables: `CLAUDE_API_KEY`, `WINRM_USERNAME`, `WINRM_PASSWORD`, `LOG_LEVEL`, `REPORT_OUTPUT_DIR`.

#### [NEW] `.vscode/settings.json`
Configuración para Python interpreter, linting (flake8), formatting (black), test discovery (pytest).

#### [NEW] `docs/`, `examples/case_studies/`, `examples/sample_reports/`
Carpetas vacías con `.gitkeep`.

---

### `src/config.py`

Carga variables de entorno vía `python-dotenv`.  
Define constantes globales:
- `SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}`
- `COMPLIANCE_CONTROLS` – mapeo de checks a controles ISO 27001 / CIS / PCI-DSS
- `APP_VERSION = "0.1.0"`

Configura logger centralizado (`logging.getLogger("auditor")`).

---

### `src/scanner/windows_scanner.py`

**Clase `WindowsScanner(target: str, credentials: dict | None = None)`**

Detecta si el escaneo es local (`target == "localhost"` o `"127.0.0.1"`) o remoto (vía WinRM).  
Cada check usa `subprocess.run` (PowerShell) o WinRM para ejecutar comandos y parsear stdout.

**15+ métodos de check** (cada uno retorna `FindingDict`):

| Método | Severidad máx | Técnica |
|---|---|---|
| `check_firewall()` | HIGH | `Get-NetFirewallProfile` |
| `check_smb_v1()` | CRITICAL | `Get-SmbServerConfiguration` |
| `check_llmnr_netbios()` | HIGH | Registro + `Get-NetAdapter` |
| `check_windows_defender()` | HIGH | `Get-MpComputerStatus` |
| `check_tls_versions()` | HIGH | `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols` |
| `check_password_policies()` | MEDIUM | `net accounts` |
| `check_rdp_nla()` | HIGH | `Get-ItemProperty` RDP reg key |
| `check_windows_update()` | MEDIUM | `Get-WindowsUpdateLog` / WUA COM |
| `check_admin_accounts()` | HIGH | `Get-LocalGroupMember Administrators` |
| `check_privilege_creep()` | MEDIUM | `Get-LocalGroupMember` multiple groups |
| `check_event_log_config()` | MEDIUM | `Get-WinEvent -ListLog` |
| `check_lsass_protection()` | HIGH | `HKLM:\SYSTEM\...\lsa` RunAsPPL |
| `check_weak_ciphers()` | HIGH | SCHANNEL reg keys |
| `check_file_sharing()` | MEDIUM | `Get-SmbShare` |
| `check_installed_software()` | LOW | `Get-Package` / registry |

**`run_scan() -> dict`** ejecuta todos los checks concurrentemente (vía `ThreadPoolExecutor`) y retorna:
```python
{
  "server": str,
  "timestamp": str,  # ISO 8601
  "scan_duration_seconds": float,
  "findings": list[FindingDict]
}
```

`FindingDict` shape:
```python
{
  "check": str,
  "status": Literal["PASS", "FAIL", "WARNING"],
  "severity": Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"],
  "description": str,
  "recommendation": str,
  "raw_output": str | None
}
```

---

### `src/analyzer/analyzer.py`

**Clase `Analyzer(findings: list[dict])`**

| Método | Descripción |
|---|---|
| `calculate_risk_score() -> float` | Promedio ponderado por `SEVERITY_WEIGHTS`, normalizado 0–10. Solo cuenta findings con status FAIL/WARNING. |
| `assign_severity_distribution() -> dict` | `{"CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n}` |
| `map_to_compliance() -> dict` | Mapea findings a controles. Format: `{"ISO_27001": 0.85, "CIS_Benchmarks": 0.78, "PCI_DSS": 0.72}` |
| `generate_recommendations() -> list[dict]` | Llama a Claude API con un prompt estructurado. Cae back a recomendaciones estáticas si la API falla. |
| `analyze() -> dict` | Orquesta todos los métodos anteriores. Retorna análisis completo. |

---

### `src/analyzer/risk_scorer.py`

**Clase `RiskScorer`** (stateless, métodos estáticos)  
Encapsula la lógica de cálculo de score para facilitar testing unitario por Agente 2.

---

### `src/reporter/html_generator.py` + `src/reporter/templates/report.html`

**Clase `HTMLReporter(analysis_data: dict)`**

`generate() -> str` renderiza el template Jinja2 en memoria y retorna HTML standalone (CSS inlineado, sin CDN).

**Secciones del template:**
1. **Executive Summary** – párrafo narrativo, risk score visual (color-coded badge)
2. **Risk Dashboard** – métrica 0–10 con barra de progreso CSS
3. **Security Findings** – tabla agrupada por severidad (CRITICAL → LOW), con badges y detalles expandibles (`<details>`)
4. **Compliance Status** – tablas ISO 27001 / CIS / PCI-DSS con porcentaje y barra CSS
5. **Detailed Recommendations** – lista ordenada por severidad
6. **Remediation Roadmap** – tabla con columnas: Priority, Finding, Effort, Timeline
7. **Technical Appendix** – JSON raw colapsable

---

### `src/cli.py` + `auditor.py` (root entry point)

Usa **Click**:

```
auditor scan  --target <IP|host>  --os windows  [--output scan.json]
auditor report --input scan.json  --output report.html
auditor version
```

`auditor.py` en la raíz simplemente importa y llama `cli()` para poder hacer `python auditor.py`.

---

### Tests Skeleton

#### [NEW] `tests/__init__.py`, `tests/test_basic.py`
Verifica que todos los módulos core importan sin error y que las clases se pueden instanciar con datos dummy.

#### [NEW] `tests/test_scanner.py`, `tests/test_analyzer.py`, `tests/test_reporter.py`
Skeletons con `pass` (Agente 2 los completa).

---

## Verification Plan

### Automated Tests

```bash
# Desde la raíz del proyecto (Windows PowerShell)
pip install -r requirements.txt

# 1. Verificar imports y clases
python -m pytest tests/test_basic.py -v

# 2. Correr todos los tests (deben pasar o skip)
python -m pytest tests/ -v

# 3. Verificar CLI carga correctamente
python auditor.py --help
python auditor.py version

# 4. Verificar import directo del scanner
python -c "from src.scanner.windows_scanner import WindowsScanner; s = WindowsScanner('localhost'); print('OK')"

# 5. Contar métodos de check del scanner
python -c "from src.scanner.windows_scanner import WindowsScanner; checks = [m for m in dir(WindowsScanner) if m.startswith('check_')]; print(f'{len(checks)} checks:', checks)"
```

Expected: ≥ 15 check methods, all imports succeed, CLI shows help text.

### Manual Verification (local Windows)

> [!IMPORTANT]
> Estos pasos requieren Windows con PowerShell. El scanner hará llamadas reales de PowerShell en localhost.

1. Abre PowerShell como Administrador
2. Ejecuta: `python auditor.py scan --target localhost --os windows --output scan_result.json`
3. Verifica que `scan_result.json` se crea con la estructura `{server, timestamp, findings, scan_duration_seconds}`
4. Ejecuta: `python auditor.py report --input scan_result.json --output report.html`
5. Abre `report.html` en el navegador y verifica que las 7 secciones están presentes
