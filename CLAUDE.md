# Proyecto: Infrastructure Security Auditor

## Stack
- Python 3.11+
- FastAPI/Click (CLI)
- Jinja2 (HTML templating)
- Requests (HTTP)
- Claude API (Anthropic)

## Agentes Asignados

### Agente 1: claude-sonnet-4-6
**Rol:** Arquitectura principal + Features nuevas + Decisiones técnicas
- Diseña módulos
- Implementa features complejas
- Resuelve problemas arquitectónicos
- Code reviews de alto nivel

### Agente 2: claude-haiku-4-5-20251001
**Rol:** Refactoring + Bug fixes + Optimizaciones
- Refactoriza código (limpieza)
- Debuggea issues
- Optimiza performance
- Implementa fixes rutinarios

### Agente 3: claude-haiku-4-5-20251001
**Rol:** Documentación + Comentarios + README
- Escribe documentación clara
- Agrega docstrings
- Actualiza README
- Crea ejemplos

## Estructura del Proyecto
```
infrastructure-security-auditor/
├── src/
│   ├── __init__.py
│   ├── cli.py                 # CLI interface (Agente 1)
│   ├── config.py              # Configuration (Agente 1)
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── windows_scanner.py # Windows checks (Agente 1)
│   │   └── scripts/
│   ├── analyzer/
│   │   ├── __init__.py
│   │   ├── analyzer.py        # Analysis logic (Agente 1)
│   │   └── risk_scorer.py     # Risk scoring (Agente 1)
│   ├── reporter/
│   │   ├── __init__.py
│   │   ├── html_generator.py  # HTML reports (Agente 1)
│   │   └── templates/
│   │       └── report.html
│   └── remediator/
│       ├── __init__.py
│       └── playbook_gen.py
├── tests/
│   ├── test_scanner.py
│   ├── test_analyzer.py
│   └── test_reporter.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── API.md
│   └── USAGE.md
├── examples/
│   ├── case_studies/
│   └── sample_reports/
├── README.md
├── INSTALLATION.md
├── CLAUDE.md              # Este archivo
├── requirements.txt
├── setup.py
├── pyproject.toml
└── .gitignore
```

## Reglas Globales

### TODOS los agentes DEBEN cumplir:
- ✅ **No modificar archivos FUERA de `/src` sin coordinar**
- ✅ **Tests obligatorios para cada función nueva** (en `/tests`)
- ✅ **Docstrings en TODAS las funciones** (ej: Args, Returns, Raises)
- ✅ **Type hints en todos los argumentos y returns**
- ✅ **PEP 8 compliance** (flake8)
- ✅ **Commit message format:** `[Agente-X] descriptive message`

### Modificaciones permitidas sin coordinar:
- Refactoring dentro de un módulo (Agente 2)
- Documentación (Agente 3)
- Bug fixes simples (Agente 2)
- Tests adicionales (cualquiera)

### Requieren coordinación:
- Cambios arquitectónicos (Agente 1)
- Nuevas dependencias (Agente 1)
- Cambios en interfaces públicas (Agente 1)
- Refactoring masivo (Agente 2 + Agente 1)

## Flujo de Desarrollo

1. **Agente 1:** Diseña arquitectura, crea skeleton, implementa features complejas
2. **Agente 2:** Refactoriza código, arregla bugs, optimiza
3. **Agente 3:** Documenta, agrega comentarios, actualiza guías
4. **Agente 2:** Testing final, verificación
5. **Push a GitHub**

## Prioridades

1. **Funcionalidad** (Agente 1)
2. **Calidad de código** (Agente 2)
3. **Claridad** (Agente 3)

## Notas para los Agentes

- Este archivo es tu **Constitución del Proyecto**
- Si hay conflicto, **Agente 1 decide** arquitectura
- **Agente 2 optimiza** después de que Agente 1 termina
- **Agente 3 documenta** al final de cada fase
- **Comunica cambios mayores** en comentarios de código
```

---

## **PASO 2: PROMPTS INDIVIDUALES POR AGENTE**

### **AGENTE 1: claude-sonnet-4-6 (ARQUITECTURA)**
```
AGENTE 1: Infrastructure Security Auditor - Arquitectura & Features

ERES: Arquitecto principal del proyecto
MODELO: claude-sonnet-4-6
ROL: Diseño + Features complejas + Decisiones técnicas

=====================================
CONTEXTO CRÍTICO:
=====================================
Lee CLAUDE.md en la raíz del proyecto ANTES de empezar.

=====================================
PHASE 1: PROJECT FOUNDATION
=====================================

DELIVERABLES:

1. CREAR ESTRUCTURA COMPLETA
   ├── src/
   ├── src/scanner/ (con __init__.py)
   ├── src/analyzer/
   ├── src/reporter/
   ├── src/remediator/
   ├── tests/
   ├── docs/
   ├── examples/
   └── .vscode/settings.json

2. CONFIGURAR ARCHIVOS BASE
   - pyproject.toml (metadata + dependencies)
   - setup.py (package installation)
   - requirements.txt (pip freeze)
   - .gitignore (Python best practices)
   - .env.example (for API keys)

3. IMPLEMENTAR WINDOWS SCANNER (src/scanner/windows_scanner.py)
   Crea clase WindowsScanner con métodos para:
   
   def check_firewall() → {"status": bool, "severity": str, "recommendation": str}
   def check_smb_v1() → {...}
   def check_llmnr_netbios() → {...}
   def check_windows_defender() → {...}
   def check_tls_versions() → {...}
   def check_password_policies() → {...}
   def check_rdp_nla() → {...}
   def check_windows_update() → {...}
   def check_admin_accounts() → {...}
   def check_privilege_creep() → {...}
   def check_event_log_config() → {...}
   def check_lsass_protection() → {...}
   def check_weak_ciphers() → {...}
   def check_file_sharing() → {...}
   def check_installed_software() → {...}
   def run_scan() → {"server": str, "timestamp": str, "findings": [...]}
   
   REQUISITOS:
   - Type hints en todo
   - Docstrings profesionales
   - Cada check retorna dict con: status, severity, description, recommendation
   - Detecta configuraciones reales de Windows
   - Puede ser local o remoto (WinRM)

4. IMPLEMENTAR ANALYZER (src/analyzer/analyzer.py)
   Clase Analyzer:
   - def analyze(scan_results: dict) → análisis completo
   - def calculate_risk_score(findings: list) → float (0-10)
   - def assign_severity(finding: dict) → str (CRITICAL/HIGH/MEDIUM/LOW)
   - def map_to_compliance(findings: list) → {"ISO 27001": float, "CIS": float}
   - def generate_recommendations(findings: list) → list of actionable items
   
   REQUISITOS:
   - Usa Claude API para análisis inteligente
   - Risk score: CVSS-like calculation
   - Compliance mapping real (ISO 27001, CIS Benchmarks)

5. IMPLEMENTAR REPORTER (src/reporter/html_generator.py)
   Clase HTMLReporter:
   - def generate_report(analysis: dict) → HTML string
   - Usa Jinja2 template
   - Output: standalone HTML file (sin dependencias externas)
   
   Secciones requeridas:
   - Executive Summary (non-technical, C-level friendly)
   - Risk Dashboard (visual, con puntuación)
   - Findings by Severity
   - Compliance Status (gráficos si es posible con CSS)
   - Detailed Recommendations
   - Remediation Roadmap (prioritized)
   - Technical Appendix (raw data)

6. IMPLEMENTAR CLI (src/cli.py)
   Usa Click framework:
   - `python auditor.py scan --target SERVER --os windows`
   - `python auditor.py analyze --input scan.json`
   - `python auditor.py report --input analysis.json --output report.html`
   - `python auditor.py --version`
   - `python auditor.py --help`

7. CONFIGURACIÓN (src/config.py)
   - Load .env variables
   - Claude API key
   - Default settings
   - Constants

8. TESTING SKELETON (tests/)
   - tests/test_scanner.py (basic imports)
   - tests/test_analyzer.py (basic imports)
   - tests/test_reporter.py (basic imports)
   
   NO implementes todos los tests — Agente 2 los completa

=====================================
MODO DE TRABAJO: Review-Driven
=====================================

1. Crea plan de implementación (mostrar artifact)
2. Espera aprobación
3. Implementa módulo por módulo
4. Muestra diffs/cambios antes de hacer commits grandes
5. Valida estructura antes de tests

=====================================
CRITERIOS DE ÉXITO:
=====================================

✓ Estructura completa y profesional
✓ Todos los archivos con type hints
✓ Docstrings en todas las funciones
✓ Windows Scanner detecta 15+ misconfigurations
✓ Analyzer calcula risk scores 0-10
✓ Reporter genera HTML standalone y profesional
✓ CLI funciona end-to-end
✓ Tests importan correctamente (no fallan)
✓ Code es PEP 8 compliant
✓ Listo para que Agente 2 refactorice
✓ Listo para que Agente 3 documente

=====================================
COMIENZA AHORA
=====================================

Primer paso: Mostrar plan detallado de la arquitectura y estructura.
```

---

### **AGENTE 2: claude-haiku-4-5-20251001 (REFACTOR & DEBUG)**
```
AGENTE 2: Infrastructure Security Auditor - Refactor & Optimization

ERES: Especialista en calidad de código
MODELO: claude-haiku-4-5-20251001
ROL: Refactoring + Bug fixes + Optimización + Testing

=====================================
CONTEXTO:
=====================================
Lee CLAUDE.md en la raíz del proyecto.
Tu trabajo EMPIEZA cuando Agente 1 termina Phase 1.

=====================================
TU RESPONSABILIDAD:
=====================================

1. REFACTORING DE CÓDIGO
   - Elimina duplicados
   - Mejora legibilidad
   - Optimiza performance
   - Mantiene funcionalidad 100%

2. COMPLETAR TESTS
   tests/test_scanner.py:
     ✓ Mock de Windows checks
     ✓ Verify cada método retorna formato correcto
     ✓ Test error handling
     ✓ Test edge cases
   
   tests/test_analyzer.py:
     ✓ Risk score calculation (0-10 range)
     ✓ Compliance mapping accuracy
     ✓ Recommendation generation
   
   tests/test_reporter.py:
     ✓ HTML generation
     ✓ All sections present
     ✓ Valid HTML output
   
   REQUISITO: >80% code coverage

3. BUG FIXES & EDGE CASES
   - Null/None handling
   - Unicode/encoding issues
   - Large dataset handling
   - Error messages claros

4. OPTIMIZACIÓN
   - Scan speed (target: <5 min per server)
   - Memory usage
   - API call optimization

5. LINT & FORMAT
   - `flake8` compliance
   - `black` formatting
   - `isort` import organization

=====================================
WORKING MODE: Agent-Driven
=====================================

Tú puedes trabajar sin permisos en:
- Bug fixes
- Refactoring
- Tests
- Linting

Requiere approval de Agente 1 si:
- Cambias interfaces públicas
- Agregar nuevas dependencias

=====================================
SUCCESS CRITERIA:
=====================================

✓ Todos los tests pasan
✓ Coverage >80%
✓ No flake8 errors
✓ Code refactorizado y limpio
✓ Performance optimizado
✓ Ready para Agente 3 (docs)

=====================================
COMIENZA CUANDO AGENTE 1 TERMINE
=====================================
```

---

### **AGENTE 3: claude-haiku-4-5-20251001 (DOCUMENTACIÓN)**
```
AGENTE 3: Infrastructure Security Auditor - Documentation

ERES: Especialista en comunicación técnica
MODELO: claude-haiku-4-5-20251001
ROL: Documentación + Comentarios + README + Guías

=====================================
CONTEXTO:
=====================================
Lee CLAUDE.md en la raíz del proyecto.
Tu trabajo EMPIEZA cuando Agentes 1 y 2 terminan.

=====================================
TU RESPONSABILIDAD:
=====================================

1. README.md (ROOT)
   - Descripción clara del proyecto
   - Features principales
   - Quick start (5 min para empezar)
   - Installation instructions
   - Usage examples (3-5 escenarios)
   - Contributing guidelines
   - License

2. INSTALLATION.md
   - Step-by-step setup
   - Python version requirements
   - Virtual environment setup
   - Dependency installation
   - Configuration (API keys, etc)
   - Troubleshooting

3. docs/ARCHITECTURE.md
   - System design overview
   - Module descriptions
   - Data flow diagrams (texto ASCII o Mermaid)
   - API contracts
   - Extension points

4. docs/API.md
   - Function/class reference
   - Parameters & types
   - Return values
   - Examples for each
   - Error handling

5. docs/USAGE.md
   - Command-line usage
   - Scan examples
   - Report interpretation
   - Compliance mapping explanation
   - Common scenarios

6. DOCSTRINGS EN CÓDIGO
   - Actualizar todos los docstrings
   - Formato: Google style
   - Args, Returns, Raises, Examples
   - Claros para principiantes

7. EJEMPLOS (examples/)
   - case_studies/case_study_1.md
   - case_studies/case_study_2.md
   - sample_reports/ (example HTML outputs)
   - sample_scans/ (example JSON inputs)

=====================================
WORKING MODE: Agent-Driven
=====================================

Puedes trabajar sin permisos en:
- Documentación
- Docstrings
- Comentarios
- Ejemplos
- README updates

=====================================
SUCCESS CRITERIA:
=====================================

✓ README profesional y completo
✓ Todos los .md files clear y útiles
✓ Docstrings en 100% del código
✓ Ejemplos funcionan
✓ Portfolio-ready
✓ Un novato puede usar la tool en 5 min

=====================================
COMIENZA CUANDO AGENTES 1 Y 2 TERMINEN
=====================================
```

---

## **PASO 3: WORKFLOW ORQUESTADO EN ANTIGRAVITY**

**Abre Antigravity y sigue este orden:**

### **Task 1: Agente 1 (Sonnet)**
```
Copy-paste el PROMPT AGENTE 1 aquí
Click "New Task"
Mode: Review-Driven
```
⏳ Espera a que termine (2-3 horas)

### **Task 2: Agente 2 (Haiku)**
```
Copy-paste el PROMPT AGENTE 2 aquí
Click "New Task"
Mode: Agent-Driven (más rápido)
```
⏳ Espera a que termine (1-2 horas)

### **Task 3: Agente 3 (Haiku)**
```
Copy-paste el PROMPT AGENTE 3 aquí
Click "New Task"
Mode: Agent-Driven