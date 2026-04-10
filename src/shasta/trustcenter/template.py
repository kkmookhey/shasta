"""Trust center HTML template.

A single self-contained Jinja2 template that renders to a deployable
index.html. Uses Tailwind CDN for styling and Chart.js CDN for doughnut
rings. No local assets, no build step, opens in any browser.

Engineering Principle #11: this is pure Jinja2. Zero LLM calls.
Engineering Principle #1: every number comes from the context dict.
"""

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ config.company_name }} — Security & Compliance</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
  <style>
    :root {
      --primary: {{ config.primary_color }};
      --accent: {{ config.accent_color }};
      --pass: #10b981;
      --fail: #ef4444;
      --partial: #f59e0b;
      --not-assessed: #9ca3af;
    }
    body { font-family: 'Inter', system-ui, -apple-system, sans-serif; }
    .grade-badge {
      display: inline-flex; align-items: center; justify-content: center;
      width: 3rem; height: 3rem; border-radius: 9999px;
      font-size: 1.25rem; font-weight: 700; color: white;
    }
    .grade-A, .grade-B { background-color: var(--pass); }
    .grade-C { background-color: var(--partial); }
    .grade-D, .grade-F { background-color: var(--fail); }
    .grade-NA { background-color: var(--not-assessed); }
    .status-pass { color: var(--pass); }
    .status-fail { color: var(--fail); }
    .status-partial { color: var(--partial); }
    .chart-container { width: 100px; height: 100px; }
  </style>
</head>
<body class="bg-gray-50 text-gray-900">

  <!-- Header -->
  <header class="bg-white border-b border-gray-200">
    <div class="max-w-5xl mx-auto px-6 py-8">
      <div class="flex items-center gap-4">
        {% if config.logo_url %}
        <img src="{{ config.logo_url }}" alt="{{ config.company_name }}" class="h-12">
        {% endif %}
        <div>
          <h1 class="text-3xl font-bold text-gray-900">{{ config.company_name }}</h1>
          <p class="text-gray-500 mt-1">{{ config.company_tagline }}</p>
        </div>
      </div>
      <div class="mt-4 flex items-center gap-2 text-sm text-gray-400">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
        </svg>
        <span>Security & Compliance Trust Center</span>
      </div>
    </div>
  </header>

  <main class="max-w-5xl mx-auto px-6 py-10 space-y-10">

    <!-- Compliance Framework Badges -->
    {% if config.show_soc2 or config.show_iso27001 or config.show_hipaa %}
    <section>
      <h2 class="text-xl font-semibold mb-6">Compliance Frameworks</h2>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">

        {% if config.show_soc2 %}
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h3 class="font-semibold text-lg">SOC 2 Type II</h3>
              <p class="text-sm text-gray-500">Trust Services Criteria</p>
            </div>
            {% if has_scan_data and soc2_score %}
            <span class="grade-badge grade-{{ soc2_score.grade }}">{{ soc2_score.grade }}</span>
            {% else %}
            <span class="grade-badge grade-NA">—</span>
            {% endif %}
          </div>
          {% if has_scan_data and soc2_score %}
          <div class="text-3xl font-bold" style="color: var(--primary)">{{ "%.0f"|format(soc2_score.score_percentage) }}%</div>
          <p class="text-sm text-gray-500 mt-1">{{ soc2_score.passing }} of {{ soc2_score.total_controls }} controls passing</p>
          <div class="mt-3 w-full bg-gray-200 rounded-full h-2">
            <div class="h-2 rounded-full" style="width: {{ soc2_score.score_percentage }}%; background: var(--primary)"></div>
          </div>
          {% else %}
          <p class="text-sm text-gray-400 italic">Not yet scanned</p>
          {% endif %}
        </div>
        {% endif %}

        {% if config.show_iso27001 %}
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h3 class="font-semibold text-lg">ISO 27001:2022</h3>
              <p class="text-sm text-gray-500">Annex A Controls</p>
            </div>
            {% if has_scan_data and iso_score %}
            <span class="grade-badge grade-{{ iso_score.grade }}">{{ iso_score.grade }}</span>
            {% else %}
            <span class="grade-badge grade-NA">—</span>
            {% endif %}
          </div>
          {% if has_scan_data and iso_score %}
          <div class="text-3xl font-bold" style="color: var(--primary)">{{ "%.0f"|format(iso_score.score_percentage) }}%</div>
          <p class="text-sm text-gray-500 mt-1">{{ iso_score.passing }} of {{ iso_score.total_controls }} controls passing</p>
          <div class="mt-3 w-full bg-gray-200 rounded-full h-2">
            <div class="h-2 rounded-full" style="width: {{ iso_score.score_percentage }}%; background: var(--primary)"></div>
          </div>
          {% else %}
          <p class="text-sm text-gray-400 italic">Not yet scanned</p>
          {% endif %}
        </div>
        {% endif %}

        {% if config.show_hipaa %}
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h3 class="font-semibold text-lg">HIPAA</h3>
              <p class="text-sm text-gray-500">Security Rule</p>
            </div>
            {% if has_scan_data and hipaa_score %}
            <span class="grade-badge grade-{{ hipaa_score.grade }}">{{ hipaa_score.grade }}</span>
            {% else %}
            <span class="grade-badge grade-NA">—</span>
            {% endif %}
          </div>
          {% if has_scan_data and hipaa_score %}
          <div class="text-3xl font-bold" style="color: var(--primary)">{{ "%.0f"|format(hipaa_score.score_percentage) }}%</div>
          <p class="text-sm text-gray-500 mt-1">{{ hipaa_score.passing }} of {{ hipaa_score.total_controls }} controls passing</p>
          <div class="mt-3 w-full bg-gray-200 rounded-full h-2">
            <div class="h-2 rounded-full" style="width: {{ hipaa_score.score_percentage }}%; background: var(--primary)"></div>
          </div>
          {% else %}
          <p class="text-sm text-gray-400 italic">Not yet scanned</p>
          {% endif %}
        </div>
        {% endif %}

      </div>
    </section>
    {% endif %}

    <!-- Security Controls Summary -->
    {% if config.show_controls_summary and has_scan_data and domain_breakdown %}
    <section>
      <h2 class="text-xl font-semibold mb-6">Security Controls by Domain</h2>
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <div class="space-y-4">
          {% for domain, counts in domain_breakdown.items() %}
          {% set total = counts.get('pass', 0) + counts.get('fail', 0) + counts.get('partial', 0) %}
          {% if total > 0 %}
          {% set pct = (counts.get('pass', 0) / total * 100) | round | int %}
          <div>
            <div class="flex justify-between text-sm mb-1">
              <span class="font-medium capitalize">{{ domain }}</span>
              <span class="text-gray-500">{{ counts.get('pass', 0) }}/{{ total }} passing ({{ pct }}%)</span>
            </div>
            <div class="w-full bg-gray-200 rounded-full h-3 flex overflow-hidden">
              <div class="h-3" style="width: {{ (counts.get('pass', 0) / total * 100) }}%; background: var(--pass)"></div>
              <div class="h-3" style="width: {{ (counts.get('partial', 0) / total * 100) }}%; background: var(--partial)"></div>
              <div class="h-3" style="width: {{ (counts.get('fail', 0) / total * 100) }}%; background: var(--fail)"></div>
            </div>
          </div>
          {% endif %}
          {% endfor %}
        </div>
      </div>
    </section>
    {% endif %}

    <!-- Policies In Place -->
    {% if config.show_policies and policies %}
    <section>
      <h2 class="text-xl font-semibold mb-6">Security Policies</h2>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        {% for policy in policies %}
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5 flex items-center justify-between">
          <div>
            <h3 class="font-medium">{{ policy.title }}</h3>
            <div class="flex gap-1 mt-1">
              {% for ctrl in policy.get('soc2_controls', [])[:4] %}
              <span class="inline-block bg-indigo-50 text-indigo-700 text-xs px-2 py-0.5 rounded">{{ ctrl }}</span>
              {% endfor %}
            </div>
          </div>
          <span class="inline-flex items-center gap-1 text-sm font-medium px-3 py-1 rounded-full bg-green-50 text-green-700">
            <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
            </svg>
            In Place
          </span>
        </div>
        {% endfor %}
      </div>
    </section>
    {% endif %}

    <!-- Data Protection -->
    {% if config.show_data_protection %}
    <section>
      <h2 class="text-xl font-semibold mb-6">Data Protection</h2>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">

        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5 text-center">
          <div class="text-3xl mb-2">&#128274;</div>
          <h3 class="font-medium">Encryption at Rest</h3>
          <p class="text-sm text-gray-500 mt-1">AES-256 / KMS encryption on all storage, databases, and backups</p>
          {% if has_scan_data and encryption_pass_rate is not none %}
          <div class="mt-2 text-sm font-semibold status-{{ 'pass' if encryption_pass_rate >= 80 else ('partial' if encryption_pass_rate >= 50 else 'fail') }}">
            {{ encryption_pass_rate }}% of checks passing
          </div>
          {% endif %}
        </div>

        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5 text-center">
          <div class="text-3xl mb-2">&#128225;</div>
          <h3 class="font-medium">Encryption in Transit</h3>
          <p class="text-sm text-gray-500 mt-1">TLS 1.2+ enforced on all endpoints, APIs, and inter-service traffic</p>
        </div>

        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5 text-center">
          <div class="text-3xl mb-2">&#128100;</div>
          <h3 class="font-medium">Access Controls</h3>
          <p class="text-sm text-gray-500 mt-1">RBAC, MFA enforced, least-privilege IAM, regular access reviews</p>
          {% if has_scan_data and iam_pass_rate is not none %}
          <div class="mt-2 text-sm font-semibold status-{{ 'pass' if iam_pass_rate >= 80 else ('partial' if iam_pass_rate >= 50 else 'fail') }}">
            {{ iam_pass_rate }}% of checks passing
          </div>
          {% endif %}
        </div>

        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5 text-center">
          <div class="text-3xl mb-2">&#128065;</div>
          <h3 class="font-medium">Monitoring</h3>
          <p class="text-sm text-gray-500 mt-1">CloudTrail, GuardDuty, Security Hub, continuous compliance scanning</p>
          {% if has_scan_data and monitoring_pass_rate is not none %}
          <div class="mt-2 text-sm font-semibold status-{{ 'pass' if monitoring_pass_rate >= 80 else ('partial' if monitoring_pass_rate >= 50 else 'fail') }}">
            {{ monitoring_pass_rate }}% of checks passing
          </div>
          {% endif %}
        </div>

      </div>
    </section>
    {% endif %}

    <!-- Infrastructure Overview -->
    {% if config.show_infrastructure and has_scan_data %}
    <section>
      <h2 class="text-xl font-semibold mb-6">Infrastructure</h2>
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
          <div>
            <p class="text-sm text-gray-500">Cloud Providers</p>
            <p class="text-lg font-semibold mt-1">
              {% for cp in cloud_providers %}
              <span class="inline-block bg-gray-100 text-gray-700 text-sm px-3 py-1 rounded-full">{{ cp }}</span>
              {% endfor %}
            </p>
          </div>
          <div>
            <p class="text-sm text-gray-500">Domains Scanned</p>
            <p class="text-lg font-semibold mt-1">{{ domains_scanned | length }}</p>
          </div>
          <div>
            <p class="text-sm text-gray-500">Last Scan</p>
            <p class="text-lg font-semibold mt-1">{{ scan_date or "—" }}</p>
          </div>
          <div>
            <p class="text-sm text-gray-500">Account</p>
            <p class="text-lg font-semibold mt-1">****{{ account_id_suffix }}</p>
          </div>
        </div>
      </div>
    </section>
    {% endif %}

    <!-- Subprocessors -->
    {% if config.show_subprocessors %}
    <section>
      <h2 class="text-xl font-semibold mb-6">Subprocessors</h2>
      {% if config.subprocessors %}
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 text-gray-500 text-left">
            <tr>
              <th class="px-6 py-3 font-medium">Service</th>
              <th class="px-6 py-3 font-medium">Purpose</th>
              <th class="px-6 py-3 font-medium">Location</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            {% for sp in config.subprocessors %}
            <tr>
              <td class="px-6 py-3 font-medium">{{ sp.name }}</td>
              <td class="px-6 py-3 text-gray-600">{{ sp.purpose }}</td>
              <td class="px-6 py-3 text-gray-600">{{ sp.location }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6 text-center text-gray-400">
        <p>Contact us for our complete subprocessor list.</p>
      </div>
      {% endif %}
    </section>
    {% endif %}

  </main>

  <!-- Footer -->
  <footer class="bg-white border-t border-gray-200 mt-10">
    <div class="max-w-5xl mx-auto px-6 py-8">
      <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          {% if config.contact_email %}
          <p class="text-sm text-gray-500">Security inquiries: <a href="mailto:{{ config.contact_email }}" class="text-indigo-600 hover:underline">{{ config.contact_email }}</a></p>
          {% endif %}
          {% if config.dpo_email %}
          <p class="text-sm text-gray-500">Data Protection Officer: <a href="mailto:{{ config.dpo_email }}" class="text-indigo-600 hover:underline">{{ config.dpo_email }}</a></p>
          {% endif %}
          {% if config.privacy_url %}
          <p class="text-sm text-gray-500"><a href="{{ config.privacy_url }}" class="text-indigo-600 hover:underline">Privacy Policy</a></p>
          {% endif %}
        </div>
        <div class="text-right">
          <p class="text-xs text-gray-400">Last updated: {{ generated_at }}</p>
          <p class="text-xs text-gray-400 mt-1">Generated by <a href="https://github.com/transilienceai/shasta" class="text-indigo-500 hover:underline">Shasta Compliance Platform</a></p>
        </div>
      </div>
    </div>
  </footer>

</body>
</html>
"""
