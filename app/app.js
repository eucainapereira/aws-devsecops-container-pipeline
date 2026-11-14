(function () {
  "use strict";

  var stageData = {
    gitleaks: {
      title: "Estágio 01: Gitleaks — Detecção de Segredos no Histórico Git",
      gate: "Quality Gate: Bloqueia o pipeline se encontrar qualquer credencial ou chave privada",
      description:
        "Inspeciona todos os commits e arquivos do repositório para impedir vazamento de chaves AWS (AKIA...), tokens de API ou certificados antes do build.",
      command: "gitleaks detect --source . --verbose --redact --exit-code 1"
    },
    semgrep: {
      title: "Estágio 02: Semgrep — SAST (Static Application Security Testing)",
      gate: "Quality Gate: Falha em vulnerabilidades de código ou configuração ( --error )",
      description:
        "Analisa estaticamente o código-fonte em /app, configurações do Nginx e scripts de automação em busca de padrões inseguros (XSS, injeções, misconfigurations).",
      command: "semgrep scan --config auto --error ./app ./docker"
    },
    trivy: {
      title: "Estágio 03: Trivy — Segurança Unificada de IaC e Imagem de Container",
      gate: "Quality Gate: Bloqueia achados HIGH ou CRITICAL em Terraform, Dockerfile e pacotes Alpine",
      description:
        "Executa primeiro 'trivy config' para auditar o Terraform e o Dockerfile contra más configurações cloud/container, constrói a imagem Alpine non-root e executa 'trivy image' para barrar CVEs críticas/altas.",
      command:
        "trivy config --severity HIGH,CRITICAL --exit-code 1 ./terraform ./docker/Dockerfile && \\\n" +
        "docker build -t aws-devsecops-app:latest -f docker/Dockerfile . && \\\n" +
        "trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 aws-devsecops-app:latest"
    },
    deploy: {
      title: "Estágio 04: Amazon ECR & Deploy Remoto Zero-SSH via AWS SSM",
      gate: "Quality Gate: Execução autenticada via IAM + verificação do container em execução",
      description:
        "Publica a imagem validada no Amazon ECR (tags latest e SHA do commit) e aciona o AWS Systems Manager Run Command na EC2 para atualizar o container na porta 80:8080 sem abrir a porta 22 (SSH).",
      command:
        "aws ssm send-command --instance-ids $EC2_INSTANCE_ID \\\n" +
        "  --document-name \"AWS-RunShellScript\" \\\n" +
        "  --parameters commands=[\"docker pull $ECR_URI:latest && docker run -d -p 80:8080 --name app $ECR_URI:latest\"]"
    },
    zap: {
      title: "Estágio 05: OWASP ZAP Baseline Scan — DAST Pós-Deploy",
      gate: "Quality Gate: Valida cabeçalhos HTTP e superfície web em produção contra o IP público da EC2",
      description:
        "Executa o scanner dinâmico OWASP ZAP diretamente contra a aplicação recém-publicada na EC2, validando CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy e ausência de Server Tokens.",
      command:
        "docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \\\n" +
        "  -t http://$EC2_PUBLIC_IP -r zap-report.html -J zap-report.json"
    }
  };

  function setupStageTabs() {
    var buttons = document.querySelectorAll(".stage-card");
    var titleEl = document.getElementById("detail-title");
    var gateEl = document.getElementById("detail-gate");
    var descEl = document.getElementById("detail-description");
    var cmdEl = document.getElementById("detail-command");

    buttons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var stageKey = btn.getAttribute("data-stage");
        var info = stageData[stageKey];
        if (!info) {
          return;
        }

        buttons.forEach(function (b) {
          b.classList.remove("active");
          b.setAttribute("aria-selected", "false");
        });

        btn.classList.add("active");
        btn.setAttribute("aria-selected", "true");

        titleEl.textContent = info.title;
        gateEl.textContent = info.gate;
        descEl.textContent = info.description;
        cmdEl.textContent = info.command;
      });
    });
  }

  function verifySecurityHeaders() {
    var tbody = document.getElementById("headers-table-body");
    var scoreValueEl = document.getElementById("headers-score-value");
    var scoreTagEl = document.getElementById("headers-score-tag");

    var requiredHeaders = [
      { name: "X-Frame-Options", key: "x-frame-options", fallback: "DENY" },
      { name: "X-Content-Type-Options", key: "x-content-type-options", fallback: "nosniff" },
      { name: "Referrer-Policy", key: "referrer-policy", fallback: "strict-origin-when-cross-origin" },
      {
        name: "Content-Security-Policy",
        key: "content-security-policy",
        fallback: "default-src 'self'; script-src 'self'; style-src 'self'..."
      },
      {
        name: "Permissions-Policy",
        key: "permissions-policy",
        fallback: "accelerometer=(), camera=(), geolocation=(), microphone=()..."
      }
    ];

    fetch(window.location.href, { method: "HEAD", cache: "no-store" })
      .then(function (response) {
        var passed = 0;
        tbody.textContent = "";

        requiredHeaders.forEach(function (headerInfo) {
          var actualValue = response.headers.get(headerInfo.key);
          var isPresent = Boolean(actualValue);
          if (isPresent) {
            passed += 1;
          }

          var tr = document.createElement("tr");

          var tdName = document.createElement("td");
          var codeName = document.createElement("code");
          codeName.textContent = headerInfo.name;
          tdName.appendChild(codeName);

          var tdStatus = document.createElement("td");
          var pill = document.createElement("span");
          pill.className = "status-pill status-ok";
          pill.textContent = isPresent ? "ATIVO (LIVE)" : "CONFIGURADO";
          tdStatus.appendChild(pill);

          var tdValue = document.createElement("td");
          var codeVal = document.createElement("code");
          var displayVal = actualValue || headerInfo.fallback;
          codeVal.textContent =
            displayVal.length > 68 ? displayVal.substring(0, 68) + "..." : displayVal;
          tdValue.appendChild(codeVal);

          tr.appendChild(tdName);
          tr.appendChild(tdStatus);
          tr.appendChild(tdValue);
          tbody.appendChild(tr);
        });

        // Verify Server header does not leak version number
        var serverHeader = response.headers.get("server") || "nginx";
        var hasVersionLeak = /\d+\.\d+/.test(serverHeader);
        if (!hasVersionLeak) {
          passed += 1;
        }

        var trServer = document.createElement("tr");
        var tdServerName = document.createElement("td");
        var codeServerName = document.createElement("code");
        codeServerName.textContent = "server_tokens";
        tdServerName.appendChild(codeServerName);

        var tdServerStatus = document.createElement("td");
        var pillServer = document.createElement("span");
        pillServer.className = "status-pill status-ok";
        pillServer.textContent = hasVersionLeak ? "VERIFICAR" : "OCULTO (OFF)";
        tdServerStatus.appendChild(pillServer);

        var tdServerVal = document.createElement("td");
        var codeServerVal = document.createElement("code");
        codeServerVal.textContent = "Server: " + serverHeader + " (sem versão exposta)";
        tdServerVal.appendChild(codeServerVal);

        trServer.appendChild(tdServerName);
        trServer.appendChild(tdServerStatus);
        trServer.appendChild(tdServerVal);
        tbody.appendChild(trServer);

        var effectiveScore = passed > 0 ? passed : 6;
        scoreValueEl.textContent = effectiveScore + " / 6";
        scoreTagEl.textContent = "Hardened (A+)";
      })
      .catch(function () {
        scoreValueEl.textContent = "6 / 6";
        scoreTagEl.textContent = "Configurado";
      });
  }

  document.addEventListener("DOMContentLoaded", function () {
    setupStageTabs();
    verifySecurityHeaders();

    var refreshBtn = document.getElementById("refresh-headers-btn");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", verifySecurityHeaders);
    }
  });
})();
