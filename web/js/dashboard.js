Chart.register(ChartDataLabels);

// 🎨 Deterministic color generator
function generateColors(labels) {
  return labels.map((_, i) => `hsl(${(i * 67) % 360}, 65%, 60%)`);
}

// 🖱️ Chart click handler
function setupClickHandler(chart, labels) {
  chart.canvas.ondblclick = function (evt) {
    const point = chart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, true)[0];
    if (point) {
      const label = labels[point.index];
      const filter = encodeURIComponent(label.split(" ")[0]);
      window.open(`details.html?filter=${filter}`, "_blank");
    }
  };
}

fetch("data/findings.json")
  .then(res => res.json())
  .then(data => {
    const libraryFindings = data.filter(f => f.category === "library");
    const secretFindings = data.filter(f => f.category === "secret");
    const artefacts = data.filter(f => f.category !== "library" && f.category !== "secret");
    
    // Update summary
    const summaryText = document.getElementById("summaryText");
    summaryText.innerHTML = `
      📚 <strong>${libraryFindings.length}</strong> crypto library usages found<br>
      🚨 <strong>${secretFindings.length}</strong> potential hardcoded secrets found<br>
      🔎 <strong>${artefacts.length}</strong> other crypto artifacts found<br>
      📁 Total files scanned: <strong>${new Set(data.map(f => f.file)).size}</strong>
    `;

    const libCounts = {};
    libraryFindings.forEach(f => {
      const key = `${f.keyword} ${f.version ?? ""}`.trim();
      libCounts[key] = (libCounts[key] || 0) + 1;
    });

    const libLabels = Object.keys(libCounts);
    const libData = Object.values(libCounts);
    const libColors = generateColors(libLabels);

    const libBarChart = new Chart(document.getElementById("libraryChartBar"), {
      type: "bar",
      data: {
        labels: libLabels,
        datasets: [{
          label: "Library Usage",
          data: libData,
          backgroundColor: libColors
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'bottom' },
          datalabels: {
            anchor: 'end',
            align: 'top',
            formatter: Math.round
          }
        },
        scales: {
          x: {
            ticks: { autoSkip: false, maxRotation: 90, minRotation: 45 },
            title: { display: true, text: "Library" }
          },
          y: {
            beginAtZero: true,
            title: { display: true, text: "Occurrences" }
          }
        }
      }
    });
    setupClickHandler(libBarChart, libLabels);

    const libPieChart = new Chart(document.getElementById("libraryChartPie"), {
      type: "pie",
      data: {
        labels: libLabels,
        datasets: [{
          data: libData,
          backgroundColor: libColors
        }]
      },
      options: {
        plugins: {
          legend: { position: 'bottom' },
          datalabels: {
            color: "#000",
            formatter: val => val
          }
        }
      }
    });
    setupClickHandler(libPieChart, libLabels);

    const fileTypeCounts = {};
    libraryFindings.forEach(f => {
      const ext = f.file.split('.').pop().toLowerCase();
      fileTypeCounts[ext] = (fileTypeCounts[ext] || 0) + 1;
    });

    const typeLabels = Object.keys(fileTypeCounts);
    const typeData = Object.values(fileTypeCounts);
    const typeColors = generateColors(typeLabels);

    const typeBarChart = new Chart(document.getElementById("fileTypeChartBar"), {
      type: "bar",
      data: {
        labels: typeLabels,
        datasets: [{
          label: "File Types",
          data: typeData,
          backgroundColor: typeColors
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'bottom' },
          datalabels: {
            anchor: 'end',
            align: 'top',
            formatter: Math.round
          }
        },
        scales: {
          x: {
            title: { display: true, text: "File Type" }
          },
          y: {
            beginAtZero: true,
            title: { display: true, text: "Occurrences" }
          }
        }
      }
    });
    setupClickHandler(typeBarChart, typeLabels);

    const typePieChart = new Chart(document.getElementById("fileTypeChartPie"), {
      type: "pie",
      data: {
        labels: typeLabels,
        datasets: [{
          data: typeData,
          backgroundColor: typeColors
        }]
      },
      options: {
        plugins: {
          legend: { position: 'bottom' },
          datalabels: {
            color: "#000",
            formatter: val => val
          }
        }
      }
    });
    setupClickHandler(typePieChart, typeLabels);

    // Secrets charts
    const secretCounts = {};
    secretFindings.forEach(f => {
      secretCounts[f.keyword] = (secretCounts[f.keyword] || 0) + 1;
    });

    const secretLabels = Object.keys(secretCounts);
    const secretData = Object.values(secretCounts);
    const secretColors = secretLabels.map((_, i) => `hsl(${(i * 67) % 360}, 70%, 55%)`);

    if (secretLabels.length > 0) {
      const secretBarChart = new Chart(document.getElementById("secretsChartBar"), {
        type: "bar",
        data: {
          labels: secretLabels,
          datasets: [{
            label: "Secret Types",
            data: secretData,
            backgroundColor: secretColors
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { position: 'bottom' },
            datalabels: {
              anchor: 'end',
              align: 'top',
              formatter: Math.round
            }
          },
          scales: {
            x: {
              ticks: { autoSkip: false, maxRotation: 90, minRotation: 45 },
              title: { display: true, text: "Secret Type" }
            },
            y: {
              beginAtZero: true,
              title: { display: true, text: "Count" }
            }
          }
        }
      });
      setupClickHandler(secretBarChart, secretLabels);

      const secretPieChart = new Chart(document.getElementById("secretsChartPie"), {
        type: "pie",
        data: {
          labels: secretLabels,
          datasets: [{
            data: secretData,
            backgroundColor: secretColors
          }]
        },
        options: {
          plugins: {
            legend: { position: 'bottom' },
            datalabels: {
              color: "#fff",
              formatter: val => val
            }
          }
        }
      });
      setupClickHandler(secretPieChart, secretLabels);
    } else {
      // Show "No secrets found" message
      document.getElementById("secretsChartBar").parentElement.innerHTML = "<p style='text-align: center; padding: 2rem;'>✅ No hardcoded secrets detected!</p>";
      document.getElementById("secretsChartPie").parentElement.innerHTML = "<p style='text-align: center; padding: 2rem;'>🔒 Great security posture!</p>";
    }

    const tbody = document.getElementById("artefactBody");
    artefacts.forEach(f => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${f.category}</td>
        <td>${f.keyword}</td>
        <td>${f.context}</td>
        <td>${f.file}</td>
        <td>${f.line_number}</td>
      `;
      tbody.appendChild(row);
    });
  })
  .catch(err => {
    console.error("❌ Failed to load findings.json", err);
  });
