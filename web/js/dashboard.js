Chart.register(ChartDataLabels);

// 🎨 Deterministic color generator (based on label index)
function generateColors(labels) {
  return labels.map((_, i) => `hsl(${(i * 67) % 360}, 65%, 60%)`);
}

fetch("data/findings.json")
  .then(res => res.json())
  .then(data => {
    const libraryFindings = data.filter(f => f.category === "library");
    const artefacts = data.filter(f => f.category !== "library");

    const libCounts = {};
    libraryFindings.forEach(f => {
      const key = `${f.keyword} ${f.version ?? ""}`.trim();
      libCounts[key] = (libCounts[key] || 0) + 1;
    });

    const libLabels = Object.keys(libCounts);
    const libData = Object.values(libCounts);
    const libColors = generateColors(libLabels); // 🔁 used in both bar + pie

    new Chart(document.getElementById("libraryChartBar"), {
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

    new Chart(document.getElementById("libraryChartPie"), {
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
            formatter: val => val // ✅ numbers only
          }
        }
      }
    });

    const fileTypeCounts = {};
    libraryFindings.forEach(f => {
      const ext = f.file.split('.').pop().toLowerCase();
      fileTypeCounts[ext] = (fileTypeCounts[ext] || 0) + 1;
    });

    const typeLabels = Object.keys(fileTypeCounts);
    const typeData = Object.values(fileTypeCounts);
    const typeColors = generateColors(typeLabels); // 🔁 reused

    new Chart(document.getElementById("fileTypeChartBar"), {
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

    new Chart(document.getElementById("fileTypeChartPie"), {
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
