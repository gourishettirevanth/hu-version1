function toggleMenu() {
  document.getElementById('sidebar').classList.toggle('active');
  document.getElementById('mainContent').classList.toggle('shift');
}

function showSection(id) {
  document.querySelectorAll('.table-section').forEach(section => {
    section.classList.remove('active');
  });
  document.getElementById(id).classList.add('active');
}

function initializeWebSocket() {
  const socket = new WebSocket('ws://localhost:6790');

  socket.onopen = () => {
    console.log('WebSocket connected');
  };

  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    updateTables(data);
    renderCharts(data);
  };

  socket.onerror = (error) => {
    console.error('WebSocket error:', error);
  };

  socket.onclose = () => {
    console.log('WebSocket closed');
  };
}

function updateTables(data) {
  const fillTable = (id, rows, columns) => {
    const tbody = document.querySelector(`#${id} tbody`);
	    if (id !== "networkPacketsTable") {
    tbody.innerHTML = ""; // Clear only for other tables
  }


    rows.forEach(row => {
      const tr = document.createElement('tr');
      columns.forEach(col => {
        const td = document.createElement('td');
        td.textContent = row[col];
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  };

  fillTable("cpuUtilizationTable", data.cpuUtilization, ["timestamp", "pid", "comm", "cpu_time"]);
  fillTable("cpuAlarmsTable", data.cpuAlarms, ["pid", "comm", "cpu", "threshold", "triggeredAt"]);
  fillTable("networkPacketsTable", data.networkPackets, ["timestamp","pid","comm","event_type","saddr","daddr","dport","protocol"]);
}

function renderCharts(data) {
  if (window.charts) window.charts.forEach(c => c.destroy());
  window.charts = [];

  const createChart = (id, labels, label, dataPoints, color) => {
    const ctx = document.getElementById(id).getContext('2d');
    const chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels.slice(0, 20),
        datasets: [{
          label: label,
          data: dataPoints.slice(0, 20),
          borderColor: color,
          backgroundColor: color + '33',
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: 'top' } },
        scales: {
          x: { title: { display: true, text: 'Timestamp' } },
          y: { beginAtZero: true }
        }
      }
    });
    window.charts.push(chart);
  };

  const cpuLabels = data.cpuUtilization.map(row => row.timestamp);
  const cpuData = data.cpuUtilization.map(row => row.cpu_time);
  createChart("cpuUtilizationChart", cpuLabels, "CPU Time", cpuData, "#007bff");

  const alarmLabels = data.cpuAlarms.map(row => row.triggeredAt);
  const alarmData = data.cpuAlarms.map(row => row.cpu);
  createChart("cpuAlarmsChart", alarmLabels, "High CPU Processes", alarmData, "#dc3545");

  const networkLabels = data.networkPackets.map(row => row.timestamp);
  const packetData = data.networkPackets.map(row => row.pid);
  createChart("networkPacketsChart", networkLabels, "pid", packetData, "#17a2b8");
}

// Init
initializeWebSocket();
