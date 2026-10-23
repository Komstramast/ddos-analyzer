const ctx = document.getElementById('trafficChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'PPS (пакетов/сек)',
            data: [],
            borderColor: '#3498db', /* Яркий синий */
            backgroundColor: 'rgba(52, 152, 219, 0.2)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 2,
            pointHoverRadius: 6
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false, // <--- ДОБАВИТЬ ЭТУ СТРОКУ
        animation: false,
        interaction: { mode: 'index', intersect: false },
        scales: {
            x: { 
                display: false 
            },
            y: { 
                beginAtZero: true, 
                grid: { color: '#333' },
                ticks: { color: '#9e9e9e' }
            }
        },
        plugins: { 
            legend: { display: false },
            tooltip: {
                backgroundColor: '#1e1e1e',
                titleColor: '#fff',
                bodyColor: '#fff',
                borderColor: '#333',
                borderWidth: 1
            }
        }
    }
});

async function updateDashboard() {
    try {
        // 1. Статус
        const statusRes = await fetch('/api/status');
        const status = await statusRes.json();
        
        const icon = document.getElementById('status-icon');
        const text = document.getElementById('status-text');
        
        if (status.level === 'green') { 
            icon.innerText = '🟢'; icon.className = 'status-indicator text-green'; text.innerText = 'Норма'; 
        } else if (status.level === 'yellow') { 
            icon.innerText = '🟡'; icon.className = 'status-indicator text-yellow'; text.innerText = 'Внимание'; 
        } else { 
            icon.innerText = '🔴'; icon.className = 'status-indicator text-red'; text.innerText = 'АТАКА'; 
        }

        document.getElementById('val-pps').innerText = status.pps.toFixed(0);
        document.getElementById('val-uniq').innerText = status.unique_ips;

        // 2. График
        const metricsRes = await fetch('/api/metrics');
        const metrics = await metricsRes.json();
        
        if (metrics.length > 0) {
            chart.data.labels = metrics.map(m => m.timestamp.split(' ')[1]);
            chart.data.datasets[0].data = metrics.map(m => m.total_pps);
            chart.update();

            const last = metrics[metrics.length - 1];
            document.getElementById('val-entropy').innerText = last.entropy ? last.entropy.toFixed(2) : '0.00';
        }

        // 3. Алерты
        const alertsRes = await fetch('/api/alerts');
        const alerts = await alertsRes.json();
        const tbody = document.getElementById('alerts-body');
        
        if (alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="text-muted text-center py-3">Нет событий</td></tr>';
        } else {
            tbody.innerHTML = alerts.map(a => `
                <tr class="alert-row">
                    <td class="text-light text-opacity-75" style="font-size: 0.8rem;">${a.timestamp.split(' ')[1]}</td>
                    <td class="fw-bold" style="color: #e74c3c; font-size: 0.85rem;">${a.alert_type}</td>
                    <td class="text-light" style="font-size: 0.85rem;">${a.src_ip}</td>
                </tr>
            `).join('');
        }
    } catch (e) {
        console.error("Ошибка обновления:", e);
    }
}

// Запускаем чаще, чтобы график был живее (раз в секунду)
setInterval(updateDashboard, 1000);
updateDashboard();