// Инициализация графика
const ctx = document.getElementById('trafficChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'PPS (пакетов/сек)',
            data: [],
            borderColor: '#0dcaf0',
            backgroundColor: 'rgba(13, 202, 240, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.3,
            pointRadius: 0
        }]
    },
    options: {
        responsive: true,
        animation: false,
        scales: {
            x: { display: false },
            y: { beginAtZero: true, grid: { color: '#343a40' } }
        },
        plugins: { legend: { display: false } }
    }
});

// Функция обновления данных
async function updateDashboard() {
    try {
        // 1. Обновляем статус и цифры
        const statusRes = await fetch('/api/status');
        const status = await statusRes.json();
        
        const icon = document.getElementById('status-icon');
        const text = document.getElementById('status-text');
        
        if (status.level === 'green') { icon.innerText = '🟢'; icon.className = 'status-indicator text-green'; text.innerText = 'Норма'; }
        else if (status.level === 'yellow') { icon.innerText = '🟡'; icon.className = 'status-indicator text-yellow'; text.innerText = 'Внимание'; }
        else { icon.innerText = '🔴'; icon.className = 'status-indicator text-red'; text.innerText = 'АТАКА'; }

        document.getElementById('val-pps').innerText = status.pps.toFixed(0);
        document.getElementById('val-uniq').innerText = status.unique_ips;

        // 2. Обновляем график
        const metricsRes = await fetch('/api/metrics');
        const metrics = await metricsRes.json();
        
        if (metrics.length > 0) {
            chart.data.labels = metrics.map(m => m.timestamp.split(' ')[1]);
            chart.data.datasets[0].data = metrics.map(m => m.total_pps);
            chart.update();

            // Выводим энтропию последней секунды
            const last = metrics[metrics.length - 1];
            document.getElementById('val-entropy').innerText = last.entropy ? last.entropy.toFixed(2) : '0.00';
        }

        // 3. Обновляем ленту алертов
        const alertsRes = await fetch('/api/alerts');
        const alerts = await alertsRes.json();
        const tbody = document.getElementById('alerts-body');
        
        if (alerts.length === 0) {
            tbody.innerHTML = '<tr><td class="text-muted text-center">Нет событий</td></tr>';
        } else {
            tbody.innerHTML = alerts.map(a => `
                <tr class="alert-row">
                    <td class="text-muted">${a.timestamp.split(' ')[1]}</td>
                    <td class="text-danger fw-bold">${a.alert_type}</td>
                    <td>${a.src_ip}</td>
                </tr>
            `).join('');
        }
    } catch (e) {
        console.error("Ошибка обновления:", e);
    }
}

// Запускаем каждые 2 секунды
setInterval(updateDashboard, 2000);
updateDashboard();