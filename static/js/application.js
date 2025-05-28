$(document).ready(function(){
    console.log('Document ready, initializing socket connection...');

    // Define a mapping for classification integers to string labels and styles
    const classificationMap = {
        0: { label: 'Benign', class: 'badge-benign', icon: 'fa-check-circle' },
        1: { label: 'Malicious', class: 'badge-malicious', icon: 'fa-exclamation-triangle' }
    };

    // Initialize counters
    let totalFlows = 0;
    let benignFlows = 0;
    let maliciousFlows = 0;

    //connect to the socket server.
    var socket = io.connect(window.location.protocol + '//' + window.location.host + '/test', {
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: 5
    });

    var messages_received = [];
    var ipTraffic = {};

    // Initialize chart
    var ctx = document.getElementById("trafficChart");
    var myChart = null;
    if (ctx) {
        myChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Traffic Count',
                    data: [],
                    backgroundColor: 'rgba(135, 206, 250, 0.6)',
                    borderColor: 'rgba(135, 206, 250, 0.8)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 500
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `Traffic Count: ${context.raw}`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                            font: {
                                size: 12
                            }
                        },
                        title: {
                            display: true,
                            text: 'Number of Packets',
                            font: {
                                size: 14
                            }
                        }
                    },
                    x: {
                        ticks: {
                            font: {
                                size: 12
                            },
                            maxRotation: 45,
                            minRotation: 45
                        }
                    }
                }
            }
        });
    }

    // Update connection status
    const $connectionStatus = $('#connection-status');
    const $statusIndicator = $('.status-indicator');

    socket.on('connect', function() {
        console.log('Connected to server');
        if ($connectionStatus.length) $connectionStatus.text('Connected');
        if ($statusIndicator.length) $statusIndicator.addClass('status-active').removeClass('status-inactive');
    });

    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        if ($connectionStatus.length) $connectionStatus.text('Disconnected');
        if ($statusIndicator.length) $statusIndicator.addClass('status-inactive').removeClass('status-active');
    });

    // Handle classification results
    socket.on('newresult', function(msg) {
        console.log("Received classification result:", msg);
        if (!msg || !msg.result) return;

        const resultData = msg.result;
        messages_received.unshift(resultData);

        // Update counters
        totalFlows++;
        if (resultData.classification === 0) {
            benignFlows++;
        } else {
            maliciousFlows++;
        }
        updateCounters();

        if (messages_received.length > 100) {
            messages_received = messages_received.slice(0, 100);
        }

        // Update IP traffic counts for the result
        if (resultData.source_ip && resultData.source_ip !== 'N/A') {
            ipTraffic[resultData.source_ip] = (ipTraffic[resultData.source_ip] || 0) + 1;
        }
        if (resultData.dest_ip && resultData.dest_ip !== 'N/A') {
            ipTraffic[resultData.dest_ip] = (ipTraffic[resultData.dest_ip] || 0) + 1;
        }

        // Update chart with top 10 IPs
        updateChart();

        updateTrafficTable();
    });

    function updateCounters() {
        $('#total-flows').text(totalFlows);
        $('#benign-flows').text(benignFlows);
        $('#malicious-flows').text(maliciousFlows);
    }

    function updateChart() {
        const sortedIPs = Object.entries(ipTraffic)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        if (myChart) {
            myChart.data.labels = sortedIPs.map(item => item[0]);
            myChart.data.datasets[0].data = sortedIPs.map(item => item[1]);
            myChart.update('none'); // Use 'none' mode for better performance
        }
    }

    function updateTrafficTable() {
        const $trafficBody = $('#traffic-body');
        if (!$trafficBody.length) return;

        let html = '';
        messages_received.forEach(function(msg) {
            const classification = classificationMap[msg.classification] || { 
                label: 'Unknown', 
                class: 'text-muted',
                icon: 'fa-question-circle'
            };

            html += `
                <tr>
                    <td>${msg.flow_id || 'N/A'}</td>
                    <td>${msg.source_ip || 'N/A'}</td>
                    <td>${msg.source_port || 'N/A'}</td>
                    <td>${msg.dest_ip || 'N/A'}</td>
                    <td>${msg.dest_port || 'N/A'}</td>
                    <td>${msg.protocol || 'N/A'}</td>
                    <td>
                        <span class="classification-badge ${classification.class}">
                            <i class="fas ${classification.icon} me-1"></i>
                            ${classification.label}
                        </span>
                    </td>
                </tr>
            `;
        });

        $trafficBody.html(html);
    }

    // Handle refresh button click
    $('#refresh-table').on('click', function() {
        updateTrafficTable();
    });

    // Initialize counters
    updateCounters();
});
