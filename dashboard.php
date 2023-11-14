<?php
// @author h3st4k3r
// @version 0.2

$jsonFilePath = ''; // Ruta al json vuestro

$jsonData = file_get_contents($jsonFilePath);

if ($jsonData === false) {
    die("Error al leer el archivo JSON: No se pudo leer el archivo");
}

$dataArray = json_decode($jsonData, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    die("Error al leer el archivo JSON: " . json_last_error_msg());
}

// Contadores para los datos de las gráficas
$totalArchivosAnalizados = count($dataArray);
$totalArchivosPositivos = 0;
$totalMalwareDetectado = 0;
$totalMalwareNoDetectado = 0;

// Calcular los valores para las otras dos nuevas gráficas
foreach ($dataArray as $entry) {
    if ($entry['malware_detected'] === 'true') {
        $totalArchivosPositivos++;
        $totalMalwareDetectado++;
    } else {
        $totalMalwareNoDetectado++;
    }
}

$messageIdCounts = [];
$subjectCounts = [];

foreach ($dataArray as $entry) {
    // Contar los Message ID
    $domain = explode('@', $entry['message_id'])[1] ?? '';
    if (!empty($domain)) {
        if (!isset($messageIdCounts[$domain])) {
            $messageIdCounts[$domain] = 0;
        }
        $messageIdCounts[$domain]++;
    }

    // Contar los Subjects
    $subject = $entry['subject'];
    if (!empty($subject)) {
        if (!isset($subjectCounts[$subject])) {
            $subjectCounts[$subject] = 0;
        }
        $subjectCounts[$subject]++;
    }
}

// Preparar arrays para las gráficas
$messageIdLabels = [];
$messageIdData = [];
foreach ($messageIdCounts as $domain => $count) {
    $messageIdLabels[] = $domain;
    $messageIdData[] = $count;
}

$subjectLabels = [];
$subjectData = [];
foreach ($subjectCounts as $subject => $count) {
    $subjectLabels[] = $subject;
    $subjectData[] = $count;
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Dashboard de Spamtrap</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
        }
        .container {
            max-width: 100%;
            padding: 20px;
        }
        .charts-container {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
        }
        .chart {
            width: 45%;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Dashboard de Spamtrap</h1>
        <div class="charts-container">
            <div class="chart">
                <h2>Archivos Analizados</h2>
                <canvas id="fileCountChart" width="400" height="200"></canvas>
            </div>
            <div class="chart">
                <h2>Malware Detectado</h2>
                <canvas id="malwareChart" width="400" height="200"></canvas>
            </div>
        </div
        <script>
            // Obtén el contexto del canvas para el gráfico de archivos analizados
            var fileCountCtx = document.getElementById('fileCountChart').getContext('2d');

            // Datos para el gráfico de archivos analizados
            var fileCountData = {
                labels: ['Total de Archivos Analizados', 'Total de Archivos Positivos'],
                datasets: [{
                    label: 'Cantidad',
                    data: [<?php echo $totalArchivosAnalizados; ?>, <?php echo $totalArchivosPositivos; ?>],
                    backgroundColor: [
                        'rgba(75, 192, 192, 0.2)',
                        'rgba(255, 99, 132, 0.2)'
                    ],
                    borderColor: [
                        'rgba(75, 192, 192, 1)',
                        'rgba(255, 99, 132, 1)'
                    ],
                    borderWidth: 1
                }]
            };

            // Configuración del gráfico de archivos analizados
            var fileCountOptions = {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            };

            // Crea el gráfico de archivos analizados
            var fileCountChart = new Chart(fileCountCtx, {
                type: 'bar',
                data: fileCountData,
                options: fileCountOptions
            });

            // Obtén el contexto del canvas para el gráfico de malware
            var malwareCtx = document.getElementById('malwareChart').getContext('2d');

            // Datos para el gráfico de malware
            var malwareData = {
                labels: ['Malware Detectado', 'Malware No Detectado'],
                datasets: [{
                    label: 'Cantidad',
                    data: [<?php echo $totalMalwareDetectado; ?>, <?php echo $totalMalwareNoDetectado; ?>],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.2)',
                        'rgba(75, 192, 192, 0.2)'
                    ],
                    borderColor: [
                        'rgba(255, 99, 132, 1)',
                        'rgba(75, 192, 192, 1)'
                    ],
                    borderWidth: 1
                }]
            };

            // Configuración del gráfico de malware
            var malwareOptions = {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            };

            // Crea el gráfico de malware
            var malwareChart = new Chart(malwareCtx, {
                type: 'bar',
                data: malwareData,
                options: malwareOptions
            });
        </script>
      
<!-- Añadimos las otras dos gráficas de las que hablamos en el artículo -->
<div class="charts-container">
    <div class="chart">
        <h2>Top Message IDs</h2>
        <canvas id="messageIdChart" width="400" height="200"></canvas>
    </div>
    <div class="chart">
        <h2>Top Subjects</h2>
        <canvas id="subjectChart" width="400" height="200"></canvas>
    </div>
</div>
<script>
    // Gráfico para Message IDs
    var messageIdCtx = document.getElementById('messageIdChart').getContext('2d');
    var messageIdChart = new Chart(messageIdCtx, {
        type: 'bar',
        data: {
            labels: <?php echo json_encode($messageIdLabels); ?>,
            datasets: [{
                label: 'Cantidad',
                data: <?php echo json_encode($messageIdData); ?>,
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: { scales: { y: { beginAtZero: true } } }
    });

    // Gráfico para Subjects
    var subjectCtx = document.getElementById('subjectChart').getContext('2d');
    var subjectChart = new Chart(subjectCtx, {
        type: 'bar',
        data: {
            labels: <?php echo json_encode($subjectLabels); ?>,
            datasets: [{
                label: 'Cantidad',
                data: <?php echo json_encode($subjectData); ?>,
                backgroundColor: 'rgba(255, 206, 86, 0.2)',
                borderColor: 'rgba(255, 206, 86, 1)',
                borderWidth: 1
            }]
        },
        options: { scales: { y: { beginAtZero: true } } }
    });
</script>
      <!-- Finalmente pintamos la tabla con lso campos que queramos -->
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Message ID</th>
                    <th>File</th>
                    <th>Hash</th>
                    <th>Malware Detected</th>
                    <th>Malware Type</th>
                    <th>Subject</th> 
                    <th>Body</th>    
                    <th>Links</th>   
                </tr>
            </thead>
            <tbody>
                <?php foreach ($dataArray as $entry): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($entry['timestamp']); ?></td>
                        <td><?php echo htmlspecialchars($entry['message_id']); ?></td>
                        <td><?php echo htmlspecialchars($entry['file']); ?></td>
                        <td><?php echo htmlspecialchars($entry['hash']); ?></td>
                        <td><?php echo htmlspecialchars($entry['malware_detected']); ?></td>
                        <td><?php echo htmlspecialchars($entry['malware_type']); ?></td>
                        <td><?php echo htmlspecialchars($entry['subject']); ?></td>
                        <td><?php echo htmlspecialchars($entry['body']); ?></td>
                        <td><?php echo htmlspecialchars($entry['links']); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
