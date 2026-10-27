<?php
// Track one shipment with the trackcourier.io API.
// For PHP 7.2 and later, with the curl extension.
// Documentation: https://api.trackcourier.io/docs#php
// Set TRACKCOURIER_API_KEY to your API key, from
// https://api.trackcourier.io/dashboard/keys
$courier = 'dtdc';
$tracking_number = 'YOUR_TRACKING_NUMBER';

$api_key = getenv('TRACKCOURIER_API_KEY');
if ($api_key === false || $api_key === '') {
    echo "Set TRACKCOURIER_API_KEY to your API key, from\n"
        . "https://api.trackcourier.io/dashboard/keys\n";
    exit(1);
}

$url = 'https://api.trackcourier.io/v1/track?' . http_build_query(array(
    'courier' => $courier,
    'tracking_number' => $tracking_number,
));
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_HTTPHEADER, array('X-API-Key: ' . $api_key));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 60);
$body = curl_exec($ch);
if ($body === false) {
    echo 'Could not reach the API: ' . curl_error($ch) . "\n";
    exit(1);
}
$http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$answer = json_decode($body, true);

if ($http_status != 200 || !isset($answer['data'])) {
    // Branch on error.code, never on the HTTP status.
    // Every code: https://api.trackcourier.io/docs#errors
    $code = isset($answer['error']['code'])
        ? $answer['error']['code'] : 'HTTP ' . $http_status;
    $message = isset($answer['error']['message'])
        ? $answer['error']['message'] : $body;
    echo $code . ': ' . $message . "\n";
    exit(1);
}

$shipment = $answer['data'];
echo $shipment['ShipmentState'] . ': ' . $shipment['MostRecentStatus'] . "\n";
foreach ((array) $shipment['Checkpoints'] as $checkpoint) {
    echo $checkpoint['Date'] . ' ' . $checkpoint['Time'] . '  '
        . $checkpoint['Location'] . '  ' . $checkpoint['Activity'] . "\n";
}
