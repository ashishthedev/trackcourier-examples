<?php
// A stand-in for https://api.trackcourier.io/v1/track in the tests: it records what it was asked
// and answers with /app/answer.json ({"status": <HTTP status>, "body": <the JSON to send>}).
file_put_contents('/out/request.json', json_encode(array(
    'path' => parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH),
    'query' => $_GET,
    'api_key' => isset($_SERVER['HTTP_X_API_KEY']) ? $_SERVER['HTTP_X_API_KEY'] : null,
)));
$answer = json_decode(file_get_contents('/app/answer.json'), true);
http_response_code($answer['status']);
header('Content-Type: application/json');
echo json_encode($answer['body']);
