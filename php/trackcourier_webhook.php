<?php
// trackcourier.io webhook receiver, for PHP 7.2 and later.
// No framework and no Composer: copy this one file to your server.
// Documentation: https://api.trackcourier.io/docs#php
//
// It answers:
//   405 to anything but a POST
//   401 until you paste your secret below, and when a signature does not match
//   400 to a signed body that is not a trackcourier.io update
//   200 to a test event, without calling your code
//   200 to a live update once save_tracking_update() has run
//   500 when save_tracking_update() throws
// We send an update again later after a 401 or a 500, never after a 200.

// Your signing secret, exactly as your dashboard showed it.
const TRACKCOURIER_WEBHOOK_SECRET = 'paste-your-signing-secret-here';

// After you rotate your secret, put the old one here for at least 15 minutes,
// so updates signed with it are still accepted. Otherwise leave it empty.
const TRACKCOURIER_WEBHOOK_PREVIOUS_SECRET = '';

function respond($http_status, $message)
{
    http_response_code($http_status);
    header('Content-Type: application/json');
    echo json_encode(array('message' => $message));
    exit;
}

function signature_matches($raw_body, $signature, $secret)
{
    if ($secret === '') {
        return false;
    }
    $expected = 'sha256=' . hash_hmac('sha256', $raw_body, $secret);
    return hash_equals($expected, $signature);
}

function text_field($fields, $name)
{
    return isset($fields[$name]) && is_string($fields[$name])
        ? $fields[$name] : '';
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    respond(405, 'Use POST.');
}

// The placeholder above is public, so anyone could sign with it.
$secret = TRACKCOURIER_WEBHOOK_SECRET;
$previous_secret = TRACKCOURIER_WEBHOOK_PREVIOUS_SECRET;
if ($secret === '' || $secret === 'paste-your-signing-secret-here') {
    error_log('TrackCourier webhook: paste your signing secret into this file');
    respond(401, 'Signing secret not set.');
}

// Check the signature on the raw body, byte for byte, before anything else:
// json_decode() then json_encode() can change the bytes, and then it fails.
// Read the header from $_SERVER: getallheaders() is missing on some servers.
$raw_body = file_get_contents('php://input');
$signature = isset($_SERVER['HTTP_X_TRACKCOURIER_SIGNATURE'])
    ? $_SERVER['HTTP_X_TRACKCOURIER_SIGNATURE'] : '';
if (!signature_matches($raw_body, $signature, $secret)
    && !signature_matches($raw_body, $signature, $previous_secret)) {
    respond(401, 'Signature does not match.');
}

$event = json_decode($raw_body, true);
if (!is_array($event) || !isset($event['data']) || !is_array($event['data'])) {
    respond(400, 'Not a trackcourier.io update.');
}
$data = $event['data'];
$event_name = text_field($event, 'event');
$courier = text_field($data, 'courier');
$tracking_number = trim(text_field($data, 'tracking_number'));
if ($event_name === '' || $courier === '' || $tracking_number === '') {
    respond(400, 'Not a trackcourier.io update.');
}

// A test event names no real shipment: its courier begins "synthetic-test-".
if (strpos($courier, 'synthetic-test-') === 0) {
    respond(200, 'Test event received.');
}

try {
    save_tracking_update(
        $tracking_number,
        $courier,
        text_field($data, 'status'),
        isset($data['checkpoints']) && is_array($data['checkpoints'])
            ? $data['checkpoints'] : null
    );
} catch (Throwable $e) {
    error_log('TrackCourier webhook not saved: ' . $e->getMessage());
    respond(500, 'Not saved; it will be sent again.');
}
respond(200, 'Received.');

// Write your own code in this function. Aim to answer within 5 seconds.
//
// $tracking_number  the docket. Find your booking by this alone: $courier is
//                   our name for the courier (for example blue-dart-courier),
//                   not the one you sent us.
// $status           the shipment's state, for example delivered, in_transit,
//                   out_for_delivery or exception. Treat a value you do not
//                   know as still in progress.
// $checkpoints      the shipment's whole history, or null when this update
//                   carries none. Replace the checkpoints you hold for the
//                   docket with these rather than adding them: the same
//                   update can arrive more than once. When it is null, keep
//                   the ones you hold.
//
// A docket that is not yours must still get a 200: just return.
function save_tracking_update($tracking_number, $courier, $status, $checkpoints)
{
    // Until you replace this line, every live update gets a 500 and is sent
    // again later, so none is counted as delivered before your code saves it.
    throw new Exception('Write your own code in save_tracking_update().');
}
