<?php
require '/home/pi/phs/vendor/autoload.php';
//require_once '../KISA_SEED_CBC.php';
require 'SEED_CBC_new.php';
use phpseclib3\Crypt\RSA;
use phpseclib3\File\X509;

function fetch($url, $body = null)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/x-www-form-urlencoded',
        'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
        'Origin: https://hcs.eduro.go.kr',
        'Referer: https://hcs.eduro.go.kr/'
    ]);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}

$password = $_GET['p'];

$transkeyServlet = 'https://hcs.eduro.go.kr/transkeyServlet';
$publicKey = [
    'n' => '00e58d6a1c010cf703505cb454520876b0e2a2e0c732652b18824d367c3a7b420ad56e148c84484ff48e1efcfc4534fe1e8773f57e07b5bb0f9880349978db85c2bbbc39ccf2ef899dd8ae56fa6401b4f3a1eace450cda1b0412752e4a7b163d85e35a3d87a8f50588f336bcfde8f10c616998f8475b54e139a5f62b875ebb46a4bd21c0bac7dacce227bfe6b08da53849118c61958dd17b5cedd96b898cfd0b6cabcceaa971c634456530c5cc0a7a99152e34abd2857387cc6cbddf6c393d035da9ac960232ae5f7dcc4f62d776235d46076a871e79d5527e40e74a8199f03bd1b342e415c3c647afb45820fa270e871379b183bde974ed13e1bd8b467f0d1729',
    'k' => 256,
    'e' => '010001'
];
$delimiter = '$';

$getInitTime = fetch($transkeyServlet.'?op=getInitTime');
$initTime = substr($getInitTime,14,strpos($getInitTime, "';var limitTime") - 14);

$token = '';
$getToken = fetch($transkeyServlet.'?op=getToken');
$token = str_replace(['var TK_requestToken=', ';'],['',''],$getToken);


$getPublicKey = fetch($transkeyServlet, 'op=getPublicKey&TK_requestToken='.$token);
$data = base64_decode($getPublicKey);

$x509 = new X509();
$cert = $x509->loadX509($getPublicKey);
$publicKey = $x509->getPublicKey();

$uuid = bin2hex(random_bytes(32));

$genSessionKey = bin2hex(random_bytes(16));
$sessionKey = array_map(fn($char) => '0x0'.$char, str_split($genSessionKey));
$encSessionKey = encSessionKey($genSessionKey, $publicKey);

$getKeyInfo = htmlspecialchars(fetch($transkeyServlet, 'op=getKeyInfo&key='.$encSessionKey.'&transkeyUuid='.$uuid.'&useCert=true&TK_requestToken='.$token.'&mode=common'));
// <result><script> 태그에 있음

$keyIndex = fetch($transkeyServlet, 'op=getKeyIndex&name=password&keyboardType=number&initTime='.$initTime);
$dummy = fetch($transkeyServlet, 'op=getDummy&keyboardType=number&fieldType=password&keyIndex='.$keyIndex.'&talkBack=true');

$keysXY = [
    [125, 27], [165, 27], [165, 67], [165, 107],
    [165, 147], [125, 147], [85, 147], [45, 147],
    [45, 107], [45, 67], [45, 27], [85, 27]
];
$keys = explode(',', $dummy);
$enc = implode('', array_map(
    function($n) {
        global $keysXY, $delimiter, $keys, $sessionKey, $initTime;
        list($x, $y) = $keysXY[array_search($n, $keys)];
        return $delimiter.seedEnc("$x $y", $sessionKey, $initTime);
    },
    str_split($password)
));
for ($j = 4; $j < 128; ++$j) {
    //$enc .= $delimiter.seedEnc('# 0 0', $sessionKey, $initTime);
}
$hmac = hash_hmac('sha256', $enc, $genSessionKey);
$result = [
    'raon' => [[
        'id' => 'password',
        'enc' => $enc,
        'hmac' => $hmac,
        'keyboardType' => 'number',
        'keyIndex' => $keyIndex,
        'fieldType' => 'password',
        'seedKey' => $encSessionKey,
        'initTime' => $initTime,
        'ExE2E' => 'false'
    ]]
];
var_dump($result);
//echo json_encode($result);
        
function encSessionKey($plaintext, $publicKey){
    $key = $publicKey->withPadding(RSA::ENCRYPTION_OAEP)->withHash('sha1')->withMGFHash('sha1');
    return bin2hex($key->encrypt($plaintext));
}
function encrypt($pass) {
    global $keys, $dummy;
    $geos = array_map(fn($n) => $keys[$dummy[$n]], str_split($pass));
    return geos_encrypt($geos);
}
function geos_encrypt($geos) {
    $iv = [0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x4b, 0x65, 0x79, 0x31, 0x30];
    $out = "";
    foreach ($geos as $geo) {
        list($x, $y) = $geo;

        //$xbytes = 
    }
    return $out;
}
function seedEnc(string $geo, array $sessionKey, $initTime) {
    $iv = [0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x4b, 0x65, 0x79, 0x31, 0x30];
    $tSize = 48;
    $inData = $outData = array_pad([], $tSize, 0);
    $roundKey = array_pad([], 32, 0);
    $encDelimiter = ',';
    
    for($i=0; $i<strlen($geo); ++$i) {
        if($geo[$i] === 'l' || $geo[$i] === 'u' || $geo[$i] === '#') {
            $inData[$i] = ord($geo[$i]);
            continue;
        } elseif($geo[$i] === ' ') {
            $inData[$i] = ord($geo[$i]);
            continue;
        }
        $inData[$i] = $geo[$i];
    }

    $inData[++$i] = 32;
    for ($k=0; $k<strlen($initTime); ++$k) {
        if(preg_match('/^[\x61-\x7A]*$/', $initTime[$k]))
            $inData[++$i] = ord($initTime[$k]);
        else
            $inData[++$i] = $initTime[$k];
    }

    $inData[++$i] = 32;
    $inData[++$i] = 37;
    
    $roundKey = SEED::SeedRoundKey($roundKey, $sessionKey);
    $outData = SEED::SeedEncryptCbc($roundKey, $iv, $inData, $tSize, $outData);
    

    $encodedDataStr =  implode('', array_map(fn($k) => dechex($outData[$k]).$encDelimiter, array_keys(array_pad(array(),$tSize,0))));

    $res = substr($encodedDataStr, 0, strlen($encodedDataStr) - 1);
    var_dump(count(explode(',',$res)));
    return $res;
}
