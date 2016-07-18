<?php
function dataEncryption($dataToEncrypt, $ResellerUsername) {
    return strtr(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($ResellerUsername), serialize($dataToEncrypt), MCRYPT_MODE_CBC, md5(md5($ResellerUsername)))), '+/=', '-_,');
}
$bridgeKey = '';
$ResellerUsername = '';

$dataToEncrypt = array(
        'action'                => 'edit_dns_record',
        'reseller_username'     => $ResellerUsername,
        'reseller_password'     => '',
        'bridge_key'            => $bridgeKey,
        'domain'                => '',
		'record_name'			=> '',
		'record_data'			=> '',
		'record_type'			=> '',
		'record_class'			=> 'IN',
		'record_prio'			=> '10',
		'ttl'					=> '',
		'log_user'				=> ''
);
$ch = curl_init('http://admin.server.example.org:8080/remotebridge.php');
curl_setopt($ch, CURLOPT_POST, 1).'<br>';
curl_setopt($ch, CURLOPT_POSTFIELDS, 'key='.$bridgeKey.'&data='.dataEncryption($dataToEncrypt, $ResellerUsername)).'<br>';
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1).'<br>';

$httpResponse = curl_exec($ch);
echo $httpResponse;
curl_close($ch);
?>
