<?php
function dataEncryption($dataToEncrypt, $ResellerUsername) {
    return strtr(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($ResellerUsername), serialize($dataToEncrypt), MCRYPT_MODE_CBC, md5(md5($ResellerUsername)))), '+/=', '-_,');
}
$bridgeKey = '';
$ResellerUsername = '';

$dataToEncrypt = array(
        'action'                => 'update_user',
        'reseller_username'     => $ResellerUsername,
        'reseller_password'     => '',
        'bridge_key'            => $bridgeKey,
        'hosting_plan'          => '',
	'domain'                => '',
	'email'			=> '',
	'fname'			=> '',
	'lname'			=> ''
);
$ch = curl_init('http://admin.server.example.org:8080/remotebridge.php');
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, 'key='.$bridgeKey.'&data='.dataEncryption($dataToEncrypt, $ResellerUsername));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

$httpResponse = curl_exec($ch);
echo $httpResponse;
curl_close($ch);
?>
