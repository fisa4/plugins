<?php
function dataEncryption($dataToEncrypt, $ResellerUsername) {
    return strtr(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($ResellerUsername), serialize($dataToEncrypt), MCRYPT_MODE_CBC, md5(md5($ResellerUsername)))), '+/=', '-_,');
}
$bridgeKey = '';
$ResellerUsername = '';

$dataToEncrypt = array(
        'action'                => 'add_mail',
        'reseller_username'     => $ResellerUsername,
        'reseller_password'     => '',
        'bridge_key'            => $bridgeKey,
		'newmailpass'			=> '',
        'account'               => '',
        'domain'                => '',
		'quota'					=> '',				// in MB only required when account_type has normal_mail
		'account_type'			=> '',				// possible values: 'normal_mail', 'normal_forward' or 'normal_mail, normal_forward'
		'mail_forward'			=> ''
);
$ch = curl_init('http://admin.server.example.org:8080/remotebridge.php');
curl_setopt($ch, CURLOPT_POST, 1).'<br>';
curl_setopt($ch, CURLOPT_POSTFIELDS, 'key='.$bridgeKey.'&data='.dataEncryption($dataToEncrypt, $ResellerUsername)).'<br>';
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1).'<br>';

$httpResponse = curl_exec($ch);
echo $httpResponse;
curl_close($ch);
?>
