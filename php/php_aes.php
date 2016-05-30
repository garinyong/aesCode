<?php
if(!defined('IN_MITU')) {
	exit('Access Denied');
}
//print(aesencrypt('1234456789'));
//echo("\n<br>");
//print(aesdecrypt('3voDR6EtDidFr03fShvejg=='));
//exit;
function addpadding($string, $blocksize = 16)
{
    $len = strlen($string);
    $pad = $blocksize - ($len % $blocksize);
    $string .= str_repeat(chr($pad), $pad);
    return $string;
}
function strippadding($string)
{
    $slast = ord(substr($string, -1));
    $slastc = chr($slast);
    $pcheck = substr($string, -$slast);
    if(preg_match("/$slastc{".$slast."}/", $string)){
        $string = substr($string, 0, strlen($string)-$slast);
        return $string;
    } else {
        return false;
    }
}
function aesencrypt($string = "",$key = "1234567812345678")
{
    $iv = null; 
    return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, addpadding($string), MCRYPT_MODE_CBC, $iv));
}
 
function aesdecrypt($string = "",$key = "1234567812345678")
{
    $iv = null;
    $string = base64_decode($string);
    return strippadding(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $string, MCRYPT_MODE_CBC, $iv));
}
?>