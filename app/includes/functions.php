<?php
include 'connection.php'; // start MySQL connection

$role = $_SESSION['role']; // user role
$ip = fetchip(); // ip address
function vpn_check($ipaddr)
{
	global $proxycheckapikey;
    	$url = "https://proxycheck.io/v2/{$ipaddr}?key={$proxycheckapikey}?vpn=1";
	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	$result = curl_exec($ch);
	curl_close($ch);
	$json = json_decode($result);
	if($json->$ipaddr->proxy == "yes")
	{
		return true;
	}

    return false;
}

function selectedapp($username)
{
    global $link;

    ($result = mysqli_query($link, "SELECT * FROM `accounts` WHERE `username` = '$username'")) or die(mysqli_error($link));
	$row = mysqli_fetch_array($result);

    $appname = $row["selectedapp"];
    $_SESSION['selectedapp'] = $appname;

    ($result = mysqli_query($link, "SELECT * FROM `apps` WHERE `owner` = '$username' AND `name` = '$appname'")) or die(mysqli_error($link));
	$row = mysqli_fetch_array($result);

    $_SESSION["app"] = $row["secret"];

}

function expire_check($username, $expires)
{
	global $link;
	
	if($expires < time())
	{
		$_SESSION['role'] = "tester";
		mysqli_query($link,"UPDATE `accounts` SET `role` = 'tester' WHERE `username` = '$username'");
	}

	if($expires - time() < 2629743) // account expires in month
	{
		return true;
	}
	else
	{
		return false;
	}
}

function wh_log($webhook_url, $msg, $un)
{
    $timestamp = date("c", strtotime("now"));

    $json_data = json_encode([
    // Message
    "content" => $msg,

    // Username
    "username" => "$un",

    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    $ch = curl_init($webhook_url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Content-type: application/json'
    ));
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_HEADER, 0);

    curl_exec($ch);
    curl_close($ch);
}

function xss_clean($data)
{
// Fix &entity\n;
$data = str_replace(array('&amp;','&lt;','&gt;'), array('&amp;amp;','&amp;lt;','&amp;gt;'), $data);
$data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
$data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
$data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');

// Remove any attribute starting with "on" or xmlns
$data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);

// Remove javascript: and vbscript: protocols
$data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
$data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
$data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);

// Only works in IE: <span style="width: expression(alert('Ping!'));"></span>
$data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
$data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
$data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);

// Remove namespaced elements (we do not need them)
$data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);

do
{
    // Remove really unwanted tags
    $old_data = $data;
    $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
}
while ($old_data !== $data);

// we are done...
return $data;
}

function sanitize($input)
{
    if (empty($input) & !is_numeric($input))
    {
        return NULL;
    }
    global $link; // needed to refrence active MySQL connection
    return mysqli_real_escape_string($link, strip_tags(trim($input))); // return string with quotes escaped to prevent SQL injection, script tags stripped to prevent XSS attach, and trimmed to remove whitespace
    
}
function getIp()
{
    return $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
}
function fetchip()
{
    return str_replace(",62.210.119.214", "",$_SERVER['HTTP_X_FORWARDED_FOR']) ?? $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
}

function error($msg)
{
    echo '<script src="https://cdn.jsdelivr.net/npm/notyf@3/notyf.min.js"></script><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/notyf@3/notyf.min.css"><script type=\'text/javascript\'>
                
                            const notyf = new Notyf();
                            notyf
                              .error({
                                message: \'' . $msg . '\',
                                duration: 3500,
                                dismissible: true
                              });               
                
                </script>';
}

function success($msg)
{
    echo '<script src="https://cdn.jsdelivr.net/npm/notyf@3/notyf.min.js"></script><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/notyf@3/notyf.min.css"><script type=\'text/javascript\'>
                
                            const notyf = new Notyf();
                            notyf
                              .success({
                                message: \'' . $msg . '\',
                                duration: 3500,
                                dismissible: true
                              });               
                
                </script>';
}

function random_string_upper($length = 10, $keyspace = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    string
    {
        $out = '';

        for ($i = 0;$i < $length;$i++)
        {
            $rand_index = random_int(0, strlen($keyspace) - 1);

            $out .= $keyspace[$rand_index];
        }

        return $out;
    }

    function random_string_lower($length = 10, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyz'):
        string
        {
            $out = '';

            for ($i = 0;$i < $length;$i++)
            {
                $rand_index = random_int(0, strlen($keyspace) - 1);

                $out .= $keyspace[$rand_index];
            }

            return $out;
        }

        function formatBytes($bytes, $precision = 2)
        {
            $units = array(
                'B',
                'KB',
                'MB',
                'GB',
                'TB'
            );

            $bytes = max($bytes, 0);
            $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
            $pow = min($pow, count($units) - 1);

            // Uncomment one of the following alternatives
            // $bytes /= pow(1024, $pow);
            $bytes /= (1 << (10 * $pow));

            return round($bytes, $precision) . ' ' . $units[$pow];
        }

        function generateRandomString($length = 10)
        {
            $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $charactersLength = strlen($characters);
            $randomString = '';
            for ($i = 0;$i < $length;$i++)
            {
                $randomString .= $characters[rand(0, $charactersLength - 1) ];
            }
            return $randomString;
        }

        function generateRandomNum($length = 6)
        {
            $characters = '0123456789';
            $charactersLength = strlen($characters);
            $randomString = '';
            for ($i = 0;$i < $length;$i++)
            {
                $randomString .= $characters[rand(0, $charactersLength - 1) ];
            }
            return $randomString;
        }

                function getsession($sessionid, $secret)
                {
                    global $link; // needed to refrence active MySQL connection
                    mysqli_query($link, "DELETE FROM `sessions` WHERE `expiry` < " . time() . "") or die(mysqli_error($link));
                    // clean out expired sessions
                    $result = mysqli_query($link, "SELECT * FROM `sessions` WHERE `id` = '$sessionid' AND `app` = '$secret'");
                    $num = mysqli_num_rows($result);
                    if ($num === 0)
                    {
                        die("no active session");
                    }
                    $row = mysqli_fetch_array($result);
                    return array(
                        "credential" => $row["credential"],
                        "enckey" => $row["enckey"],
                        "validated" => $row["validated"]
                    );
                }
?>

<style>
			/* width */
			::-webkit-scrollbar {
			width: 10px;
			}

			/* Track */
			::-webkit-scrollbar-track {
			box-shadow: inset 0 0 5px grey; 
			border-radius: 10px;
			}
			
			/* Handle */
			::-webkit-scrollbar-thumb {
			background: #2549e8; 
			border-radius: 10px;
			}

			/* Handle on hover */
			::-webkit-scrollbar-thumb:hover {
			background: #0a2bbf; 
			}
			</style>

            <?php

            /**
             * PHP Class for handling Google Authenticator 2-factor authentication
             *
             * @author Michael Kliewe
             * @copyright 2012 Michael Kliewe
             * @license http://www.opensource.org/licenses/bsd-license.php BSD License
             * 
             */
            
            class GoogleAuthenticator
            {
                protected $_codeLength = 6;
            
                /**
                 * Create new secret.
                 * 16 characters, randomly chosen from the allowed base32 characters.
                 *
                 * @param int $secretLength
                 * @return string
                 */
                public function createSecret($secretLength = 16)
                {
                    $validChars = $this->_getBase32LookupTable();
                    unset($validChars[32]);
            
                    $secret = '';
                    for ($i = 0; $i < $secretLength; $i++) {
                        $secret .= $validChars[array_rand($validChars)];
                    }
                    return $secret;
                }
            
                /**
                 * Calculate the code, with given secret and point in time
                 *
                 * @param string $secret
                 * @param int|null $timeSlice
                 * @return string
                 */
                public function getCode($secret, $timeSlice = null)
                {
                    if ($timeSlice === null) {
                        $timeSlice = floor(time() / 30);
                    }
            
                    $secretkey = $this->_base32Decode($secret);
            
                    // Pack time into binary string
                    $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);
                    // Hash it with users secret key
                    $hm = hash_hmac('SHA1', $time, $secretkey, true);
                    // Use last nipple of result as index/offset
                    $offset = ord(substr($hm, -1)) & 0x0F;
                    // grab 4 bytes of the result
                    $hashpart = substr($hm, $offset, 4);
            
                    // Unpak binary value
                    $value = unpack('N', $hashpart);
                    $value = $value[1];
                    // Only 32 bits
                    $value = $value & 0x7FFFFFFF;
            
                    $modulo = pow(10, $this->_codeLength);
                    return str_pad($value % $modulo, $this->_codeLength, '0', STR_PAD_LEFT);
                }
            
                /**
                 * Get QR-Code URL for image, from google charts
                 *
                 * @param string $name
                 * @param string $secret
                 * @param string $title
                 * @return string
                 */
                public function getQRCodeGoogleUrl($name, $secret, $title = null) {
                    $urlencoded = urlencode('otpauth://totp/'.$name.'?secret='.$secret.'');
                if(isset($title)) {
                            $urlencoded .= urlencode('&issuer='.urlencode($title));
                    }
                    return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl='.$urlencoded.'';
                }
            
                /**
                 * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
                 *
                 * @param string $secret
                 * @param string $code
                 * @param int $discrepancy This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
                 * @param int|null $currentTimeSlice time slice if we want use other that time()
                 * @return bool
                 */
                public function verifyCode($secret, $code, $discrepancy = 1, $currentTimeSlice = null)
                {
                    if ($currentTimeSlice === null) {
                        $currentTimeSlice = floor(time() / 30);
                    }
            
                    for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
                        $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
                        if ($calculatedCode == $code ) {
                            return true;
                        }
                    }
            
                    return false;
                }
            
                /**
                 * Set the code length, should be >=6
                 *
                 * @param int $length
                 * @return GoogleAuthenticator
                 */
                public function setCodeLength($length)
                {
                    $this->_codeLength = $length;
                    return $this;
                }
            
                /**
                 * Helper class to decode base32
                 *
                 * @param $secret
                 * @return bool|string
                 */
                protected function _base32Decode($secret)
                {
                    if (empty($secret)) return '';
            
                    $base32chars = $this->_getBase32LookupTable();
                    $base32charsFlipped = array_flip($base32chars);
            
                    $paddingCharCount = substr_count($secret, $base32chars[32]);
                    $allowedValues = array(6, 4, 3, 1, 0);
                    if (!in_array($paddingCharCount, $allowedValues)) return false;
                    for ($i = 0; $i < 4; $i++){
                        if ($paddingCharCount == $allowedValues[$i] &&
                            substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])) return false;
                    }
                    $secret = str_replace('=','', $secret);
                    $secret = str_split($secret);
                    $binaryString = "";
                    for ($i = 0; $i < count($secret); $i = $i+8) {
                        $x = "";
                        if (!in_array($secret[$i], $base32chars)) return false;
                        for ($j = 0; $j < 8; $j++) {
                            $x .= str_pad(base_convert(@$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
                        }
                        $eightBits = str_split($x, 8);
                        for ($z = 0; $z < count($eightBits); $z++) {
                            $binaryString .= ( ($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48 ) ? $y:"";
                        }
                    }
                    return $binaryString;
                }
            
                /**
                 * Helper class to encode base32
                 *
                 * @param string $secret
                 * @param bool $padding
                 * @return string
                 */
                protected function _base32Encode($secret, $padding = true)
                {
                    if (empty($secret)) return '';
            
                    $base32chars = $this->_getBase32LookupTable();
            
                    $secret = str_split($secret);
                    $binaryString = "";
                    for ($i = 0; $i < count($secret); $i++) {
                        $binaryString .= str_pad(base_convert(ord($secret[$i]), 10, 2), 8, '0', STR_PAD_LEFT);
                    }
                    $fiveBitBinaryArray = str_split($binaryString, 5);
                    $base32 = "";
                    $i = 0;
                    while ($i < count($fiveBitBinaryArray)) {
                        $base32 .= $base32chars[base_convert(str_pad($fiveBitBinaryArray[$i], 5, '0'), 2, 10)];
                        $i++;
                    }
                    if ($padding && ($x = strlen($binaryString) % 40) != 0) {
                        if ($x == 8) $base32 .= str_repeat($base32chars[32], 6);
                        elseif ($x == 16) $base32 .= str_repeat($base32chars[32], 4);
                        elseif ($x == 24) $base32 .= str_repeat($base32chars[32], 3);
                        elseif ($x == 32) $base32 .= $base32chars[32];
                    }
                    return $base32;
                }
            
                /**
                 * Get array with all 32 characters for decoding from/encoding to base32
                 *
                 * @return array
                 */
                protected function _getBase32LookupTable()
                {
                    return array(
                        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
                        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
                        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
                        'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
                        '='  // padding char
                    );
                }
            }
            