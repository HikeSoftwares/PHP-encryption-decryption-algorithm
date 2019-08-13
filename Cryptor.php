<?php


function hikeEncrypt($token){
      $encryption_key = 'CKXH2U9RPY3EFD70TLS1ZG4N8WQBOVI6AMJ5';
      $cryptor = new HikeEncryption($encryption_key);
      $crypted_token = $cryptor->encrypt($token);
      unset($token);
      return $crypted_token;
}

function hikeDecrypt($crypted_token){
      $encryption_key = 'CKXH2U9RPY3EFD70TLS1ZG4N8WQBOVI6AMJ5';
      $cryptor = new HikeEncryption($encryption_key);
      $decrypted_token = $cryptor->decrypt($crypted_token);
      return $decrypted_token;
}

class HikeEncryption
{

  protected $method = 'AES-128-CTR'; // default
  private $key;

  protected function iv_bytes()
  {
    return openssl_cipher_iv_length($this->method);
  }

  public function __construct($key = FALSE, $method = FALSE)
  {
    if(!$key) {
      // if you don't supply your own key, this will be the default
      $key = gethostname() . "|" . ip2long($_SERVER['SERVER_ADDR']);
    }
    if(ctype_print($key)) {
      // convert key to binary format
      $this->key = openssl_digest($key, 'SHA256', TRUE);
    } else {
      $this->key = $key;
    }
    if($method) {
      if(in_array($method, openssl_get_cipher_methods())) {
        $this->method = $method;
      } else {
        die(__METHOD__ . ": unrecognised encryption method: {$method}");
      }
    }
  }

  public function encrypt($data)
  {
    $iv = openssl_random_pseudo_bytes($this->iv_bytes());
    $encrypted_string = bin2hex($iv) . openssl_encrypt($data, $this->method, $this->key, 0, $iv);
    return $encrypted_string;
  }

  // decrypt encrypted string
  public function decrypt($data)
  {
    $iv_strlen = 2  * $this->iv_bytes();
    if(preg_match("/^(.{" . $iv_strlen . "})(.+)$/", $data, $regs)) {
      list(, $iv, $crypted_string) = $regs;
      $decrypted_string = openssl_decrypt($crypted_string, $this->method, $this->key, 0, hex2bin($iv));
      return $decrypted_string;
    } else {
      return FALSE;
    }
  }

}

?>