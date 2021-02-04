<?php

namespace wechat\payment;

use wechat\Config;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Exception\RequestException;
use WechatPay\GuzzleMiddleware\Util\PemUtil;
use WechatPay\GuzzleMiddleware\WechatPayMiddleware;

/**
 * 数据对象基础类，该类中定义数据类最基本的行为，包括：
 * 计算/设置/获取签名、输出 json 格式的参数、从 json 读取数据对象等
 *
 * @author Chai Yuan(chaiyuan@chaidada.cn)
 * @version v2&v3
 */
class WxPayDataBase extends Config
{
    public $values = array();

    /**
     * validate
     *
     * @param $cert_path
     *
     * @return bool
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function validate($cert_path)
    {
        $body = file_get_contents('php://input');
        $header = $this->em_getallheaders();
        $serialNo = $this->getHeader('Wechatpay-Serial');
        $sign = $this->getHeader('Wechatpay-Signature');
        $timestamp = $this->getHeader('Wechatpay-Timestamp');
        $nonce = $this->getHeader('Wechatpay-Nonce');
        if (!isset($serialNo, $sign, $timestamp, $nonce)) {
            return false;
        }
        $message = "$timestamp\n$nonce\n$body\n";
        $certificate = $this->readCert($cert_path);
        $signature = base64_decode($sign);
        $_serialNo = $this->getSerialNo($certificate);
        if ($serialNo !== $_serialNo) {
            throw new WxPayException("微信平台公钥不匹配");
        }
        $public_content = file_get_contents($cert_path);
        $publicKey = openssl_get_publickey($public_content);
        //$publicKey = openssl_get_publickey($certificate);
        if (!$publicKey) {
            throw new WxPayException("微信平台公钥初始化失败");
        }
        if (!in_array('sha256WithRSAEncryption', openssl_get_md_methods(true))) {
            throw new WxPayException("当前PHP环境不支持SHA256withRSA");
        }

        $verify = openssl_verify($message, $signature, $publicKey, 'sha256WithRSAEncryption');
        if ($verify == 1) {
            return true;
        }
        return false;
    }

    /**
     * readCert
     *
     * @param $cert_path
     *
     * @return resource
     *
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function readCert($cert_path)
    {
        return openssl_x509_read(file_get_contents($cert_path));

    }

    /**
     * getHeader
     *
     * @param string $key
     *
     * @return array|false|string
     *
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function getHeader(string $key = '')
    {
        $headers = $this->em_getallheaders();
        if ($key) {
            return $headers[$key];
        }
        return $headers;
    }

    /**
     * 获取header
     *
     * @return mixed
     *
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function em_getallheaders()
    {
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }

    /**
     * getSerialNo
     *
     * @param $certificate
     *
     * @return string
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function getSerialNo($certificate)
    {
        $info = openssl_x509_parse($certificate);
        error_log(var_export(array($certificate, $info), true) . PHP_EOL, 3, '/tmp/wxpay.log');
        if (!isset($info['serialNumber']) && !isset($info['serialNumberHex'])) {
            throw new WxPayException("证书格式错误");
        }

        $serialNo = '';
        if (isset($info['serialNumberHex'])) {
            $serialNo = $info['serialNumberHex'];
        } else {
            if (strtolower(substr($info['serialNumber'], 0, 2)) == '0x') { // HEX format
                $serialNo = substr($info['serialNumber'], 2);
            } else { // DEC format
                $value = $info['serialNumber'];
                $hexvalues = ['0', '1', '2', '3', '4', '5', '6', '7',
                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];
                while ($value != '0') {
                    $serialNo = $hexvalues[bcmod($value, '16')] . $serialNo;
                    $value = bcdiv($value, '16', 0);
                }
            }
        }

        return strtoupper($serialNo);
    }

    /**
     * getApiKey
     *
     * @return string
     *
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function getApiKey()
    {
        return $this->pay_sslkey;
    }

    /**
     * createHeader
     *
     * @param string $schema
     * @param string $token
     *
     * @return array
     *
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function createHeader(string $schema, string $token)
    {
        return [
            'Authorization:' . $schema . ' ' . $token,
            'Content-Type:application/json',
            'Accept:application/json',
            'User-Agent:' . $_SERVER['HTTP_USER_AGENT']
        ];
    }

    /**
     * createToken
     *
     * @param string $nonce
     * @param string $timestamp
     * @param string $sign
     *
     * @return string
     *
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function createToken(string $nonce, string $timestamp, string $sign)
    {
        $certificate = $this->readCert($this->pay_sslcert);
        $merchantSerialNumber = $this->getSerialNo($certificate);

        return sprintf('mchid="%s",nonce_str="%s",timestamp="%d",serial_no="%s",signature="%s"',
            $this->pay_mchid, $nonce, $timestamp, $merchantSerialNumber, $sign
        );
    }

    /**
     * createMessage
     *
     * @param string $url
     * @param string $method
     * @param string $timestamp
     * @param string $nonce
     * @param string $body
     *
     * @return string
     *
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function createMessage(string $url, string $method, string $timestamp, string $nonce, string $body)
    {
        $urlParts = parse_url($url);
        $canonicalUrl = ($urlParts['path'] . (!empty($urlParts['query']) ? "?{$urlParts['query']}" : ""));
        $message = strtoupper($method) . "\n" .
            $canonicalUrl . "\n" .
            $timestamp . "\n" .
            $nonce . "\n" .
            $body . "\n";
        return $message;
    }

    /**
     * createSign
     *
     * @param $message
     *
     * @return string
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function createSign($message)
    {
        if (!in_array('sha256WithRSAEncryption', openssl_get_md_methods(true))) {
            throw new WxPayException("当前PHP环境不支持SHA256withRSA！");
        }
        $res = file_get_contents($this->getApiKey());
        if (!openssl_sign($message, $sign, $res, 'sha256WithRSAEncryption')) {
            throw new WxPayException("创建签名失败！");
        }
        return base64_encode($sign);
    }

    /**
     * getBody
     *
     * @return false|string
     *
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function getBody()
    {
        return $this->values ? json_encode($this->values) : '';
    }

    /**
     * getSchema
     *
     * @return string
     *
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function getSchema()
    {
        return 'WECHATPAY2-SHA256-RSA2048';
    }

    /**
     * getNonceStr
     *
     * @param int $length
     *
     * @return string
     *
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v2&v3
     */
    public function getNonceStr(int $length = 32)
    {
        $chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

    /**
     * Decrypt AEAD_AES_256_GCM ciphertext
     *
     * @param string $associatedData AES GCM additional authentication data
     * @param string $nonceStr AES GCM nonce
     * @param string $ciphertext AES GCM cipher text
     *
     * @return string|bool      Decrypted string on success or FALSE on failure
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function decryptToString(string $associatedData, string $nonceStr, string $ciphertext)
    {
        $ciphertext = base64_decode($ciphertext);
        if (strlen($ciphertext) <= 16) {
            return false;
        }

        // ext-sodium (default installed on >= PHP 7.2)
        if (function_exists('sodium_crypto_aead_aes256gcm_is_available') &&
            sodium_crypto_aead_aes256gcm_is_available()) {
            return sodium_crypto_aead_aes256gcm_decrypt($ciphertext, $associatedData, $nonceStr, $this->pay_key);
        }

        // ext-libsodium (need install libsodium-php 1.x via pecl)
        if (function_exists('\Sodium\crypto_aead_aes256gcm_is_available') &&
            \Sodium\crypto_aead_aes256gcm_is_available()) {
            return \Sodium\crypto_aead_aes256gcm_decrypt($ciphertext, $associatedData, $nonceStr, $this->pay_key);
        }

        // openssl (PHP >= 7.1 support AEAD)
        if (PHP_VERSION_ID >= 70100 && in_array('aes-256-gcm', openssl_get_cipher_methods())) {
            $ctext = substr($ciphertext, 0, -16);
            $authTag = substr($ciphertext, -16);

            return openssl_decrypt($ctext, 'aes-256-gcm', $this->pay_key, OPENSSL_RAW_DATA, $nonceStr,
                $authTag, $associatedData);
        }
        throw new WxPayException("AEAD_AES_256_GCM需要PHP 7.1以上或者安装libsodium-php");
    }

    /**
     * Guzzle 中间件发送请求
     *
     * @param string $method
     * @param string $url
     * @param array $headers
     * @param array $body
     *
     * @return array|bool
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function send(string $method, string $url, array $headers, array $body = array())
    {
        // 商户相关配置
        $merchantId = $this->pay_mchid;
        $certificate = $this->readCert($this->pay_sslcert);
        $merchantSerialNumber = $this->getSerialNo($certificate);
        $merchantPrivateKey = PemUtil::loadPrivateKey($this->pay_sslkey);
        $wechatpayCertificate = PemUtil::loadCertificate($this->pay_sslcert);
        // 构造一个WechatPayMiddleware
        $wechatpayMiddleware = WechatPayMiddleware::builder()
            ->withMerchant($merchantId, $merchantSerialNumber, $merchantPrivateKey)// 传入商户相关配置
            ->withWechatPay([$wechatpayCertificate])// 可传入多个微信支付平台证书，参数类型为array
            ->build();

        // 将WechatPayMiddleware添加到Guzzle的HandlerStack中
        $stack = HandlerStack::create();
        $stack->push($wechatpayMiddleware, 'wechatpay');

        // 创建Guzzle HTTP Client时，将HandlerStack传入
        $client = new Client(['handler' => $stack]);

        // 接下来，正常使用Guzzle发起API请求，WechatPayMiddleware会自动地处理签名和验签
        try {
            switch (strtoupper($method)) {
                case 'GET':
                    $resp = $client->request('GET', $url, [ // 注意替换为实际URL
                        'headers' => $headers
                    ]);
                    break;
                case 'POST':
                    if (empty($body)) {
                        return false;
                    }
                    $resp = $client->request('POST', $url, [
                        'json' => $body,
                        'headers' => $headers
                    ]);
                    break;
                default:
                    throw new WxPayException('请求类型错误');
                    break;
            }

            return [
                'code' => $resp->getStatusCode(),
                'message' => $resp->getReasonPhrase(),
                'data' => $resp->getBody()
            ];
        } catch (RequestException $e) {
            return [
                'code' => $e->getResponse()->getStatusCode(),
                'message' => $e->getResponse()->getReasonPhrase(),
                'data' => $e->getResponse()->getBody()
            ];
        }
    }

    /**
     * 以post方式提交xml到对应的接口url
     *
     * @param $config
     * @param $xml  需要post的xml数据
     * @param $url
     * @param bool $useCert 是否需要证书，默认不需要
     * @param int $second url执行超时时间，默认30s
     *
     * @return bool|string
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v2
     */
    public function postXmlCurl($xml, $url, $useCert = false, $second = 30)
    {
        $ch = curl_init();
        $curlVersion = curl_version();
        $ua = "WXPaySDK/3.0.10 (" . PHP_OS . ") PHP/" . PHP_VERSION . " CURL/" . $curlVersion['version'] . " "
            . $this->pay_mchid;

        //设置超时
        curl_setopt($ch, CURLOPT_TIMEOUT, $second);

        $proxyHost = "0.0.0.0";
        $proxyPort = 0;
        $this->GetProxy($proxyHost, $proxyPort);
        //如果有配置代理这里就设置代理
        if ($proxyHost != "0.0.0.0" && $proxyPort != 0) {
            curl_setopt($ch, CURLOPT_PROXY, $proxyHost);
            curl_setopt($ch, CURLOPT_PROXYPORT, $proxyPort);
        }
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);//严格校验
        curl_setopt($ch, CURLOPT_USERAGENT, $ua);
        //设置header
        curl_setopt($ch, CURLOPT_HEADER, FALSE);
        //要求结果为字符串且输出到屏幕上
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);

        if ($useCert == true) {
            //设置证书
            //使用证书：cert 与 key 分别属于两个.pem文件
            //证书文件请放入服务器的非web目录下
            $sslCertPath = "";
            $sslKeyPath = "";
            $this->GetSSLCertPath($sslCertPath, $sslKeyPath);
            curl_setopt($ch, CURLOPT_SSLCERTTYPE, 'PEM');
            curl_setopt($ch, CURLOPT_SSLCERT, $sslCertPath);
            curl_setopt($ch, CURLOPT_SSLKEYTYPE, 'PEM');
            curl_setopt($ch, CURLOPT_SSLKEY, $sslKeyPath);
        }
        //post提交方式
        curl_setopt($ch, CURLOPT_POST, TRUE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $xml);
        //运行curl
        $data = curl_exec($ch);
        //返回结果
        if ($data) {
            curl_close($ch);
            return $data;
        } else {
            $error = curl_errno($ch);
            curl_close($ch);
            throw new WxPayException("curl出错，错误码:$error");
        }
    }

    /**
     * 设置商户证书路径
     * 证书路径,注意应该填写绝对路径（仅退款、撤销订单时需要，可登录商户平台下载
     * API证书下载地址：https://pay.weixin.qq.com/index.php/account/api_cert，下载之前需要安装商户操作证书）
     * 注意:
     * 1.证书文件不能放在web服务器虚拟目录，应放在有访问权限控制的目录中，防止被他人下载；
     * 2.建议将证书文件名改为复杂且不容易猜测的文件名；
     * 3.商户服务器要做好病毒和木马防护工作，不被非法侵入者窃取证书文件。
     *
     * @param $sslCertPath
     * @param $sslKeyPath
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v2
     */
    public function GetSSLCertPath(&$sslCertPath, &$sslKeyPath)
    {
        $sslCertPath = $this->pay_sslcert;
        $sslKeyPath = $this->pay_sslkey;
    }

    /**
     * 本例程通过curl使用HTTP POST方法，此处可修改代理服务器
     * 默认CURL_PROXY_HOST=0.0.0.0和CURL_PROXY_PORT=0，此时不开启代理（如有需要才设置）
     * 这里设置代理机器，只有需要代理的时候才设置，不需要代理，请设置为0.0.0.0和0
     *
     * @param $proxyHost
     * @param $proxyPort
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v2
     */
    public function GetProxy(&$proxyHost, &$proxyPort)
    {
        $proxyHost = "0.0.0.0";
        $proxyPort = 0;
    }

    /**
     * 输出xml字符
     * @throws WxPayException
     * @version v2
     **/
    public function ToXml()
    {
        if (!is_array($this->values) || count($this->values) <= 0) {
            throw new WxPayException("数组数据异常！");
        }

        $xml = "<xml>";
        foreach ($this->values as $key => $val) {
            if (is_numeric($val)) {
                $xml .= "<" . $key . ">" . $val . "</" . $key . ">";
            } else {
                $xml .= "<" . $key . "><![CDATA[" . $val . "]]></" . $key . ">";
            }
        }
        $xml .= "</xml>";
        return $xml;
    }

    /**
     * 将xml转为array
     *
     * @param $xml
     *
     * @return mixed
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v2
     */
    public function FromXml($xml)
    {
        if (!$xml) {
            throw new WxPayException("xml数据异常！");
        }
        //将XML转为array
        //禁止引用外部xml实体
        libxml_disable_entity_loader(true);
        $this->values = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
        return $this->values;
    }

    /**
     * 设置签名，详见签名生成算法类型
     * @param string $sign_type
     * @return string
     **/
    public function SetSignType(string $sign_type)
    {
        $this->values['sign_type'] = $sign_type;
        return $sign_type;
    }

    /**
     * 设置签名，详见签名生成算法
     * @return string
     **/
    public function SetSign()
    {
        $sign = $this->MakeSignMd5();
        $this->values['sign'] = $sign;
        return $sign;
    }

    /**
     * 获取签名，详见签名生成算法的值
     * @return string
     **/
    public function GetSign()
    {
        return $this->values['sign'];
    }

    /**
     * 判断签名，详见签名生成算法是否存在
     * @return true 或 false
     **/
    public function IsSignSet()
    {
        return array_key_exists('sign', $this->values);
    }

    /**
     * 生成签名
     *
     * @param bool $needSignType
     * @return string
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v2
     */
    public function MakeSignMd5(bool $needSignType = false)
    {
        if ($needSignType) {
            $this->SetSignType('MD5');
        }
        //签名步骤一：按字典序排序参数
        ksort($this->values);
        $string = $this->ToUrlParams();
        //签名步骤二：在string后加入KEY
        $string = $string . "&key=" . $this->pay_api_key;
        //签名步骤三：MD5加密
        $string = md5($string);
        //签名步骤四：所有字符转为大写
        $result = strtoupper($string);
        return $result;
    }

    /**
     * 格式化参数格式化成url参数
     *
     * @return string
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v2
     */
    public function ToUrlParams()
    {
        $buff = "";
        foreach ($this->values as $k => $v) {
            if ($k != "sign" && $v != "" && !is_array($v)) {
                $buff .= $k . "=" . $v . "&";
            }
        }

        $buff = trim($buff, "&");
        return $buff;
    }

    /**
     * 获取微信支付结果
     *
     * @param $xml
     * @return array
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v2
     */
    public function WxPayResults($xml)
    {
        $this->FromXml($xml);
        //失败则直接返回失败
        if ($this->values['return_code'] != 'SUCCESS') {
            foreach ($this->values as $key => $value) {
                #除了return_code和return_msg之外其他的参数存在，则报错
                if ($key != "return_code" && $key != "return_msg") {
                    throw new WxPayException("输入数据存在异常！");
                }
            }
            return $this->values;
        }
        $this->CheckSign();
        return $this->values;
    }

    /**
     * 检测签名
     *
     * @return bool
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v2
     */
    public function CheckSign()
    {
        if (!$this->IsSignSet()) {
            throw new WxPayException("签名错误！");
        }

        $sign = $this->MakeSignMd5();
        if ($this->GetSign() == $sign) {
            //签名正确
            return true;
        }
        throw new WxPayException("签名错误！");
    }
}