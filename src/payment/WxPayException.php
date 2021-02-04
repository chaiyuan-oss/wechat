<?php


namespace wechat\payment;

/**
 *
 * 微信支付API异常类
 *
 * @author Chai Yuan(chaiyuan@laiyipiao.com)
 */
class WxPayException extends \Exception {
    public function errorMessage()
    {
        return $this->getMessage();
    }
}