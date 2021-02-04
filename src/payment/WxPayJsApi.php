<?php


namespace wechat\payment;
/**
 * JsApi 下单输入对象
 * @author Chai Yuan(chaiyuan@laiyipiao.com)
 * @package app\modules\api\components\payment
 * @data 2020-11-13
 */
class WxPayJsApi extends WxPayDataBase
{
    /**
     * 设置微信分配的公众账号ID
     * @param string $value
     **/
    public function SetAppid(string $value)
    {
        $this->values['appid'] = $value;
    }

    /**
     * 获取微信分配的公众账号ID的值
     * @return mixed
     */
    public function GetAppid()
    {
        return $this->values['appid'];
    }

    /**
     * 判断微信分配的公众账号ID是否存在
     * @return bool
     **/
    public function IsAppidSet()
    {
        return array_key_exists('appid', $this->values);
    }

    /**
     * 设置微信支付分配的商户号
     * @param string $value
     **/
    public function SetMch_id(string $value)
    {
        $this->values['mchid'] = $value;
    }

    /**
     * 获取微信支付分配的商户号的值
     * @return mixed
     **/
    public function GetMch_id()
    {
        return $this->values['mchid'];
    }

    /**
     * 判断微信支付分配的商户号是否存在
     * @return true 或 false
     **/
    public function IsMch_idSet()
    {
        return array_key_exists('mchid', $this->values);
    }

    /**
     * 设置商品描述
     * @param string $value
     **/
    public function SetDescription(string $value)
    {
        $this->values['description'] = $value;
    }

    /**
     * 获取商品描述
     * @return mixed
     **/
    public function GetDescription()
    {
        return $this->values['description'];
    }

    /**
     * 判断商品描述是否存在
     * @return bool
     **/
    public function IsDescriptionSet()
    {
        return array_key_exists('description', $this->values);
    }

    /**
     * 设置商户系统内部的订单号,32个字符内、可包含字母, 其他说明见商户订单号
     * @param string $value
     **/
    public function SetOut_trade_no(string $value)
    {
        $this->values['out_trade_no'] = $value;
    }

    /**
     * 获取商户系统内部的订单号,32个字符内、可包含字母, 其他说明见商户订单号的值
     * @return mixed
     **/
    public function GetOut_trade_no()
    {
        return $this->values['out_trade_no'];
    }

    /**
     * 判断商户系统内部的订单号,32个字符内、可包含字母, 其他说明见商户订单号是否存在
     * @return bool
     **/
    public function IsOut_trade_noSet()
    {
        $pattern = '/^[0-9a-z][1-32]$/';
        if (array_key_exists('out_trade_no', $this->values) && preg_match($pattern, $this->values['out_trade_no']) ? true : false) {
            return true;
        }
        return false;
    }

    /**
     * 设置订单总金额，只能为整数，详见支付金额
     * @param int $value
     **/
    public function SetTotal(int $value)
    {
        $this->values['amount']['total'] = $value;
    }

    /**
     * 获取订单总金额，只能为整数，详见支付金额的值
     * @return mixed
     **/
    public function GetTotal()
    {
        return $this->values['amount']['total'];
    }

    /**
     * 判断订单总金额，只能为整数，详见支付金额是否存在
     * @return bool
     **/
    public function IsTotalSet()
    {
        if (array_key_exists('total', $this->values['amount']) && is_int($this->values['amount']['total']) && $this->values['amount']['total'] > 0) {
            return true;
        }
        return false;
    }

    /**
     * 设置接收微信支付异步通知回调地址
     * @param string $value
     **/
    public function SetNotify_url(string $value)
    {
        $this->values['notify_url'] = $value;
    }

    /**
     * 获取接收微信支付异步通知回调地址的值
     * @return mixed
     **/
    public function GetNotify_url()
    {
        return $this->values['notify_url'];
    }

    /**
     * 判断接收微信支付异步通知回调地址是否存在
     * @return true 或 false
     **/
    public function IsNotify_urlSet()
    {
        return array_key_exists('notify_url', $this->values);
    }

    /**
     * 设置trade_type=JSAPI，此参数必传，用户在商户appid下的唯一标识。下单前需要调用【网页授权获取用户信息】接口获取到用户的Openid。
     * @param string $value
     **/
    public function SetOpenid(string $value)
    {
        $this->values['payer']['openid'] = $value;
    }

    /**
     * 获取trade_type=JSAPI，此参数必传，用户在商户appid下的唯一标识。下单前需要调用【网页授权获取用户信息】接口获取到用户的Openid。 的值
     * @return mixed
     **/
    public function GetOpenid()
    {
        return $this->values['payer']['openid'];
    }

    /**
     * 判断trade_type=JSAPI，此参数必传，用户在商户appid下的唯一标识。下单前需要调用【网页授权获取用户信息】接口获取到用户的Openid。 是否存在
     * @return true 或 false
     **/
    public function IsOpenidSet()
    {
        $pattern = '/^[-_a-zA-Z0-9]{1,128}$/';
        if (array_key_exists('openid', $this->values['payer']) && preg_match($pattern, $this->values['payer']['openid']) ? true : false) {
            return true;
        }
        return false;
    }

    public function SetAttach(string $value)
    {
        $this->values['attach'] = $value;
    }

    public function GetAttach()
    {
        return $this->values['attach'];
    }
}