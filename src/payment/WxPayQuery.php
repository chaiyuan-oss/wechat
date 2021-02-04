<?php


namespace wechat\payment;
/**
 *  微信支付查询对象类
 *
 * @author Chai Yuan(chaiyuan@laiyipiao.com)
 * @example
 * @global
 * @var
 * @version
 */
class WxPayQuery extends WxPayDataBase
{
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
}