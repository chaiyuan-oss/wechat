<?php

namespace wechat\payment;

use wechat\Config;

/**
 * 接口访问类，包含所有微信支付API（V3）列表的封装，类中方法为static方法
 * 每个接口有默认超时时间（除提交被扫支付为10s，上报超时时间为1s外，其他均为6s）
 *
 * @author Chai Yuan(chaiyuan@chaidada.cn)
 * @doc https://pay.weixin.qq.com/wiki/doc/apiv3/wxpay/pages/Overview.shtml
 * @package app\modules\api\components\payment
 * @data 2020-11-13
 */
class WxPayApi extends Config
{
    /**
     * 微信 jsApi 小程序下单
     *
     * @param string $description
     * @param string $out_trade_no
     * @param int $total
     * @param string $openId
     * @param string $notify_url
     * @param string $attach
     * @param bool $dev
     *
     * @return array
     *
     * @author Chai Yuan(chaiyuan@chaidada.cn)
     * @version v3
     * @throws WxPayException
     */
    public function jsApi(string $description,string $out_trade_no,int $total,string $openId,string $notify_url,string $attach='',bool $dev = false)
    {
        $input = new WxPayJsApi();
        $input->SetDescription($description);
        $input->SetOut_trade_no($out_trade_no);
        $input->SetTotal($total);
        if ($dev) {
            $input->SetTotal(1);
        }
        $input->SetNotify_url($notify_url);
        $input->SetOpenid($openId);
        $input->SetAttach($attach);
        $input->SetAppid($this->appid);
        $input->SetMch_id($this->pay_mchid);
        $url = $this->domain . $this->jsapi;
        $way = 'POST';
        //检测必填参数
        if ($input->IsOut_trade_noSet()) {
            throw new WxPayException("缺少统一支付接口必填参数out_trade_no！");
        } else if (!$input->IsDescriptionSet()) {
            throw new WxPayException("缺少统一支付接口必填参数description！");
        } else if (!$input->IsTotalSet()) {
            throw new WxPayException("缺少统一支付接口必填参数total！");
        } else if (!$input->IsOpenidSet()) {
            throw new WxPayException("缺少统一支付接口必填参数Openid！");
        }

        $headers = ['Accept' => 'application/json'];
        $res = $input->send($way, $url, $headers, $input->values);
        if (!$res) {
            throw new WxPayException("统一下单调用失败！");
        }
        $result = json_decode($res['data'], true);
        if (isset($result['prepay_id'])) {
            $timestamp = time();
            $nonce = $input->getNonceStr();
            $message = $this->appid . "\n" .
                $timestamp . "\n" .
                $nonce . "\n" .
                'prepay_id=' . $result['prepay_id'] . "\n";
            $sign = $input->createSign($message);
            $data = [
                'timeStamp' => $timestamp,
                'nonceStr' => $nonce,
                'package' => 'prepay_id=' . $result['prepay_id'],
                'signType' => 'RSA',
                'paySign' => $sign
            ];
            return $data;
        }
        if (isset($result['message'])) {
            throw new WxPayException($result['message']);
        }
        throw new WxPayException("统一下单调用失败！");
    }

    /**
     * 微信支付回调
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function notify()
    {
        $obj = new WxPayDataBase();
        $cert_path = $this->wechatpay;
        $result = $obj->validate($cert_path);
        if ($result === false) {
            throw new WxPayException("验证签名失败");
        }
        $postStr = file_get_contents('php://input');
        $postData = json_decode($postStr, true);
        if (isset($postData['resource']) && $postData['resource']) {
            $data = $obj->decryptToString($postData['resource']['associated_data'], $postData['resource']['nonce'], $postData['resource']['ciphertext']);
            $data = json_decode($data, true);
            $result = is_array($data) ? $data : false;
        } else {
            throw new WxPayException("解密失败");
        }
        if ($result === false) {
            throw new WxPayException("解密失败");
        }
        return $result;
    }

    /**
     * 查询订单（商户侧订单）
     *
     * @param string $out_trade_no
     *
     * @return array
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public  function query(string $out_trade_no)
    {
        $way = 'GET';
        $url = $this->domain . $this->query . $out_trade_no . '?mchid=' . $this->pay_mchid;
        $wx = new WxPayDataBase();
        $headers = ['Accept' => 'application/json'];
        $res = $wx->send($way, $url, $headers);
        if (!$res) {
            throw new WxPayException("查询订单失败");
        }
        if (!isset($res['code'])) {
            throw new WxPayException("查询订单失败");
        }
        $query_result = json_decode($res['data'], true);
        return $query_result;
    }

    /**
     * 关闭订单（商户侧）
     *
     * @param string $out_trade_no
     *
     * @return bool
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public  function close(string $out_trade_no)
    {
        //订单生成后不能马上调用关单接口，最短调用时间间隔为5分钟。
        $method = 'POST';
        $url = 'https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/' . $out_trade_no . '/close';
        $body = ['mchid' => $this->pay_mchid];
        $headers = ['Accept' => 'application/json'];
        $wx = new WxPayDataBase();
        $res = $wx->send($method, $url, $headers, $body);
        if ($res['code'] == 204) {
            return true;
        }
        return false;
    }

    /**
     * 获取微信公钥
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v3
     */
    public function certificate()
    {
        $url = 'https://api.mch.weixin.qq.com/v3/certificates';
        $method = 'GET';
        $headers = ['Accept' => 'application/json'];
        $wx = new WxPayDataBase();
        $res = $wx->send($method, $url, $headers);
        if (isset($res['code']) && $res['code'] == 200) {
            $data = json_decode($res['data'], true);
            $data = $data['data'][0];
            $wx = new WxPayDataBase();
            $nonce = $data['encrypt_certificate']['nonce'];
            $associated_data = $data['encrypt_certificate']['associated_data'];
            $ciphertext = $data['encrypt_certificate']['ciphertext'];
            $data = $wx->decryptToString($associated_data, $nonce, $ciphertext);
            file_put_contents($this->wechatpay, $data);
        }
    }

    /**
     * refund
     *
     * @param string $out_trade_no
     * @param int $total_fee
     * @param int $refund_fee
     * @param string $out_refund_no
     * @param bool $self
     *
     * @return mixed
     *
     * @throws WxPayException
     * @author Chai Yuan(chaiyuan@laiyipiao.com)
     * @version v2
     */
    public function refund(string $out_trade_no, int $total_fee, int $refund_fee, string $out_refund_no, $refund_desc, bool $self = false)
    {
        $url = 'https://api.mch.weixin.qq.com/secapi/pay/refund';
        $input = new WxPayRefund();
        $input->SetOut_trade_no($out_trade_no);
        $input->SetTotal_fee($total_fee);
        $input->SetRefund_fee($refund_fee);
        $input->SetOut_refund_no($out_refund_no);

        //检测必填参数
        if (!$input->IsOut_trade_noSet() && !$input->IsTransaction_idSet()) {
            throw new WxPayException("退款申请接口中，out_trade_no、transaction_id至少填一个！");
        } else if (!$input->IsOut_refund_noSet()) {
            throw new WxPayException("退款申请接口中，缺少必填参数out_refund_no！");
        } else if (!$input->IsTotal_feeSet()) {
            throw new WxPayException("退款申请接口中，缺少必填参数total_fee！");
        } else if (!$input->IsRefund_feeSet()) {
            throw new WxPayException("退款申请接口中，缺少必填参数refund_fee！");
        } else if (!$input->IsOp_user_idSet()) {
            //throw new WxPayException("退款申请接口中，缺少必填参数op_user_id！");
        }

        $input->SetAppid($this->appid);
        $input->SetMch_id($this->pay_mchid);
        $input->SetNonce_str($input->getNonceStr());

        $input->SetSign();
        $xml = $input->ToXml();
        $response = $input->postXmlCurl($xml, $url, true);
        $result = $input->WxPayResults($response);
        return $result;
    }
}