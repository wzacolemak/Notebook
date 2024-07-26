---
tags:
    - Web Sec
    - Java
comments: true
---
# Fastjson 反序列化漏洞


Fastjson 是阿里巴巴的开源 JSON 解析库，它可以解析 JSON 格式的字符串，支持将 Java Bean 序列化为 JSON 字符串，也可以从 JSON 字符串反序列化到 JavaBean，Fastjson不但性能好而且API非常简单易用，所以用户基数巨大，一旦爆出漏洞其影响对于使用了Fastjson的Web应用来说是毁灭性的。

## Fastjson 简介

主要序列化和反序列化方法

- JSON.toJSONString 将 Java 对象转换为 json 对象，序列化的过程。
- JSON.parseObject/JSON.parse 将 json 对象重新变回 Java 对象；反序列化的过程

=== "User"

    ```java
    public class user {
        public String username;
        public String password;

        public user(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
    ```
=== "Fastjson"

    ```java
    package cc.fastjson;

    import com.alibaba.fastjson.JSON;
    import com.alibaba.fastjson.serializer.SerializerFeature;

    public class Fastjson {
        public static void main(String[] args) {
            user user = new user("Bob", "123.com");

            //序列化方式--指定类和不指定类
            String json1 = JSON.toJSONString(user);
            System.out.println(json1);//{"password":"123.com","username":"Aur0ra.sec"}
            String json2 = JSON.toJSONString(user, SerializerFeature.WriteClassName);
            System.out.println(json2);//{"@type":"com.aur0ra.sec.fastjson.User","password":"123.com","username":"Aur0ra.sec"}



            //反序列化
            //默认解析为JSONObject
            System.out.println(JSON.parse(json1));      //{"password":"123.com","username":"Bob"}
            System.out.println(JSON.parse(json1).getClass().getName());    //com.alibaba.fastjson.JSONObject

            //依据序列化中的@type进行自动反序列化成目标对象类型
            System.out.println(JSON.parse(json2));      //com.aur0ra.sec.fastjson.user@24b1d79b
            System.out.println(JSON.parse(json2).getClass().getName()); //com.aur0ra.sec.fastjson.user

            //手动指定type，反序列化成目标对象类型
            System.out.println(JSON.parseObject(json1, user.class)); //com.aur0ra.sec.fastjson.user@68ceda24
            System.out.println(JSON.parseObject(json1, user.class).getClass().getName()); //com.aur0ra.sec.fastjson.user

        }
    }
    ```

一些值得注意的点：

1. `JSON.toJSONString`进行序列化时，可以设置将对象的类型也作为序列化的内容
2. 当对字符串进行反序列化操作时
    - 序列化字符串中有@type则会按照该类型进行反序列化操作
    - 没有@type默认返回JSONObject对象（一种字典类型数据存储）
    - 没有@type，但又想反序列化成指定的类对象时，需要通过`JSON.parseObject()`同时传入该类的class对象，才能反序列成指定的对象。
    -  `JSON.parse(jsonString)` 和 `JSON.parseObject(jsonString, Target.class)`，两者调用链一致
3. 反序列化的对象必须具有默认的无参构造器和get|set方法，反序列化的底层实现就是通过无参构造器和get .set方法进行的，具体检查逻辑在 `com.alibaba.fastjson.util.JavaBeanInfo.build()` 中。
4. 如果目标类中私有变量没有 setter 方法，但是在反序列化时仍想给这个变量赋值，则需要使用 `Feature.SupportNonPublicField` 参数。
5. fastjson 在为类属性寻找 get/set 方法时，调用函数 `com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer#smartMatch()` 会忽略名称中的 `_|-` , 1.2.36 版本及后续版本还可以支持同时使用 _ 和 - 进行组合混淆。
6. fastjson 在反序列化时，如果 Field 类型为 byte[]，将会调用`com.alibaba.fastjson.parser.JSONScanner#bytesValue` 进行 base64 解码

## 漏洞分析