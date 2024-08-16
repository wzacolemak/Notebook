---
tags:
    - Web Sec
    - Java
comments: true
---
# 5 Java 内存马基础

内存马又名无文件马，指无文件落地的webshell；由于传统的webshell需要写入文件，难以逃避防篡改监控。为了与传统的防御手段对抗，衍生出了一种新型的内存WebShell技术，其核心思想用一句话概括，即：利用类加载或Agent机制在JavaEE、框架或中间件的API中动态注册一个可访问的后门。

内存马主要分为以下几种类型：

1. 动态注册 servlet/filter/listener（使用 servlet-api 的具体实现）
2. 动态注册 interceptor/controller（使用框架如 spring/struts2）
3. 动态注册使用职责链设计模式的中间件、框架的实现（例如 Tomcat 的 Pipeline & Valve，Grizzly 的 FilterChain & Filter 等等）
4. 使用 java agent 技术写入字节码

**Servlet API 动态注册机制**

Servlet、Listener、Filter 均由 `javax.servlet.ServletContext` 加载，Web容器读取配置信息对其进行初始化并向容器中注册。

Servlet 3.0 规范中提供了动态注册的方法，在 Web 容器初始化的时候（即建立ServletContext 对象的时候）进行动态注册。

## Filter 内存马

Filter 过滤器是 Servlet 规范中的一部分，，用于在请求到达 Servlet 之前或者响应返回客户端之前对请求和响应进行处理，通常被用来处理静态 web 资源、访问权限控制、记录日志等附加功能等等。

Filter的动态注册通常有如下几种方式：

1. 使用 ServletContext 的 `addFilter/createFilter` 方法注册；
2. 使用 ServletContextListener 的 `contextInitialized` 方法在服务器启动时注册；
3. 使用 ServletContainerInitializer 的 `onStartup` 方法在初始化时注册（非动态）。

=== "addFilter(String filterName, String className)"

    ```java
        /**
     * Adds the filter with the given name and class name to this servlet context.
     *
     * <p>
     * The registered filter may be further configured via the returned {@link FilterRegistration} object.
     *
     * <p>
     * The specified <tt>className</tt> will be loaded using the classloader associated with the application represented by
     * this ServletContext.
     *
     * <p>
     * If this ServletContext already contains a preliminary FilterRegistration for a filter with the given
     * <tt>filterName</tt>, it will be completed (by assigning the given <tt>className</tt> to it) and returned.
     *
     * <p>
     * This method supports resource injection if the class with the given <tt>className</tt> represents a Managed Bean. See
     * the Jakarta EE platform and CDI specifications for additional details about Managed Beans and resource injection.
     *
     * @param filterName the name of the filter
     * @param className the fully qualified class name of the filter
     *
     * @return a FilterRegistration object that may be used to further configure the registered filter, or <tt>null</tt> if
     * this ServletContext already contains a complete FilterRegistration for a filter with the given <tt>filterName</tt>
     *
     * @throws IllegalStateException if this ServletContext has already been initialized
     *
     * @throws IllegalArgumentException if <code>filterName</code> is null or an empty String
     *
     * @throws UnsupportedOperationException if this ServletContext was passed to the
     * {@link ServletContextListener#contextInitialized} method of a {@link ServletContextListener} that was neither
     * declared in <code>web.xml</code> or <code>web-fragment.xml</code>, nor annotated with
     * {@link jakarta.servlet.annotation.WebListener}
     *
     * @since Servlet 3.0
     */
    public FilterRegistration.Dynamic addFilter(String filterName, String className);
    ```

=== "addFilter(String filterName, Filter filter)"

    ```java
    /**
     * Registers the given filter instance with this ServletContext under the given <tt>filterName</tt>.
     *
     * <p>
     * The registered filter may be further configured via the returned {@link FilterRegistration} object.
     *
     * <p>
     * If this ServletContext already contains a preliminary FilterRegistration for a filter with the given
     * <tt>filterName</tt>, it will be completed (by assigning the class name of the given filter instance to it) and
     * returned.
     *
     * @param filterName the name of the filter
     * @param filter the filter instance to register
     *
     * @return a FilterRegistration object that may be used to further configure the given filter, or <tt>null</tt> if this
     * ServletContext already contains a complete FilterRegistration for a filter with the given <tt>filterName</tt> or if
     * the same filter instance has already been registered with this or another ServletContext in the same container
     *
     * @throws IllegalStateException if this ServletContext has already been initialized
     *
     * @throws IllegalArgumentException if <code>filterName</code> is null or an empty String
     *
     * @throws UnsupportedOperationException if this ServletContext was passed to the
     * {@link ServletContextListener#contextInitialized} method of a {@link ServletContextListener} that was neither
     * declared in <code>web.xml</code> or <code>web-fragment.xml</code>, nor annotated with
     * {@link jakarta.servlet.annotation.WebListener}
     *
     * @since Servlet 3.0
     */
    public FilterRegistration.Dynamic addFilter(String filterName, Filter filter);
    ```

=== "addFilter(String filterName, Class<? extends Filter> filterClass)"

    ```java
        /**
         * Adds the filter with the given name and class type to this servlet context.
         *
         * <p>
         * The registered filter may be further configured via the returned {@link FilterRegistration} object.
         *
         * <p>
         * If this ServletContext already contains a preliminary FilterRegistration for a filter with the given
         * <tt>filterName</tt>, it will be completed (by assigning the name of the given <tt>filterClass</tt> to it) and
         * returned.
         *
         * <p>
         * This method supports resource injection if the given <tt>filterClass</tt> represents a Managed Bean. See the Jakarta
         * EE platform and CDI specifications for additional details about Managed Beans and resource injection.
         *
         * @param filterName the name of the filter
         * @param filterClass the class object from which the filter will be instantiated
         *
         * @return a FilterRegistration object that may be used to further configure the registered filter, or <tt>null</tt> if
         * this ServletContext already contains a complete FilterRegistration for a filter with the given <tt>filterName</tt>
         *
         * @throws IllegalStateException if this ServletContext has already been initialized
         *
         * @throws IllegalArgumentException if <code>filterName</code> is null or an empty String
         *
         * @throws UnsupportedOperationException if this ServletContext was passed to the
         * {@link ServletContextListener#contextInitialized} method of a {@link ServletContextListener} that was neither
         * declared in <code>web.xml</code> or <code>web-fragment.xml</code>, nor annotated with
         * {@link jakarta.servlet.annotation.WebListener}
         *
         * @since Servlet 3.0
         */
        public FilterRegistration.Dynamic addFilter(String filterName, Class<? extends Filter> filterClass);
    ```

=== "createFilter(Class<T> clazz)"

    ```java
        /**
         * Instantiates the given Filter class.
         *
         * <p>
         * The returned Filter instance may be further customized before it is registered with this ServletContext via a call to
         * {@link #addFilter(String,Filter)}.
         *
         * <p>
         * The given Filter class must define a zero argument constructor, which is used to instantiate it.
         *
         * <p>
         * This method supports resource injection if the given <tt>clazz</tt> represents a Managed Bean. See the Jakarta EE
         * platform and CDI specifications for additional details about Managed Beans and resource injection.
         *
         * @param <T> the class of the Filter to create
         * @param clazz the Filter class to instantiate
         *
         * @return the new Filter instance
         *
         * @throws ServletException if the given <tt>clazz</tt> fails to be instantiated
         *
         * @throws UnsupportedOperationException if this ServletContext was passed to the
         * {@link ServletContextListener#contextInitialized} method of a {@link ServletContextListener} that was neither
         * declared in <code>web.xml</code> or <code>web-fragment.xml</code>, nor annotated with
         * {@link jakarta.servlet.annotation.WebListener}
         *
         * @since Servlet 3.0
         */
        public <T extends Filter> T createFilter(Class<T> clazz) throws ServletException;
    ```

!!! tips

    如果ServletContext传递给ServletContextListener的contextInitialized方法既没有在web.xml或web-fragment.xml中声明，也没有使用`jakarta.servlet.annotation.WebListener`注解，则会抛出`UnsupportedOperationException`异常。

ServletContext 中有三个`addFilter`重载方法，提供不同场景下添加 filter 的功能，这些方法均返回 `FilterRegistration.Dynamic` 实际上就是 FilterRegistration 对象。

`addFilter` 方法实际上就是动态添加 filter 的最核心和关键的方法

ServletContext 只负责提供接口，具体实现参考不同的容器实现，这里我们以Tomcat为例，相关实现方法在 `org.apache.catalina.core.ApplicationContext#addFilter` 中。

