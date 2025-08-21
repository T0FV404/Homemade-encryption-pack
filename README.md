TODO(也有可能一辈子不会动):
1. 处理TLS而不是直接清理掉
2. 加密IAT
3. 处理掉加壳器由于错误理解的无用代码

主要学习文章:
+ https://www.freebuf.com/articles/system/268177.html
+ https://bbs.kanxue.com/thread-250960.htm
+ https://bbs.kanxue.com/thread-251267.htm

代码写得很烂,原本写得不是很现代,让ai润色了一下顺便学习,结果吞了我的代码改了半天😡.
后续发现原来64位加壳器不能直接用`LoadLibraryExA()`加载32位dll,导致部分代码其实没什么用,但是懒得改了,就这样吧.
