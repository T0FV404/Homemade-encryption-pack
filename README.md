TODO(也有可能一辈子不会动):
1. 处理TLS而不是直接清理掉
2. 加密IAT
3. 处理掉加壳器由于错误理解的无用代码
4. 加上各类可以用来对抗逆向的方式

主要学习文章:
+ https://www.freebuf.com/articles/system/268177.html
+ https://bbs.kanxue.com/thread-250960.htm
+ https://bbs.kanxue.com/thread-251267.htm

代码写得很烂,我原本用某种神秘C with Class + 少部分 STL 实现的.但是为了学习现代C++,让AI润色了一下,结果直接加了一半了,所以实际上代码不是很精简(不过倒是学了一些用法,最可气的是AI吞了我部分代码,代码太长又懒得调,耗了快一天了).
后续发现原来64位加壳器不能直接用`LoadLibraryExA()`加载32位dll,导致部分代码其实没什么用,但是懒得改了,就这样吧,这部分代码占比也不大.
