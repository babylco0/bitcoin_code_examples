# bitcoin_code_examples

Examples of bitcoin source

---
# testsha256.cpp

编译：

> g++ -o .\testsha256 .\testsha256.cpp -std=gnu++0x

运行：

> .\testsha256

结果：

> Data: 00154de7cabbb5822075e92c57a27ca3ef3e8be50c</br>
> SHA-256: ab7d579d497d75ab7e337212345635a4c071c249c6e8ec7532d2ea4d82290e6

---
# testhash256.cpp

编译:

> g++ -o .\testhash256 .\testhash256.cpp -std=gnu++0x

运行：

> .\testhash256

输出：

> Data: 00154de7cabbb5822075e92c57a27ca3ef3e8be50c</br>
> SHA-256 [1]: ab7d579d497d75ab7e337212345635a4c071c249c6e8ec7532d2ea4d82290e6</br>
> SHA-256 [2]: fc897c201ef5e99b2e37853e84dd041bebe6f831f462729de2af27e4ab9ea7e

---
# testbase58.cpp

编译:

> g++ -o .\testbase58 .\testbase58.cpp -std=gnu++0x

运行：

> .\testbase58

结果：

> Encode: 12weWzbq5jT7c3MHbHD2WP2uLXEUtaGLXZ</br>
> Decode: 00154de7cabbb5822075e92c57a27ca3ef3e8be50cfc897c20

---

# testbase58check

编译：

> g++ -o .\testbase58check .\testbase58check.cpp -std=gnu++0x

运行：

> .\testbase58check

结果：

> Encode: 12weWzbq5jT7c3MHbHD2WP2uLXEUtaGLXZ</br>
> Decode: 00154de7cabbb5822075e92c57a27ca3ef3e8be50c

---

# testripemd160.cpp

编译：

>  g++ -o .\testripemd160 .\testripemd160.cpp -std=gnu++0x

运行：

> .\testripemd160

结果:

> Data: 2b0995c0703c96d694f03a8987f89d387459fc359694737547a75764989c5e16</br>
> RIPEMD-160: 154de7cabbb5822075e92c57a27ca3ef3e8be5c

---



