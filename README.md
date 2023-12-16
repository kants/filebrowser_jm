# 介绍
>文件传输web服务器

# build
## frontend
>vue development 模式
```s
# .env.testing
# vite3 build --mode testing
npm run test
```

## backend
>生产模式
```go build -ldflags="-s -w" -o fileXtransfer.exe```

# 使用说明
-d {{天数}}
```
# -r 文件路径
# -p 端口
fileTransfer -r E:\ -p 1234
```