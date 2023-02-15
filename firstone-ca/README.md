# CA证书服务

## 功能介绍

1. 根据提供的信息生成公私钥和签发单个证书，并保存证书和密钥（root密钥不作保存，只生成文件）。

2. 通过CSR文件签发单个证书，并保存证书。

3. 可以延期某个具体证书的有效期。

4. 可以通过证书链上的CA证书撤销某个证书。

5. 能够生成CA证书的最新的撤销列表文件（CRL文件）。

6. root证书可以选择配置或者自签生成。

7. 可以配置不同的启动方式，用来区分tls和sign证书的签发。

8. 可以签发单独使用的tls加密或者签名证书（国密标准，tls双证书）。

9. 可以配置中间证书启动，保护root证书。

10. 提供开启密钥文件加密功能。

    

<span id="deploy"></span>

## 安装部署

### 环境依赖

* golang
  * 版本为1.16或以上
  * 下载地址：https://golang.org/dl/

### 代码下载

```sh
$ git clone https://git.chainmaker.org.cn/chainmaker/chainmaker-ca.git
```

### 运行启动

#### 修改mysql数据库连接配置

```shell
$ cd src/conf/

$ vi config.yaml  # 配置mysql数据库，打开config.yaml，修改db_config
```

#### 部署启动

- 方式一：

  **准备并启动mysql数据库**

  mysql

  * 版本8.0及以上
  * 下载地址：https://dev.mysql.com/downloads/installer/

  

  **编译chainmaker-ca程序**

  ```shell
  $ cd src/
  $ go build -o chainmaker-ca
  ```

  

  **启动程序**

  ```shell
  $ cd src/
  $ ./chainmaker-ca -config ./conf/config.yaml
  ```

  

- 方式二：

  **准备docker基础镜像**

  mysql: 8.0, golang:1.16.2, centos:7.6.1810

  

  **启动docker容器脚本**

  ```shel
  $ sh deploy.sh
  ```

  

## 配置文件详解

目录：```src/conf/config.yaml```

配置文件主要是以下几部分构成：

### base config

CA服务的基础配置

```yaml
# Base config
base_config:
  server_port: 8090                     #服务端口
  ca_type: single_root                  #启动模式：double_root/single_root/tls/sign
  expire_year: 2                        #签发有效年限
  expire_month: 6                       #签发有效月份（优先级高于年限）
  hash_type: SHA256                     #使用哈希类型：SHA256/SHA3_256/SM3
  key_type: ECC_NISTP256                #使用密钥类型：ECC_NISTP256/SM2/RSA2048
  can_issue_ca: true                    #是否能继续签发CA证书          
  provide_service_for: [org1,org2]      #提供服务的组织列表(若不配置，则不限制组织)   
  key_encrypt: false                    #密钥是否加密 
  access_control: true                  #是否开启访问控制
  default_domain: chainmaker.org        #证书里的域名(如果不开启配置，则不会填写)
```

***注**

* SM2和SM3必须要搭配使用



* **ca_type:**

  CA启动模式，可以将tls和sign证书签发服务分离部署。

  - tls，该服务只提供为tls证书的签发服务。

  - sign，该服务只提供sign证书的签发服务。

  - single_root，可以为tls和sign证书同时提供签发服务，使用一个root CA证书。

  - double_root，可以为tls和sign证书同时提供签发服务，使用两个root CA证书。

* **can_issue_ca:**

  在所提供服务的组织内，是否能够签发中间CA证书。

* **provide_service_for:**

  对列表中的组织提供签发服务。可以仅配置一个组织，只为单个提供服务。也可以配置多个，向多个组织提供签发服务。如果不配置，则为任何组织服务。

* **key_encrypt:**

  提供密钥文件加密的开关。如果开启，密钥会采用PEMCipherAES256加密方式，加密密钥文件。（root密钥不存储，也不加密）

* **access_control:**

  访问控制开关，如果开启，访问将服务的所有接口需要携带token访问。

### root config

root 证书的路径和CSR配置

```yaml
# Root CA config
root_config:
  cert:
    -
      cert_type: tls                                             #root证书的类型：tls/sign
      cert_path: ../crypto-config/rootCA/tls/root-tls.crt        #证书的路径     
      private_key_path: ../crypto-config/rootCA/tls/root-tls.key #密钥的路径  
      key_id: SM2TlsKey261                                      #密码机pkcs11 key id
    -
      cert_type: sign
      cert_path: ../crypto-config/rootCA/sign/root-sign.crt               
      private_key_path: ../crypto-config/rootCA/sign/root-sign.key
      key_id: SM2SignKey262
  csr:
    CN: root.org-wx                                              #证书的信息的CN字段
    O: org-wx                                                    #证书的信息的O字段
    OU: root                                                     #证书的信息的OU字段
    country: CN                                                  #证书的信息的country字段
    locality: Beijing                                            #证书的信息的locality字段
    province: Beijing                                            #证书的信息的province字段
```

* **cert_type:**

  证书的路径类型，如果CA的启动方式是double_root，需要同时配置tls和sign两种类型的证书路径。如果CA启动方式是single_root，需要配置sign类型的证书路径。

* **csr（选填）:**

  * 不填：读取cert目录下的root证书启动服务。

  * 填写：以CSR配置自签root证书启动服务。

  其中，OU字段需要符合chainmaker的证书校验规范，否则链上会校验失败。需要填写root。

### intermediate_config

**可选配置**

中间CA的生成配置

```yaml
# intermediate config
intermediate_config:                 
  -
    csr:
      CN: ca.org1
      O: org1
      OU: ca
      country: CN
      locality: Beijing
      province: Beijing
    key_id: SM2TlsKey261
  -
    csr:
      CN: ca.org2
      O: org2
      OU: ca
      country: CN
      locality: Beijing
      province: Beijing
    key_id: SM2TlsKey262
```

### access_control_config

**可选配置**

访问控制账号配置

```yaml
access_control_config:
  -
    app_role: admin            #角色
    app_id: admin              #账户ID
    app_key: passw0rd          #账户口令
  - 
    app_role: user
    app_id: user1
    app_key: passw0rd
```

* **app_role**  
  * admin : 所有权限
  * user ：不能进行吊销、延期证书。只能申请，查询证书。

### database config（MySQL）

数据库信息配置

```yaml
db_config:
  user: root                   #用户名
  password: 123456             #密码
  ip: 127.0.0.1                #数据库服务器的IP地址
  port: 3306                   #数据库服务器的端口号
  dbname: chainmaker_ca        #建立的数据库的名称
```

### log config

日志相关配置

```yaml
log_config: 
  level: error               #日志等级
  filename: ../log/ca.log    #日志存取路径
  max_size: 1                #在进行切割之前，日志文件的最大大小（以MB为单位）
  max_age: 30                #保留旧文件的最大天数
  max_backups: 5             #保留旧文件的最大个数
```

### pkcs11 config

硬件机密机相关配置

```yaml
pkcs11_config:
  enabled: false                                   # pkcs11硬件加密开关。
  library: /usr/local/lib64/pkcs11/libupkcs11.so   # pkcs11连接库地址。
  label: HSM                                       # slot 标签
  password: 11111111                               # HSM token登录密码
  session_cache_size: 10                           # session 缓存大小
  hash: "SHA256"                                   # 哈希算法
```



## 可部署方式

![CA-deployment.png](./img/CA-deployment.png)

### 配置文件的使用

**集中式1：**

1. 属于集中式部署，为多个组织提供服务，base_config.provide_service_for需要配置多个组织。

2. 启用多个中间CA，intermediate_config需要配置多个。

3. 不允许继续签发中间CA证书，base_config.can_issue_ca为false。

**集中式2：**

1. 属于集中式部署，为多个组织提供服务，base_config.provide_service_for需要配置多个组织。

2. 启用单个中间CA证书，intermediate_config需要配置一个。

3. 不允许继续签发中间CA证书，base_config.can_issue_ca为false。

**分布式1：**

属于分布式和集中混合部署方式

* 集中式部分

1. 为多个组织提供服务，base_config.provide_service_for需要配置多个组织。

2. 没有启用配置中间CA证书，intermediate_config不需要配置。

3. 允许继续签发中间CA证书，base_config.can_issue_ca为ture。

* 分布式部分：

1. 为一个组织提供服务，base_config.provide_service_for需要配置单个组织。

2. root证书选择配置启动，root_config.csr部分不需要配置。

3. 没有启用配置中间CA证书，intermediate_config不需要配置。

4. 不允许继续签发中间CA证书，base_config.can_issue_ca为false。

**分布式2：**

1. 属于分布式部署，为单个组织提供服务，base_config.provide_service_for只需要配置一个组织。

2. 启用配置一个中间CA证书，intermediate_config需要配置一个。

3. 不允许继续签发中间CA证书，base_config.can_issue_ca为false。



## 服务接口

### Code与Msg

| Code |                     Msg                     |     含义     |
| :--: | :-----------------------------------------: | :----------: |
| 200  |  The request service returned successfully  |     成功     |
| 202  |         Missing required parameters         | 输入参数缺失 |
| 204  |  There is an error in the input parameter   | 输入参数非法 |
| 500  | An error occurred with the internal service | 执行服务失败 |

### 传参方式

统一为request body JSON的形式。

### 登录获取token接口

请求地址：http://localhost:8090/api/ca/login

请求方式：POST

请求参数：

|  字段  |  类型  |   含义   | 备注 |
| :----: | :----: | :------: | :--: |
| appId  | string |  登录id  | 必填 |
| appKey | string | 登录口令 | 必填 |

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": {
        "accessToken": "1111111",
        "expiressIn": 7200
    }
}
```

|    字段     |  类型  |      含义      |
| :---------: | :----: | :------------: |
| accessToken | string |    token值     |
| expiressIn  | number | 过期时间（秒） |

<span id="apply_cert"></span>

### 申请证书

从创建密钥对到证书，一步完成。

请求URL：http://localhost:8090/api/ca/gencert

请求方式：POST

请求参数：

|     字段      |  类型  |       含义       | 备注  |
| :-----------: | :----: | :--------------: | :---: |
|     orgId     | string |      组织ID      | 必填  |
|    userId     | string |      用户ID      | *选填 |
|   userType    | string |     用户类型     | 必填  |
|   certUsage   | string |     证书用途     | 必填  |
| privateKeyPwd | string |     密钥密码     | 选填  |
|    country    | string | 证书字段（国家） | 必填  |
|   locality    | string | 证书字段（城市） | 必填  |
|   province    | string | 证书字段（省份） | 必填  |
|     token     | string |      token       | 选填  |

* userType: 1.root , 2.ca , 3.admin , 4.client , 5.consensus , 6.common

* certUsage: 1.sign , 2.tls , 3.tls-sign , 4.tls-enc

*注：

* userId 只有在申请的用户类型是ca的类型时，可以填写为空。在申请节点证书时，需要保证链上节点ID唯一。

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": {
        "certSn": 4523845175273844671,
        "issueCertSn": 1146073575643658842,
        "cert": "-----BEGIN CERTIFICATE-----\nMIIChjCCAiugAwIBAgIIPsftN/MP778wCgYIKoZIzj0EAwIwgYMxCzAJBgNVBAYT\nAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAwDgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQK\nExZ3eC1vcmcxLmNoYWlubWFrZXIub3JnMQswCQYDVQQLEwJjYTEiMCAGA1UEAxMZ\nY2Etd3gtb3JnMS5jaGFpbm1ha2VyLm9yZzAeFw0yMjAzMTgwOTI0MjdaFw0yMjA5\nMTQwOTI0MjdaMGkxCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlKaW5nMRAwDgYD\nVQQHEwdCZWlKaW5nMQ0wCwYDVQQKEwRvcmcxMRIwEAYDVQQLEwljb25zZW5zdXMx\nEzARBgNVBAMTCmNvbnNlbnN1czEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ6\nRB+oQkJscRI1emYcYGMHx1AU/f9bkMOuqSdNspv6LjvdEftlBOVO7mazi5J4Ve8l\nHb65jLfnG6fBMZ7a0v5Vo4GhMIGeMA4GA1UdDwEB/wQEAwID+DAdBgNVHSUEFjAU\nBggrBgEFBQcDAgYIKwYBBQUHAwEwKQYDVR0OBCIEIGUw1TBs0Tw0Ud3HH/80neNM\nBhFcJ4u2vlzMd59943M6MCsGA1UdIwQkMCKAIFtql8AWsUPDhPN5EOpjhLf1Jrev\nUez0a7h0I3J3OrBgMBUGA1UdEQQOMAyCCmNvbnNlbnN1czEwCgYIKoZIzj0EAwID\nSQAwRgIhAPs+jzEu9H177kgyb3iFYM/LuIHNUaIsLnUAKZq9jW3NAiEA9iGP1sg3\nUXWIFW7mpRwzzakdJPkz8l+4ZPzV2nzEOjI=\n-----END CERTIFICATE-----\n",
        "privateKey": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIL2vmKiNl3hymnVvjkD3f9xrGAmvJCZEkGD4VwueObaPoAoGCCqGSM49\nAwEHoUQDQgAEOkQfqEJCbHESNXpmHGBjB8dQFP3/W5DDrqknTbKb+i473RH7ZQTl\nTu5ms4uSeFXvJR2+uYy35xunwTGe2tL+VQ==\n-----END EC PRIVATE KEY-----\n"
    }
}
```

| 字段        | 类型   | 含义         | 备注 |
| ----------- | ------ | ------------ | ---- |
| cert        | string | 证书内容     |      |
| privateKey  | string | 密钥内容     |      |
| certSn      | number | 证书序列号   |      |
| issueCertSn | number | CA证书序列号 |      |



### 申请CSR

请求URL： http://localhost:8090/api/ca/gencsr

请求方式：POST

请求参数：

|     字段      |  类型  |       含义       | 备注  |
| :-----------: | :----: | :--------------: | :---: |
|     orgId     | string |      组织ID      | 必填  |
|    userId     | string |      用户ID      | *选填 |
|   userType    | string |     用户类型     | 必填  |
| privateKeyPwd | string |     密钥密码     | 选填  |
|    country    | string | 证书字段（国家） | 必填  |
|   locality    | string | 证书字段（城市） | 必填  |
|   province    | string | 证书字段（省份） | 必填  |
|     token     | string |      token       | *选填 |

* userType: 1.root , 2.ca , 3.admin , 4.client , 5.consensus , 6.common

*注：

* userId 只有在申请的用户类型是ca的类型时，可以填写为空。在申请节点证书时，需要保证链上节点ID唯一。

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": "-----BEGIN CERTIFICATE REQUEST-----\nMIIBHjCBxQIBADBjMQ4wDAYDVQQGEwVjaGluYTEQMA4GA1UECBMHYmVpamluZzEQ\nMA4GA1UEBxMHaGFpZGlhbjENMAsGA1UEChMEb3JnNzEOMAwGA1UECxMFYWRtaW4x\nDjAMBgNVBAMTBXVzZXIyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaRv9OA2Z\nm/GcJibe/77u8lpABOLOVGgHzAzOd/h+9+Kq4+46CjXaISxEeTrqEMhLKCjcM1Bb\nm8jF5rWiQCFKFaAAMAoGCCqGSM49BAMCA0gAMEUCIFYjsphgIcInLjdhyYtILnFR\nJH7T/vahNbut8OvEgQ9tAiEAsNxL8xw+hGfhd9NgrxEx3Fv9Vj6wv1X3jaHvljME\n76U=\n-----END CERTIFICATE REQUEST-----\n"
}
```

### 通过CSR申请证书

请求URL：http://localhost:8090/api/ca/gencertbycsr

请求方式：POST

请求参数：

|   字段    |  类型  |   含义    | 备注  |
| :-------: | :----: | :-------: | :---: |
|   orgId   | string |  组织ID   | 必填  |
|  userId   | string |  用户ID   | *选填 |
| userType  | string | 用户类型  | 必填  |
| certUsage | string | 证书用途  | 必填  |
|    csr    | string | csr文件流 | 必填  |
|   token   | string |   token   | 选填  |

* userType: 1.root , 2.ca , 3.admin , 4.client , 5.consensus , 6.common
* certUsage: 1.sign , 2.tls , 3.tls-sign , 4.tls-enc

*注：

* userId 只有在申请的用户类型是ca的类型时，可以填写为空。在申请节点证书时，需要保证链上节点ID唯一。

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": {
        "certSn": 1752004958408437983,
        "issueCertSn": 1146073575643658842,
        "cert": "-----BEGIN CERTIFICATE-----\nMIIChDCCAiugAwIBAgIIGFBfOiaocN8wCgYIKoZIzj0EAwIwgYMxCzAJBgNVBAYT\nAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAwDgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQK\nExZ3eC1vcmcxLmNoYWlubWFrZXIub3JnMQswCQYDVQQLEwJjYTEiMCAGA1UEAxMZ\nY2Etd3gtb3JnMS5jaGFpbm1ha2VyLm9yZzAeFw0yMjAzMTgwOTMzNDZaFw0yMjA5\nMTQwOTMzNDZaMGkxCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlKaW5nMRAwDgYD\nVQQHEwdCZWlKaW5nMQ0wCwYDVQQKEwRvcmcyMRIwEAYDVQQLEwljb25zZW5zdXMx\nEzARBgNVBAMTCmNvbnNlbnN1czIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASi\ntzITs9l/4UpGCXzEbdlC+PhvxY/vjE/7HpGR7fdFshFEZM2sk4xVTA+b2LsIv0sf\nkverCTMdZVG3SwymTMlFo4GhMIGeMA4GA1UdDwEB/wQEAwID+DAdBgNVHSUEFjAU\nBggrBgEFBQcDAgYIKwYBBQUHAwEwKQYDVR0OBCIEIHJE5sXl09uw/aXHEm94uNt/\nf9/uJ6yWQv06UWioE0bMMCsGA1UdIwQkMCKAIFtql8AWsUPDhPN5EOpjhLf1Jrev\nUez0a7h0I3J3OrBgMBUGA1UdEQQOMAyCCmNvbnNlbnN1czIwCgYIKoZIzj0EAwID\nRwAwRAIgQyvmQDV4WYUnDRmI8vkm5pXwxvACscJ5pCqjT60SFsUCIDkEK+uURJBJ\ndnzPNSF8HWcMBiNKbWeSZtZ3EtPWlyHp\n-----END CERTIFICATE-----\n"
    }
}
```

| 字段        | 类型   | 含义         | 备注 |
| ----------- | ------ | ------------ | ---- |
| cert        | string | 证书内容     |      |
| certSn      | number | 证书序列号   |      |
| issueCertSn | number | CA证书序列号 |      |

<span id="query_cert"></span>

### 多条件查询证书

请求URL：http://localhost:8090/api/ca/querycerts

请求方式：POST

请求参数：

|   字段    |  类型  |    含义    | 备注 |
| :-------: | :----: | :--------: | :--: |
|   orgId   | string |   组织ID   | 选填 |
|  userId   | string |   用户ID   | 选填 |
| userType  | string |  用户类型  | 选填 |
| certUsage | string |  证书用途  | 选填 |
|  certSn   | number | 证书序列号 | 选填 |
|   token   | string |   token    | 选填 |

* userType: 1.root , 2.ca , 3.admin , 4.client , 5.consensus , 6.common
* certUsage: 1.sign , 2.tls , 3.tls-sign , 4.tls-enc

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": [
        {
            "userId": "consensus1",
            "orgId": "org1",
            "userType": "consensus",
            "certUsage": "tls",
            "certSn": 4523845175273844671,
            "issuerSn": 1146073575643658842,
            "certContent": "-----BEGIN CERTIFICATE-----\nMIIChjCCAiugAwIBAgIIPsftN/MP778wCgYIKoZIzj0EAwIwgYMxCzAJBgNVBAYT\nAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAwDgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQK\nExZ3eC1vcmcxLmNoYWlubWFrZXIub3JnMQswCQYDVQQLEwJjYTEiMCAGA1UEAxMZ\nY2Etd3gtb3JnMS5jaGFpbm1ha2VyLm9yZzAeFw0yMjAzMTgwOTI0MjdaFw0yMjA5\nMTQwOTI0MjdaMGkxCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlKaW5nMRAwDgYD\nVQQHEwdCZWlKaW5nMQ0wCwYDVQQKEwRvcmcxMRIwEAYDVQQLEwljb25zZW5zdXMx\nEzARBgNVBAMTCmNvbnNlbnN1czEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ6\nRB+oQkJscRI1emYcYGMHx1AU/f9bkMOuqSdNspv6LjvdEftlBOVO7mazi5J4Ve8l\nHb65jLfnG6fBMZ7a0v5Vo4GhMIGeMA4GA1UdDwEB/wQEAwID+DAdBgNVHSUEFjAU\nBggrBgEFBQcDAgYIKwYBBQUHAwEwKQYDVR0OBCIEIGUw1TBs0Tw0Ud3HH/80neNM\nBhFcJ4u2vlzMd59943M6MCsGA1UdIwQkMCKAIFtql8AWsUPDhPN5EOpjhLf1Jrev\nUez0a7h0I3J3OrBgMBUGA1UdEQQOMAyCCmNvbnNlbnN1czEwCgYIKoZIzj0EAwID\nSQAwRgIhAPs+jzEu9H177kgyb3iFYM/LuIHNUaIsLnUAKZq9jW3NAiEA9iGP1sg3\nUXWIFW7mpRwzzakdJPkz8l+4ZPzV2nzEOjI=\n-----END CERTIFICATE-----\n",
            "expirationDate": 1663147467,
            "isRevoked": false
        },
        {
            "userId": "consensus2",
            "orgId": "org2",
            "userType": "consensus",
            "certUsage": "tls",
            "certSn": 1752004958408437983,
            "issuerSn": 1146073575643658842,
            "certContent": "-----BEGIN CERTIFICATE-----\nMIIChDCCAiugAwIBAgIIGFBfOiaocN8wCgYIKoZIzj0EAwIwgYMxCzAJBgNVBAYT\nAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAwDgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQK\nExZ3eC1vcmcxLmNoYWlubWFrZXIub3JnMQswCQYDVQQLEwJjYTEiMCAGA1UEAxMZ\nY2Etd3gtb3JnMS5jaGFpbm1ha2VyLm9yZzAeFw0yMjAzMTgwOTMzNDZaFw0yMjA5\nMTQwOTMzNDZaMGkxCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlKaW5nMRAwDgYD\nVQQHEwdCZWlKaW5nMQ0wCwYDVQQKEwRvcmcyMRIwEAYDVQQLEwljb25zZW5zdXMx\nEzARBgNVBAMTCmNvbnNlbnN1czIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASi\ntzITs9l/4UpGCXzEbdlC+PhvxY/vjE/7HpGR7fdFshFEZM2sk4xVTA+b2LsIv0sf\nkverCTMdZVG3SwymTMlFo4GhMIGeMA4GA1UdDwEB/wQEAwID+DAdBgNVHSUEFjAU\nBggrBgEFBQcDAgYIKwYBBQUHAwEwKQYDVR0OBCIEIHJE5sXl09uw/aXHEm94uNt/\nf9/uJ6yWQv06UWioE0bMMCsGA1UdIwQkMCKAIFtql8AWsUPDhPN5EOpjhLf1Jrev\nUez0a7h0I3J3OrBgMBUGA1UdEQQOMAyCCmNvbnNlbnN1czIwCgYIKoZIzj0EAwID\nRwAwRAIgQyvmQDV4WYUnDRmI8vkm5pXwxvACscJ5pCqjT60SFsUCIDkEK+uURJBJ\ndnzPNSF8HWcMBiNKbWeSZtZ3EtPWlyHp\n-----END CERTIFICATE-----\n",
            "expirationDate": 1663148026,
            "isRevoked": false
        }
    ]
}
```

|      字段      |  类型   |       含义       |    备注    |
| :------------: | :-----: | :--------------: | :--------: |
|     certSn     | number  |    证书序列号    |            |
|    issuerSn    | number  | 签发者证书序列号 |            |
|  certContent   | string  |     证书内容     |            |
|     userId     | string  |      用户ID      |            |
|     orgId      | string  |      组织ID      |            |
|    userType    | string  |     用户类型     |            |
|   certUsage    | string  |     证书用途     |            |
| expirationDate | number  |     到期时间     | unix时间戳 |
|   isRevoked    | boolean |    是否被撤销    |            |

### 延期证书

请求URL：http://localhost:8090/api/ca/renewcert

请求方式：POST

请求参数：

|  字段  |  类型  |    含义    | 备注 |
| :----: | :----: | :--------: | :--: |
| certSn | number | 证书序列号 | 必填 |
| token  | string |   token    | 选填 |

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": {
        "certSn": 1752004958408437983,
        "issueCertSn": 1146073575643658842,
        "cert": "-----BEGIN CERTIFICATE-----\nMIIChTCCAiugAwIBAgIIGFBfOiaocN8wCgYIKoZIzj0EAwIwgYMxCzAJBgNVBAYT\nAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAwDgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQK\nExZ3eC1vcmcxLmNoYWlubWFrZXIub3JnMQswCQYDVQQLEwJjYTEiMCAGA1UEAxMZ\nY2Etd3gtb3JnMS5jaGFpbm1ha2VyLm9yZzAeFw0yMjAzMTgwOTMzNDZaFw0yMzAz\nMTMwOTMzNDZaMGkxCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlKaW5nMRAwDgYD\nVQQHEwdCZWlKaW5nMQ0wCwYDVQQKEwRvcmcyMRIwEAYDVQQLEwljb25zZW5zdXMx\nEzARBgNVBAMTCmNvbnNlbnN1czIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASi\ntzITs9l/4UpGCXzEbdlC+PhvxY/vjE/7HpGR7fdFshFEZM2sk4xVTA+b2LsIv0sf\nkverCTMdZVG3SwymTMlFo4GhMIGeMA4GA1UdDwEB/wQEAwID+DAdBgNVHSUEFjAU\nBggrBgEFBQcDAgYIKwYBBQUHAwEwKQYDVR0OBCIEIHJE5sXl09uw/aXHEm94uNt/\nf9/uJ6yWQv06UWioE0bMMCsGA1UdIwQkMCKAIFtql8AWsUPDhPN5EOpjhLf1Jrev\nUez0a7h0I3J3OrBgMBUGA1UdEQQOMAyCCmNvbnNlbnN1czIwCgYIKoZIzj0EAwID\nSAAwRQIhAOdDmyl0xI3cAxahOXc5pe8RYvl4OquK8jco0E+eqU+LAiBlxgWg1CqW\nk4a1oJF+LK/e1cUXnctf/6NqJLycIElwkA==\n-----END CERTIFICATE-----\n"
    }
}
```

### 撤销证书

请求URL：http://localhost:8090/api/ca/revokecert

请求方式：POST

请求参数：

|     字段      |  类型  |          含义          | 备注 |
| :-----------: | :----: | :--------------------: | :--: |
| revokedCertSn | number |       证书序列号       | 必填 |
| issuerCertSn  | number | 撤销者（ca）证书序列号 | 必填 |
|    reason     | string |        撤销原因        | 选填 |
|     token     | string |         token          | 选填 |

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": "-----BEGIN CRL-----\nMIIBNTCB3AIBATAKBggqhkjOPQQDAjBfMQswCQYDVQQGEwJDTjEQMA4GA1UECBMH\nQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzENMAsGA1UEChMEb3JnMTELMAkGA1UE\nCxMCY2ExEDAOBgNVBAMTB2NhLm9yZzgXDTIxMDYxMTA5NTQ0M1oXDTIxMDYxMTEw\nNTQ0M1owGzAZAggdEyilMlypBhcNMjMwNjExMDkxODA2WqAvMC0wKwYDVR0jBCQw\nIoAgyQvrO7BQev3fQxYIUIroQcF7HbmWFM/A7Ko2Etu9hCMwCgYIKoZIzj0EAwID\nSAAwRQIgFslGwq9Bb9a4wrOSatqRwRu9E0QMmCavrgr6GQRn5fcCIQDCV8mAepI9\nDLEbHtDHqzJ/CrGcRMJWL3gYzBNhWE/yLQ==\n-----END CRL-----\n"
}
```

### 获取某个CA的最新的撤销列表

请求URL：http://localhost:8090/api/ca/gencrl

请求方式：POST

请求参数：

|     字段     |  类型  |     含义     | 备注 |
| :----------: | :----: | :----------: | :--: |
| issuerCertSn | number | CA证书序列号 | 必填 |
|    token     | string |    token     | 选填 |

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": "-----BEGIN CRL-----\nMIIBNTCB3AIBATAKBggqhkjOPQQDAjBfMQswCQYDVQQGEwJDTjEQMA4GA1UECBMH\nQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzENMAsGA1UEChMEb3JnMTELMAkGA1UE\nCxMCY2ExEDAOBgNVBAMTB2NhLm9yZzgXDTIxMDYxMTA5NTQ0M1oXDTIxMDYxMTEw\nNTQ0M1owGzAZAggdEyilMlypBhcNMjMwNjExMDkxODA2WqAvMC0wKwYDVR0jBCQw\nIoAgyQvrO7BQev3fQxYIUIroQcF7HbmWFM/A7Ko2Etu9hCMwCgYIKoZIzj0EAwID\nSAAwRQIgFslGwq9Bb9a4wrOSatqRwRu9E0QMmCavrgr6GQRn5fcCIQDCV8mAepI9\nDLEbHtDHqzJ/CrGcRMJWL3gYzBNhWE/yLQ==\n-----END CRL-----\n"
}
```

<span id="get_nodeId"></span>

### 获取节点TLS证书的NodeID

请求URL：http://localhost:8090/api/ca/getnodeid

请求方式：POST

请求参数：

|   字段    |  类型  |    含义    |       备注       |
| :-------: | :----: | :--------: | :--------------: |
|   orgId   | string |   组织ID   |       选填       |
|  userId   | string |   用户ID   |       选填       |
| userType  | string |  用户类型  |       选填       |
| certUsage | string |  证书用途  |       选填       |
|  certSn   | number | 证书序列号 | 选填（精确查找） |
|   token   | string |   token    |       选填       |

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": "QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
}
```





## 使用案例

### 案例一：使用已有组织的CA证书，颁发节点和用户证书

#### 环境准备

+ 已经成功启动的长安链

  详情启动流程见[快速入门](../tutorial/通过命令行工具启动链)

+ CA服务的配置文件（示例）

```yaml
# log config
log_config:
  level: info                                   # The log level                               
  filename: ../log/ca.log                       # The path to the log file            
  max_size: 1                                   # The maximum size of the log file before cutting (MB)
  max_age: 30                                   # The maximum number of days to retain old log files
  max_backups: 5                                # Maximum number of old log files to keep

# db config
db_config:
  user: root
  password: 123456
  ip: 127.0.0.1
  port: 13306
  dbname: chainmaker_ca

# Base config
base_config:
  server_port: 8090                                  # Server port configuration
  ca_type: single_root                               # Ca server type : double_root/single_root/tls/sign
#  expire_year: 2                                    # The expiration time of the certificate (year)
  expire_month: 6                                    # The expiration time of the certificate (month)(high level)
#  cert_valid_time : 2m                              # cert valid time (for testing use only)
  hash_type: SHA256                                  # SHA256/SHA3_256/SM3
  key_type: ECC_NISTP256                             # ECC_NISTP256/SM2
  can_issue_ca: false                                # Whether can continue to issue CA cert
#  provide_service_for: [wx-org1.chainmaker.org,wx-org2.chainmaker.org,wx-org3.chainmaker.org,wx-org4.chainmaker.org]      
                                                     # A list of organizations that provide services
  key_encrypt: false                                 # Whether the key is stored in encryption
  access_control: false                              # Whether to enable permission control
#  default_domain: chainmaker.org                    # the default value for sans in the certificate

pkcs11_config:
  enabled: false
  library: /usr/local/lib64/pkcs11/libupkcs11.so
  label: HSM
  password: 11111111
  session_cache_size: 10
  hash: "SHA256"

# Root CA config
root_config:
  cert:
    - cert_type: sign                                                  # Certificate path type : tls/sign (if ca_type is 'single_root',should be sign)
      cert_path: ../crypto-config/rootCA/root.crt                      # Certificate file path
      private_key_path: ../crypto-config/rootCA/root.key               # private key file path    
      key_id: SM2SignKey261                                            # pkcs11 key id
  # csr:
  #   CN: root                
  #   O: org-root                         
  #   OU: root                         
  #   country: CN                      
  #   locality: Beijing                
  #   province: Beijing             

# access control config
access_control_config:
  - app_role: admin
    app_id: admin1
    app_key: passw0rd
  - app_role: user
    app_id: user1
    app_key: passw0rd
```

修改配置

```yaml
# Root CA config
root_config:
  cert:
    - cert_type: sign                                                  # Certificate path type : tls/sign (if ca_type is 'single_root',should be sign)
      cert_path: ../crypto-config/rootCA/root.crt                      # Certificate file path
      private_key_path: ../crypto-config/rootCA/root.key               # private key file path    
      key_id: SM2SignKey261                                            # pkcs11 key id
  # csr:
  #   CN: root                
  #   O: org-root                         
  #   OU: root                         
  #   country: CN                      
  #   locality: Beijing                
  #   province: Beijing   
```

需要修改：

1. cert_path: 需将该路径下的证书文件替换成在链上已有组织的`CA证书文件`。

   也可直接替换路径，但是要注意的是，如果采用docker方式启动的话，需要修改docker容器文件的映射路径，修改deploy.sh文件：

   ```yaml
   -v $path/crypto-config:/crypto-config \
   ```

   将`$path/crypto-config`目录替换

2. private_key_path: 需将该路径下的密钥文件替换成在链上已有组织的`CA密钥文件`。

   也可直接替换路径，但是要注意的是，如果采用docker方式启动的话，需要修改docker容器文件的映射路径，修改deploy.sh文件：
   
   ```yaml
   -v $path/crypto-config:/crypto-config \
   ```
   
   将`$path/crypto-config`目录替换
   
2. csr: 需要注释掉，不再配置。（由于root CA是配置启动，不需要该部分信息去生成）

   

+ 已经启动的CA服务

  详情启动流程见上文[安装部署](#deploy)

  

#### 生成证书

调用上文中[申请证书](#apply_cert)的接口

**参数填写（以BodyJSON为例）**

共识节点（consensus node）Sign证书

**注：生成共识节点证书时，userId需要保证链上唯一；同一节点的Sign和Tls证书，userId需要保持一致。**

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.consensus1.com",
    "userType": "consensus",
    "certUsage": "sign",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

共识节点（consensus node）Tls证书

**注：生成共识节点证书时，userId需要保证链上唯一；同一节点的Sign和Tls证书，userId需要保持一致。**

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.consensus1.com",
    "userType": "consensus",
    "certUsage": "tls",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

同步节点（common node）Sign证书

**注：生成同步节点证书时，userId需要保证链上唯一；同一节点的Sign和Tls证书，userId需要保持一致。**

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.common1.com",
    "userType": "common",
    "certUsage": "sign",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

同步节点（common node）Tls证书

**注：生成同步节点证书时，userId需要保证链上唯一；同一节点的Sign和Tls证书，userId需要保持一致。**

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.common1.com",
    "userType": "common",
    "certUsage": "tls",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

用户管理员（admin）Sign证书

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "admin1",
    "userType": "admin",
    "certUsage": "sign",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

用户管理员（admin）Tls证书

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "admin1",
    "userType": "admin",
    "certUsage": "tls",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

用户客户端（client）Sign证书

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "client1",
    "userType": "client",
    "certUsage": "sign",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

用户客户端（client）Tls证书

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "client1",
    "userType": "client",
    "certUsage": "tls",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

**注：使用CA颁发的节点和用户证书时，需要将sdk配置文件中的`tls_host_name`，改成节点tls证书的userId**

以组织1的共识节点为例：

```yaml
  nodes:
    - # 节点地址，格式为：IP:端口:连接数
      node_addr: "127.0.0.1:12301"
      # 节点连接数
      conn_cnt: 10
      # RPC连接是否启用双向TLS认证
      enable_tls: true
      # 信任证书池路径
      trust_root_paths:
        - "./testdata/crypto-config/wx-org1.chainmaker.org/ca"
      # TLS hostname
      # tls_host_name: "chainmaker.org"
      #########################################
      tls_host_name: "org1.consensus1.com"
      #########################################
```



#### 获取节点TLS证书的NodeId

调用上文中[获取节点TLS证书的NodeID](#get_nodeId)的接口

**参数填写（以BodyJSON为例）**

获取共识节点（consensus node）Tls证书的NodeId

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.consensus1.com",
    "userType": "consensus",
    "certUsage": "tls"
}
```

获取共识节点（common node）Tls证书的NodeId

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.common1.com",
    "userType": "common",
    "certUsage": "tls"
}
```

将`bc1.yml`和`chainmaker.yml`中的nodeId替换，配置文件修改位置如下：

- bc1.yml

```yaml
#共识配置
consensus:
  # 共识类型(0-SOLO,1-TBFT,2-MBFT,3-MAXBFT,4-RAFT,10-POW)
  type: 1
  # 共识节点列表，组织必须出现在trust_roots的org_id中，每个组织可配置多个共识节点，节点地址采用libp2p格式
  nodes:
    - org_id: "wx-org1.chainmaker.org"
      node_id:
        - "QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
    - org_id: "wx-org2.chainmaker.org"
      node_id:
        - "QmeyNRs2DwWjcHTpcVHoUSaDAAif4VQZ2wQDQAUNDP33gH"
    - org_id: "wx-org3.chainmaker.org"
      node_id:
        - "QmXf6mnQDBR9aHauRmViKzSuZgpumkn7x6rNxw1oqqRr45"
    - org_id: "wx-org4.chainmaker.org"
      node_id:
        - "QmRRWXJpAVdhFsFtd9ah5F4LDQWFFBDVKpECAF8hssqj6H"
```

- chainmaker.yml

```yaml
# Network Settings
net:
  # Network provider, can be libp2p or liquid.
  # libp2p: using libp2p components to build the p2p module.
  # liquid: a new p2p module we build from 0 to 1.
  # This item must be consistent across the blockchain network.
  provider: LibP2P

  # The address and port the node listens on.
  # By default, it uses 0.0.0.0 to listen on all network interfaces.
  listen_addr: /ip4/0.0.0.0/tcp/11301

  # Max stream of a connection.
  # peer_stream_pool_size: 100

  # Max number of peers the node can connect.
  # max_peer_count_allow: 20

  # The strategy for eliminating node when the count of connecting peers reach the max value.
  # It could be: 1 Random, 2 FIFO, 3 LIFO. The default strategy is LIFO.
  # peer_elimination_strategy: 3

  # The seeds peer list used to join in the network when starting.
  # The connection supervisor will try to dial seed peer whenever the connection is broken.
  # Example ip format: "/ip4/127.0.0.1/tcp/11301/p2p/"+nodeid
  # Example dns format："/dns/cm-node1.org/tcp/11301/p2p/"+nodeid
  seeds:
    - "/ip4/127.0.0.1/tcp/11301/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
    - "/ip4/127.0.0.1/tcp/11302/p2p/QmeyNRs2DwWjcHTpcVHoUSaDAAif4VQZ2wQDQAUNDP33gH"
    - "/ip4/127.0.0.1/tcp/11303/p2p/QmXf6mnQDBR9aHauRmViKzSuZgpumkn7x6rNxw1oqqRr45"
    - "/ip4/127.0.0.1/tcp/11304/p2p/QmRRWXJpAVdhFsFtd9ah5F4LDQWFFBDVKpECAF8hssqj6H"
```



### 案例二：使用CA生成全套的ChainMaker证书

#### 环境准备

+ 已经成功启动的长安链

  详情启动流程见[快速入门](../tutorial/通过命令行工具启动链)

+ CA服务的配置文件（示例）

  ```yaml
  # log config
  log_config:
    level: info                                   # The log level                               
    filename: ../log/ca.log                       # The path to the log file            
    max_size: 1                                   # The maximum size of the log file before cutting (MB)
    max_age: 30                                   # The maximum number of days to retain old log files
    max_backups: 5                                # Maximum number of old log files to keep
  
  # db config
  db_config:
    user: root
    password: 123456
    ip: 127.0.0.1
    port: 13306
    dbname: chainmaker_ca
  
  # Base config
  base_config:
    server_port: 8090                                  # Server port configuration
    ca_type: single_root                               # Ca server type : double_root/single_root/tls/sign
  #  expire_year: 2                                    # The expiration time of the certificate (year)
    expire_month: 6                                    # The expiration time of the certificate (month)(high level)
  #  cert_valid_time : 2m                              # cert valid time (for testing use only)
    hash_type: SHA256                                  # SHA256/SHA3_256/SM3
    key_type: ECC_NISTP256                             # ECC_NISTP256/SM2
    can_issue_ca: false                                # Whether can continue to issue CA cert
  #  provide_service_for: [wx-org1.chainmaker.org,wx-org2.chainmaker.org,wx-org3.chainmaker.org,wx-org4.chainmaker.org]      
                                                       # A list of organizations that provide services
    key_encrypt: false                                  # Whether the key is stored in encryption
    access_control: false                              # Whether to enable permission control
  #  default_domain: chainmaker.org                    # the default value for sans in the certificate
  
  pkcs11_config:
    enabled: false
    library: /usr/local/lib64/pkcs11/libupkcs11.so
    label: HSM
    password: 11111111
    session_cache_size: 10
    hash: "SHA256"
  
  # Root CA config
  root_config:
    cert:
      - cert_type: sign                                                  # Certificate path type : tls/sign (if ca_type is 'single_root',should be sign)
        cert_path: ../crypto-config/rootCA/root.crt                      # Certificate file path
        private_key_path: ../crypto-config/rootCA/root.key               # private key file path    
        key_id: SM2SignKey261                                            # pkcs11 key id
    csr:
      CN: root                
      O: org-root                         
      OU: root                         
      country: CN                      
      locality: Beijing                
      province: Beijing             
  
  # intermediate config
  intermediate_config: 
    - csr:
        CN: ca-wx-org1.chainmaker.org                        
        O: wx-org1.chainmaker.org                        
        OU: ca                         
        country: CN                       
        locality: Beijing                
        province: Beijing            
      key_id: SM2SignKey6
  
    - csr:
        CN: ca-wx-org2.chainmaker.org                       
        O: wx-org2.chainmaker.org                     
        OU: ca                         
        country: CN                       
        locality: Beijing                
        province: Beijing            
      key_id: SM2SignKey249
      
    - csr:
        CN: ca-wx-org3.chainmaker.org                       
        O: wx-org3.chainmaker.org                    
        OU: ca                         
        country: CN                       
        locality: Beijing                
        province: Beijing            
      key_id: SM2SignKey257
  
    - csr:
        CN: ca-wx-org4.chainmaker.org                    
        O: wx-org4.chainmaker.org                    
        OU: ca                         
        country: CN                       
        locality: Beijing                
        province: Beijing            
      key_id: SM2SignKey260
  
  # access control config
  access_control_config:
    - app_role: admin
      app_id: admin1
      app_key: passw0rd
    - app_role: user
      app_id: user1
      app_key: passw0rd
  ```

- 已经启动的CA服务

  详情启动流程见上文[安装部署](#deploy)

  

#### 获取CA证书

由于以下配置部分，CA服务在启动时，就会生成相应的组织CA证书

```shell
intermediate_config: 
  - csr:
      CN: ca-wx-org1.chainmaker.org                        
      O: wx-org1.chainmaker.org                        
      OU: ca                         
      country: CN                       
      locality: Beijing                
      province: Beijing            
    key_id: SM2SignKey6

  - csr:
      CN: ca-wx-org2.chainmaker.org                       
      O: wx-org2.chainmaker.org                     
      OU: ca                         
      country: CN                       
      locality: Beijing                
      province: Beijing            
    key_id: SM2SignKey249
    
  - csr:
      CN: ca-wx-org3.chainmaker.org                       
      O: wx-org3.chainmaker.org                    
      OU: ca                         
      country: CN                       
      locality: Beijing                
      province: Beijing            
    key_id: SM2SignKey257

  - csr:
      CN: ca-wx-org4.chainmaker.org                    
      O: wx-org4.chainmaker.org                    
      OU: ca                         
      country: CN                       
      locality: Beijing                
      province: Beijing            
    key_id: SM2SignKey260
```



CA服务启动后，直接调用[多条件查询证书](#query_cert)，获取CA证书

**参数填写（以BodyJSON为例）**

获取org1的CA证书：

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userType": "ca",
    "certUsage": "sign"
}
```

获取org2的CA证书：

```json
{
    "orgId": "wx-org2.chainmaker.org",
    "userType": "ca",
    "certUsage": "sign"
}
```

获取org3的CA证书：

```json
{
    "orgId": "wx-org3.chainmaker.org",
    "userType": "ca",
    "certUsage": "sign"
}
```

获取org4的CA证书：

```json
{
    "orgId": "wx-org4.chainmaker.org",
    "userType": "ca",
    "certUsage": "sign"
}
```

**注：获取的CA证书，需要在启动链时，将他们配置到链配置文件`bc1.yml`的`trust_roots`里**



#### 生成证书

调用上文中[申请证书](#apply_cert)的接口userId

**参数填写（以org1为例）**

共识节点（consensus node）Sign证书

**注：生成共识节点证书时，userId需要保证链上唯一；同一节点的Sign和Tls证书，userId需要保持一致。**

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.consensus1.com",
    "userType": "consensus",
    "certUsage": "sign",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

共识节点（consensus node）Tls证书

**注：生成共识节点证书时，userId需要保证链上唯一；同一节点的Sign和Tls证书，userId需要保持一致。**

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.consensus1.com",
    "userType": "consensus",
    "certUsage": "tls",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

同步节点（common node）Sign证书

**注：生成同步节点证书时，userId需要保证链上唯一；同一节点的Sign和Tls证书，userId需要保持一致。**

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.common1.com",
    "userType": "common",
    "certUsage": "sign",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

同步节点（common node）Tls证书

**注：生成同步节点证书时，userId需要保证链上唯一；同一节点的Sign和Tls证书，userId需要保持一致。**

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.common1.com",
    "userType": "common",
    "certUsage": "tls",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

用户管理员（admin）Sign证书

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "admin1",
    "userType": "admin",
    "certUsage": "sign",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

用户管理员（admin）Tls证书

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "admin1",
    "userType": "admin",
    "certUsage": "tls",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

用户客户端（client）Sign证书

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "client1",
    "userType": "client",
    "certUsage": "sign",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

用户客户端（client）Tls证书

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "client1",
    "userType": "client",
    "certUsage": "tls",
    "country": "CN",
    "locality": "BeiJing",
    "province": "BeiJing"
}
```

**注：使用CA颁发的节点和用户证书时，需要将sdk配置文件中的`tls_host_name`，改成节点tls证书的userId**

以组织1的共识节点为例：

```yaml
  nodes:
    - # 节点地址，格式为：IP:端口:连接数
      node_addr: "127.0.0.1:12301"
      # 节点连接数
      conn_cnt: 10
      # RPC连接是否启用双向TLS认证
      enable_tls: true
      # 信任证书池路径
      trust_root_paths:
        - "./testdata/crypto-config/wx-org1.chainmaker.org/ca"
      # TLS hostname
      # tls_host_name: "chainmaker.org"
      #########################################
      tls_host_name: "org1.consensus1.com"
      #########################################
```



#### 获取节点TLS证书的NodeId

调用上文中[获取节点TLS证书的NodeID](#get_nodeId)的接口

**参数填写（以BodyJSON为例）**

获取共识节点（consensus node）Tls证书的NodeId

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.consensus1.com",
    "userType": "consensus",
    "certUsage": "tls"
}
```

获取同步节点（common node）Tls证书的NodeId

```json
{
    "orgId": "wx-org1.chainmaker.org",
    "userId": "org1.common1.com",
    "userType": "common",
    "certUsage": "tls"
}
```

将`bc1.yml`和`chainmaker.yml`中的nodeId替换，配置文件修改位置如下：

- bc1.yml

```yaml
#共识配置
consensus:
  # 共识类型(0-SOLO,1-TBFT,2-MBFT,3-MAXBFT,4-RAFT,10-POW)
  type: 1
  # 共识节点列表，组织必须出现在trust_roots的org_id中，每个组织可配置多个共识节点，节点地址采用libp2p格式
  nodes:
    - org_id: "wx-org1.chainmaker.org"
      node_id:
        - "QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
    - org_id: "wx-org2.chainmaker.org"
      node_id:
        - "QmeyNRs2DwWjcHTpcVHoUSaDAAif4VQZ2wQDQAUNDP33gH"
    - org_id: "wx-org3.chainmaker.org"
      node_id:
        - "QmXf6mnQDBR9aHauRmViKzSuZgpumkn7x6rNxw1oqqRr45"
    - org_id: "wx-org4.chainmaker.org"
      node_id:
        - "QmRRWXJpAVdhFsFtd9ah5F4LDQWFFBDVKpECAF8hssqj6H"
```

- chainmaker.yml

```yaml
# Network Settings
net:
  # Network provider, can be libp2p or liquid.
  # libp2p: using libp2p components to build the p2p module.
  # liquid: a new p2p module we build from 0 to 1.
  # This item must be consistent across the blockchain network.
  provider: LibP2P

  # The address and port the node listens on.
  # By default, it uses 0.0.0.0 to listen on all network interfaces.
  listen_addr: /ip4/0.0.0.0/tcp/11301

  # Max stream of a connection.
  # peer_stream_pool_size: 100

  # Max number of peers the node can connect.
  # max_peer_count_allow: 20

  # The strategy for eliminating node when the count of connecting peers reach the max value.
  # It could be: 1 Random, 2 FIFO, 3 LIFO. The default strategy is LIFO.
  # peer_elimination_strategy: 3

  # The seeds peer list used to join in the network when starting.
  # The connection supervisor will try to dial seed peer whenever the connection is broken.
  # Example ip format: "/ip4/127.0.0.1/tcp/11301/p2p/"+nodeid
  # Example dns format："/dns/cm-node1.org/tcp/11301/p2p/"+nodeid
  seeds:
    - "/ip4/127.0.0.1/tcp/11301/p2p/QmcQHCuAXaFkbcsPUj7e37hXXfZ9DdN7bozseo5oX4qiC4"
    - "/ip4/127.0.0.1/tcp/11302/p2p/QmeyNRs2DwWjcHTpcVHoUSaDAAif4VQZ2wQDQAUNDP33gH"
    - "/ip4/127.0.0.1/tcp/11303/p2p/QmXf6mnQDBR9aHauRmViKzSuZgpumkn7x6rNxw1oqqRr45"
    - "/ip4/127.0.0.1/tcp/11304/p2p/QmRRWXJpAVdhFsFtd9ah5F4LDQWFFBDVKpECAF8hssqj6H"
```



**重复以上步骤，依次生成org2，org3，org4的全部证书即可在链上使用。**

