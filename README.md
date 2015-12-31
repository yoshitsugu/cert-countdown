# Certificate Expire Date Count Down

countdown days until the certificate expires

## Usage

+ prepare stack (https://github.com/commercialhaskell/stack)
+ clone this repository
+ ``$ stack build``
+ ``$ stack exec -- cert-countdown (domain name1) (domain name2) ...``

## Example
```
$ stack exec -- cert-countdown github.com google.com hackage.haskell.org
hackage.haskell.org: 803
google.com: 68
github.com: 103
```
The number right side of domain name means remaining days from expiration.
