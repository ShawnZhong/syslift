# third_party

## nolibc

Vendored from Linux https://github.com/torvalds/linux/tree/master/tools/include/nolibc

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/torvalds/linux.git /tmp/linux
git -C /tmp/linux sparse-checkout set tools/include/nolibc
rm -rf third_party/nolibc
cp -a /tmp/linux/tools/include/nolibc third_party/
rm -rf /tmp/linux
```

## cxxopts

Vendored from https://github.com/jarro2783/cxxopts/blob/master/include/cxxopts.hpp

```bash
mkdir -p third_party/cxxopts
curl -fsSL https://raw.githubusercontent.com/jarro2783/cxxopts/master/include/cxxopts.hpp \
  -o third_party/cxxopts/cxxopts.hpp
```
