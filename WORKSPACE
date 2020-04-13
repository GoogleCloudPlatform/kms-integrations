workspace(name = "com_google_kmstools")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

http_archive(
    name = "com_github_gflags_gflags",  # 2020-03-18
    sha256 = "68e26a487038a842da3ef2ddd1f886dad656e9efaf1a3d49e87d1d3a9fa3a8eb",
    strip_prefix = "gflags-addd749114fab4f24b7ea1e0f2f837584389e52c",
    url = "https://github.com/gflags/gflags/archive/addd749114fab4f24b7ea1e0f2f837584389e52c.tar.gz",
)

http_archive(
    name = "com_github_google_glog",  # 2020-02-16
    sha256 = "6fc352c434018b11ad312cd3b56be3597b4c6b88480f7bd4e18b3a3b2cf961aa",
    strip_prefix = "glog-3ba8976592274bc1f907c402ce22558011d6fc5e",
    url = "https://github.com/google/glog/archive/3ba8976592274bc1f907c402ce22558011d6fc5e.tar.gz",
)

http_archive(
    name = "com_google_absl",  # 2020-04-07
    sha256 = "2ad95ee8fe9ee5aef55d8a9b59dfbd9c66056364a98dc3076ff3b32698b7bbe8",
    strip_prefix = "abseil-cpp-1112609635037a32435de7aa70a9188dcb591458",
    url = "https://github.com/abseil/abseil-cpp/archive/1112609635037a32435de7aa70a9188dcb591458.zip",
)

http_archive(
    name = "com_google_googletest",  # 2020-04-03
    sha256 = "363089f62b375e6a73b7149015e7fe92e50d124ab4e95ba062774c496d96f2fc",
    strip_prefix = "googletest-e3f0319d89f4cbf32993de595d984183b1a9fc57",
    url = "https://github.com/google/googletest/archive/e3f0319d89f4cbf32993de595d984183b1a9fc57.zip",
)

http_file(
    name = "pkcs11_h_v240",  # 2016-05-13
    downloaded_file_path = "pkcs11.h",
    sha256 = "8bb7aa1aeaa328b6a39913070d6f3d2bdeb9f2c92baf27f714fbb4cbefdf4054",
    urls = ["http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11.h"],
)

http_file(
    name = "pkcs11f_h_v240",  # 2016-05-13
    downloaded_file_path = "pkcs11f.h",
    sha256 = "a85adad038bfc9dad9c71377f3ed3b049ba2ac9b3f37198a372f211d210c6057",
    urls = ["http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11f.h"],
)

http_file(
    name = "pkcs11t_h_v240",  # 2016-05-13
    downloaded_file_path = "pkcs11t.h",
    sha256 = "5b58736b6d23f12b4d9492cd24b06b9d11056c3153afc4e89b1fe564749e71a2",
    urls = ["http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11t.h"],
)
