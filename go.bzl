load("@bazel_gazelle//:deps.bzl", "go_repository")

# Don't sync this by hand. Instead, update go.mod and then run
# gazelle update-repos -from_file=go.mod -to_macro=go.bzl%go_repositories
def go_repositories():
    go_repository(
        name = "com_github_golang_protobuf",
        importpath = "github.com/golang/protobuf",
        sum = "h1:ZFgWrT+bLgsYPirOnRfKLYJLvssAegOj/hgyMFdJZe0=",
        version = "v1.4.1",
    )
    go_repository(
        name = "com_github_google_go_cmp",
        importpath = "github.com/google/go-cmp",
        sum = "h1:xsAVV57WRhGj6kEIi8ReJzQlHHqcBYCElAvkovg3B/4=",
        version = "v0.4.0",
    )
    go_repository(
        name = "org_golang_google_protobuf",
        importpath = "google.golang.org/protobuf",
        sum = "h1:cJv5/xdbk1NnMPR1VP9+HU6gupuG9MLBoH1r6RHZ2MY=",
        version = "v1.22.0",
    )
    go_repository(
        name = "org_golang_x_xerrors",
        importpath = "golang.org/x/xerrors",
        sum = "h1:E7g+9GITq07hpfrRu66IVDexMakfv52eLZ2CXBWiKr4=",
        version = "v0.0.0-20191204190536-9bdfabe68543",
    )
