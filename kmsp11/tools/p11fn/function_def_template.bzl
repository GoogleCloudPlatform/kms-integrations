def function_def_template(name, src, out):
    native.genrule(
        name = name,
        srcs = [src],
        outs = [out],
        cmd = """
        \"$(location //kmsp11/tools/p11fn/templater)\" \
            --func_list_path \"$(location //kmsp11/tools/p11fn:function_defs.textproto)\" \
            --template_path \"$(SRCS)\" > \"$(@)\"""",
        tools = [
            "//kmsp11/tools/p11fn/templater",
            "//kmsp11/tools/p11fn:function_defs.textproto",
        ],
    )
