def function_def_template(name, src, out):
    native.genrule(
        name = name,
        srcs = [src],
        outs = [out],
        cmd = """
        \"$(location :function_def_templater)\" \
            --func_list_path \"$(location :function_defs.textproto)\" \
            --template_path \"$(SRCS)\" > \"$(@)\"""",
        tools = [
            ":function_def_templater",
            ":function_defs.textproto",
        ],
    )
