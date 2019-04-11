package result;

public class CodeMsg {
    private int code;
    private String msg;
    //通用的错误代码
    public static CodeMsg SUCCESS = new CodeMsg(0, "success");
    public static CodeMsg SEVER_ERROR = new CodeMsg(500100, "服务端异常");
    public static CodeMsg BIND_ERROR = new CodeMsg(500101, "参数校验异常:%s");
    public static CodeMsg PATH_ERROR = new CodeMsg(500102, "路径错误");

    //用户错误
    public static CodeMsg LOGIN_ERROR = new CodeMsg(500200, "账号密码为空");
    public static CodeMsg LOGIN_USER_ERROR = new CodeMsg(500201, "账号不存在");
    public static CodeMsg PASSWORD_ERROR = new CodeMsg(500201, "密码错误");

    //DU错误
    public static CodeMsg GP_FILE_NOT_EXISTS = new CodeMsg(500300, "GP文件不存在");


    public CodeMsg(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public int getCode() {
        return code;
    }

    public String getMsg() {
        return msg;
    }

    @Override
    public String toString() {
        return "CodeMsg{" +
                "code=" + code +
                ", msg='" + msg + '\'' +
                '}';
    }

    public CodeMsg fillArgs(Object... args) {
        int code = this.code;
        String message = String.format(this.msg, args);
        return new CodeMsg(code, message);
    }
}
