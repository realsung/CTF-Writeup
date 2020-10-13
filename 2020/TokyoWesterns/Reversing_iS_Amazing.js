// sudo frida -l solve.js "TWCTF{*****************************}" -f ./rsa-5ad9c93834a56350ec040acc82ffe699a20f52767a8681f1c59bd5f33caa51bd --no-pause --runtime=v8

//#include <openssl/rsa.h>
// int RSA_private_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
// int RSA_public_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);

var key = null;
Interceptor.attach(Module.findExportByName(null,'RSA_private_encrypt'),{
    onEnter: function(args){
        console.log('=============== START ===============');
        console.warn('args[0] : int flen = ' + args[0]);
        console.warn('args[1] : unsgined char * from = ' + args[1].readCString());
        console.warn('args[2] : unsgined char * to = ' + args[2]);
        console.warn('args[3] : RSA *rsa = ' + args[3]);
        key = args[3];
        console.warn('args[4] : int padding = ' + args[4]);
    },
    onLeave: function(ret){
        console.warn('ret : ' + ret);
    }
});

var decrypt = Module.findExportByName(null,'RSA_public_decrypt');
var funcDecrypt = new NativeFunction(decrypt,'int',['int','pointer','pointer','pointer','int']);
Interceptor.attach(Module.findExportByName(null,'memcmp'),{
    onEnter: function(args){
        console.warn('[*] memcmp args[0] : ' + args[0]);
        console.warn('[*] memcmp args[1] : ' + args[1]);
        console.warn('[*] memcmp args[2] : ' + args[2]);
        var tmp = Memory.alloc(0x80);
        funcDecrypt(0x80,ptr(args[1]),tmp,key,1);
        console.log(hexdump(tmp));
    },
    onLeave: function(ret){
        console.warn('ret : ' + ret);
    }
});
