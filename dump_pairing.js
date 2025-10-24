/*
adb -s emulator-5554 root
adb -s emulator-5554 shell
/data/local/tmp/frida-server

frida -D emulator-5554 -n "Meta AI" -l dump_pairing.js
*/

const module = Process.getModuleByName("libstartup.so");

// Ghidra loads libstartup at this address, so my addrs are off by this much...
const GHIDRA_BASE = 0x100000;

// hook sha256
// frida won't get this sym; dunno why...
const addr_SHA256_Incremental_update = 0x9ebf08 - GHIDRA_BASE;
const sym_SHA256_Incremental_update = module.base.add(
  addr_SHA256_Incremental_update,
);
const sym_SHA256_Incremental_update_hook = {
  onEnter(args) {
    console.log(
      "airshield::SHA256::Incremental::update:",
      hexdump(args[1], { length: args[2].toInt32() }),
    );
  },
};
/*
const sym_SHA256_Incremental_update = module.getExportByName(
  "_ZNK9airshield8security6SHA25611Incremental6updateENS0_4SpanIKhEE",
);
*/
Interceptor.attach(
  sym_SHA256_Incremental_update,
  sym_SHA256_Incremental_update_hook,
);

const addr_mbedtls_sha256_finish = 0xada0a0 - GHIDRA_BASE;
const sym_mbedtls_sha256_finish = module.base.add(
  addr_mbedtls_sha256_finish,
);

const sym_mbedtls_sha256_finish_hook = {
  onEnter(args) {
    this.buf = args[1];
  },
  onLeave(result) {
    console.log(
      "mbedtls_sha256_finish",
      hexdump(this.buf, { length: 0x20 }),
    );
  },
};

/*
const sym_SHA256_Incremental_finish = module.getExportByName(
  "_ZNK9airshield8security6SHA25611Incremental6finishENS0_4SpanIKhEE",
);
*/
Interceptor.attach(
  sym_mbedtls_sha256_finish,
  sym_mbedtls_sha256_finish_hook,
);

// hook hmac
// I'm using the mbedtls addresses since the Airshield constructor is sometimes inlined

const addr_mbedtls_md_hmac_starts = 0xad4170 - GHIDRA_BASE;
const sym_mbedtls_md_hmac_starts = module.base.add(addr_mbedtls_md_hmac_starts);

const sym_mbedtls_md_hmac_starts_hook = {
  onEnter(args) {
    console.log(
      "mbedtls_md_hmac_starts:",
      hexdump(args[1], { length: args[2].toInt32() }),
    );
  },
};

Interceptor.attach(sym_mbedtls_md_hmac_starts, sym_mbedtls_md_hmac_starts_hook);

const addr_mbedtls_md_hmac_update = 0xad42ec - GHIDRA_BASE;
const sym_mbedtls_md_hmac_update = module.base.add(addr_mbedtls_md_hmac_update);

const sym_mbedtls_md_hmac_update_hook = {
  onEnter(args) {
    console.log(
      "mbedtls_md_hmac_update:",
      hexdump(args[1], { length: args[2].toInt32() }),
    );
  },
};
Interceptor.attach(sym_mbedtls_md_hmac_update, sym_mbedtls_md_hmac_update_hook);

const addr_mbedtls_md_hmac_finish = 0xad430c - GHIDRA_BASE;
const sym_mbedtls_md_hmac_finish = module.base.add(addr_mbedtls_md_hmac_finish);

const sym_mbedtls_md_hmac_finish_hook = {
  onEnter(args) {
    this.buf = args[1];
  },
  onLeave(result) {
    console.log("mbedtls_md_hmac_finish:", hexdump(this.buf, { length: 0x20 }));
  },
};

Interceptor.attach(sym_mbedtls_md_hmac_finish, sym_mbedtls_md_hmac_finish_hook);

// hook the actual computations
// see AirshieldDoEcdhComputeShared = 0x9eb998

const addr_mbedtls_ecdh_compute_shared = 0xaceb2c - GHIDRA_BASE;

const sym_mbedtls_ecdh_compute_shared = module.base.add(
  addr_mbedtls_ecdh_compute_shared,
);

const sym_mbedtls_ecdh_compute_shared_hook = {
  onEnter(args) {
    console.log("mbedtls_ecdh_compute_shared_hook");
    // TODO: zhuowei: dump the private key.
  },
};

Interceptor.attach(
  sym_mbedtls_ecdh_compute_shared,
  sym_mbedtls_ecdh_compute_shared_hook,
);

const addr_mbedtls_cipher_set_iv = 0xacd98c - GHIDRA_BASE;

const sym_mbedtls_cipher_set_iv = module.base.add(addr_mbedtls_cipher_set_iv);

const sym_mbedtls_cipher_set_iv_hook = {
  onEnter(args) {
    console.log("mbedtls_cipher_set_iv:", hexdump(args[1], { length: 0x10 }));
  },
};

Interceptor.attach(sym_mbedtls_cipher_set_iv, sym_mbedtls_cipher_set_iv_hook);

const addr_mbedtls_cipher_setkey = 0xacd914 - GHIDRA_BASE;
const sym_mbedtls_cipher_setkey = module.base.add(addr_mbedtls_cipher_setkey);

const sym_mbedtls_cipher_setkey_hook = {
  onEnter(args) {
    console.log(
      "mbedtls_cipher_setkey:",
      hexdump(args[1], { length: 0x100 / 8 }),
      args[2].toInt32(),
    );
  },
};

Interceptor.attach(sym_mbedtls_cipher_setkey, sym_mbedtls_cipher_setkey_hook);
