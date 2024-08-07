// replace targets with your own addresses to track their frees/allocs
// const targets = [ptr("0x7fb742e500"), ptr("0x7fb743d1c0")]; // Peloton NQY02A
// const targets = [ptr("0x7f36231a80"), ptr("0x7f3622e500")]; // Pixel 3a Android 9
const targets = [ptr("0x7fb6e32780"), ptr("0x7fb6e2f320")];   // Nexus 6P

function is_target(x) {
    // check target-0x20 as that is where we will free / overwrite
    return targets.filter((y => y.equals(x) || y.sub(0x20).equals(x))).length != 0;
}

const wpasup = Process.getModuleByName("wpa_supplicant");
console.log(`wpa_supplicant base address: ${wpasup.base}`);

const chunks = {};
var eloop = false;

//0x00198a6c // Pixel 3a Android 9 offset
// const eloop_register_timeout = wpasup.base.add(ptr(0x0002e1e4)); // may need to change offset
// Interceptor.attach(eloop_register_timeout, {
//     onEnter: (args) => {
//         console.log(`eloop_register_timeout(${args[0]}, ${args[1]}, ${args[2]}, ${args[3]}, ${args[4]})`);
//         eloop = true; // always view the next alloc, it is an eloop_timeout address
//     }
// });

const wpabuf_alloc_copy = wpasup.base.add(ptr(0x00028bb8));
Interceptor.attach(wpabuf_alloc_copy, {
    onEnter: (args) => {
        console.log(`wpabuf_alloc_copy(${args[0]}, ${args[1]})`);
		this.size = args[1];
    },
    onLeave: (ret) => {
		// console.log(this.size);
		if (this.size == 0x60) {
			// console.log(`eloop_timeout is overwritten`);
			console.log(`struct wpabuf *buf => ${ret}`);
			console.log(hexdump(ret));
		}
    }
});

const p2p_set_dev_name = wpasup.base.add(ptr(0x00060c3c));
Interceptor.attach(p2p_set_dev_name, {
    onEnter: (args) => {
        console.log(`p2p_set_dev_name(${args[0]}, ${args[1]})`);
    }
});

// alloc functions
const allocs = {
    "calloc": 1,
    "malloc": 0,
    "realloc": 0
}

for (const alloc in allocs) {
    Interceptor.attach(Module.getExportByName(null, alloc), {
        onEnter: (args) => {
            if (allocs[alloc])
                this.num  = args[0].toInt32();
            else
                this.num  = 1;

            this.size = args[allocs[alloc]];
        },
        onLeave: (ret) => {
            const size = this.size.toInt32()*this.num;
            if (eloop || is_target(ret)) {
                console.log(`${alloc}(${size}) => ${ret}`);
                eloop = false;
            }
            if (is_target(ret)) {
                chunks[ret] = size;
            }
        }
    });
}

Interceptor.attach(Module.getExportByName(null, "free"), {
    onEnter: (args) => {
        if (is_target(args[0])) {
            console.log(`free(${args[0]})`);
        } 
        if (chunks[args[0]] !== undefined) {
            console.log(hexdump(args[0], {
                offset: 0,
                length: chunks[args[0]],
                header: true,
                ansi: true
            }));
        }
    }
});
