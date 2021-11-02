# Stonks Socket

## Tl;DR Spoiler

>! A race condition on the kernel heap can be used with a `msg_msg` struct to overwrite a function
>! pointer. Then, ret2usr to win!

## Summary

Stonks Socket was a very interesting kernel challenge. There were multiple bugs, some of which were
not exploitable, and the actual exploit was relatively simple. The part of this challenge that added
to the difficulty was understanding how `sock` and `iov_iter` structures work in the kernel.
However, this was part of the rabbit hole that I fell into trying to solve this challenge.

## Source Analysis

First, let's understand how this driver works. Thankfully, we are given source for this driver, and
it is located at `module/stonks_socket.c`. We are also given the `Makefile`, along with the compiled
kernel object and a docker container.

When the kernel object is loaded, the init function, `stonks_socket`, is ran. This function prints
the address of a function in the module, which I overlooked while I completed this challenge. Then,
it overwrites the `tcp_prot.ioctl` function pointer with the address of the custom `stonks_ioctl`.
This was interesting, because no new kernel device was created. My guess, which turned out to be
correct, was that this function handled IO control calls to socket descriptors for TCP sockets. 

While this may be obvious, it could be useful to check in the source of the kernel to ensure that
your assumptions are correct. This is generally good practice. Socket's that are created with the
flag `AF_INET` are referenced in
[net/ipv4/af_inet.c](https://elixir.bootlin.com/linux/latest/source/net/ipv4/af_inet.c). In this
file, there is an array of `inet_protosw` structs called `inetsw_array`, and the first element of
this array links `SOCK_STREAM` sockets with `tcp_prot`. Each element of this array is initialized as
a sort of template for creating sockets with the `inet_register_protosw` function, and this is
called in the `inet_init` init function on kernel startup. While I could go into more detail, this
is generally enough to determine that a socket created with the `AF_INET` domain and `SOCK_STREAM`
type will be linked to the `tcp_prot` structure, and ioctl calls to this socket will go through our
`stonks_ioctl` function. If you are interested, you can read more and determine exactly how these
sockets are created. As a general rule for CTF's, it is important to know how much information is
important to solve a problem and when to stop going into rabbit holes, but it is also generally
interesting to learn how different parts of the kernel work.

```c
int stonks_ioctl(struct sock *sk, int cmd, unsigned long arg) {
    int err;
    u64 *sks = (u64*)sk;
    union {
        struct {
            u64 off;
            u64 __user *data;
        };
        struct {
            unsigned size;
            u64 rounds;
            u64 key;
            u64 security;
        };
    } a;
    struct StonksSocket *stonks_sk;

    if (cmd == OPTION_CALL) {
        if (sk->sk_user_data != NULL) {
            return -EINVAL;
        }

        err = copy_from_user(&a, (void*)arg, sizeof(a));

        stonks_sk = kmalloc(sizeof(struct StonksSocket), GFP_KERNEL);
        stonks_sk->hash_size = a.size;
        stonks_sk->hash_rounds = a.rounds;
        stonks_sk->hash_key = a.key;
        if (a.security == 1) {
            stonks_sk->hash_function = secure_hash;
        } else {
            stonks_sk->hash_function = null_hash;
        }
        sk->sk_user_data = stonks_sk;
        sk->sk_prot->recvmsg = stonks_rocket;
        return err;
    } else if (cmd == OPTION_PUT) {
        if (sk->sk_user_data == NULL) {
            return -EINVAL;
        }
        kfree(sk->sk_user_data);
        sk->sk_user_data = NULL;
    } else if (cmd == OPTION_DEBUG) {
        err = copy_from_user(&a, (void*)arg, sizeof(a));
        return put_user(sks[a.off], a.data);
    }
    return tcp_ioctl(sk, cmd, arg);
}
```

As can be seen in the `stonks_ioctl` function, there are 3 different ioctl codes that can be
handled. The `OPTION_DEBUG` command is used to print a qword from an offset of the beginning of the
sk `sock` struct. This is a great gift because we can use this to leak a kernel pointer and
calculate the kernel base. The `OPTION_CALL` command creates a `StonksSocket` structure in the
kernel heap and installs this in the `sk_user_data` for the socket. Then, `sk->sk_prot->revcmsg` is
overwritten with the address of `stonks_rocket`. Again, the functionality of this can be inferred to
be a function handler called when the recvmsg syscall is invoked on the socket. You can study the
source to find out how this happens, but I will omit that this time. Finally, the `OPTION_PUT`
command is used to free the `StonksSocket` structure that is stored in the user data of the socket
and zero out the pointer.

```c
int stonks_rocket(struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len) {
    int ret, count;
    struct StonksSocket *s_sk = sk->sk_user_data;
    struct Hash hash;
    struct iov_iter iter[2];

    ret = tcp_recvmsg(sk, msg, len, nonblock, flags, addr_len);
    if (ret < 1 || s_sk == NULL) {
        return ret;
    }
    printk(KERN_INFO "stonks_socket: received message, size: %d", ret);

    iter[0] = msg->msg_iter;
    iov_iter_init(&iter[1], WRITE, iter[0].iov, iter[0].count, ret);

    hash.length = s_sk->hash_size;
    hash.rounds = s_sk->hash_rounds;
    hash.key = s_sk->hash_key;
    count = s_sk->hash_function(&iter[1], &hash);

    len = copy_to_iter(&hash.word1, count, &iter[0]);
    ret += count;
    return ret;
}
```

The `StonksSocket` structure relates to how TCP messages are hashed, and during the `OPTION_CALL`
ioctl, we can choose to set the hash function to `secure_hash` or `null_hash`. When we call
`recvmsg` on the socket, `tcp_recvmsg` is used to read the message into a `msghdr` struct. Then, an
array of two `iov_iter` structs are initialized with the `msg_iter` of the newly received message.
the `sk_user_data` pointer is saved to a local variable, and a new `Hash` structure on the stack is 
initialized with the various fields in the `StonksSocket` structure. Then, the hash function that we 
chose is used to hash the input, and this is copies back to the iter. I am not completely sure how the
`iov_iter` struct is used, or how `copy_to_iter` works. However, this is not really necessary to
know.

```c
int secure_hash(struct iov_iter *msg, struct Hash *h) {
    u64 i = 1, j, size;
    char *buf;
    char *hash = (char*)&h->word1;

    // init
    for (i = 0; i < h->length; i++) {
        (&h->word1)[i] = h->key;
    }

    //load data
    while (i) {
        size = h->length * sizeof(u64);
        buf = kmalloc(size, GFP_KERNEL);
        i = copy_from_iter(buf, size, msg);
        for (j = 0; j < i; j++) {
            hash[j] ^= buf[j];
        }
        kfree(buf);
    }

    // hash
    for (i = 0; i < h->rounds; i++) {
        for (j = 0; j < size; j++) {
            hash[j] = hash[(j+8)%size] ^ 0xAC ^ i;
        }
    }
    return size;
}
```

The `null_hash` hash function is basically a null function, but the `secure_hash` function is
interesting. First, `h->length` qwords of the Hash structure are initialized witht the key, and then
this much data from the input is used to initialize the hash array. If there is more than enough
input, the rest is xored character by character into this structure. After this, the actual hashing
is performed through a simple xor scheme.

## Kernel Leak

As mentioned above, the `OPTION_DEBUG` ioctl could be used to leak a kernel pointer. While it would
be possible to look at the `sock` structure in the 
[kernel source](https://elixir.bootlin.com/linux/latest/source/include/net/sock.h) and determine 
what members of the structure would be kernel pointers, it is easier to just test different offsets 
and see which leaks resemble a kernel pointer. By doing this, I (actually my teammate mmaekr)
determined that offset 5 was a kernel pointer. By checking in `/proc/kallsyms`, we determined that
this pointer was actually the address of the `tcp_prot` structure. We can use this and subtract the
static offset to determine the kernel base.

```
/ # /bot
[*] Socket FD: 0x3
[*] Kernel Leak: 0xffffffff9a2f9d60
[*] Kernel Base: 0xffffffff98a00000
/ # cat /proc/kallsyms | grep ffffffff9a2f9d60
ffffffff9a2f9d60 D tcp_prot
```

## Rabbit Hole (Why to Disassemble)

Besides the obvious kernel leak, I noticed a few additional things that stood out in this source
code. In the ioctl function, I noticed that there was kernel heap activity through kmalloc and
kfree, and I also noticed that there was no mutex. In the `stonks_rocket` function, I noticed that
the `Hash` structure was created on the stack, and I noticed that the pointer to this structure, a
stack pointer, was passed as an argument to the hash function. I also noticed that there was a use
of the `iov_iter` structure, which I did not know about and hoped that I wouldn't have to
understand. In the `secure_hash` function, I noticed that there was no bounds checking on
`h->length`, so you could initialize data after the 4 qwords in the `Hash` structure. This is
obviously a stack overflow, and I was very excited to see such a simple and obvious bug. 

```
struct Hash {
    u64 word1;
    u64 word2;
    u64 word3;
    u64 word4;
    unsigned length;
    u64 rounds;
    u64 key;
};
```

First, look at the structure of the `Hash` above. After the 4 main qwords, the length is stored,
followed by the rounds and the key. When the hash data is initialized, each part is assigned to the
key. I noticed that having a length over 5 and a large key value would lead to `key` number of
qwords being set to `h->key` when the hash was initialized, and this could easily lead to faulting
on the guard page. To cope with this, I set key to a smaller value, like 10, and observed what
happened. However, this led to a very disappointing outcome, and I got an error message containing
the most disappointing string: "Buffer overflow detected." This meant that the program noticed my
attempt and chose to panic the program. For a long period, I thought that this was due to a stack
canary, and I tried to find a way to use the hash function to leak the canary.

After a while, I decided to look in Binary Ninja to determine what was really happening. I noticed
that part of the `stonks_rocket` function was split into a separate function, `stonks_rocket.cold`.
This function used `__x86_indirect_thunk_rax` to call the hash function of the `StonksSocket`
structure, and then it printed our buffer overflow error and panicked if the return value was
greater than or equal to 0x38. Looking into the hash function, I noticed that the size was returned,
and this size was set to `h->length * sizeof(u64)`. This means that the program will print an error
if we touch any data on the heap after our `Hash` struct. It is possible to have `size` be
uninitialized if `h->length` is 0. In this case, `size` is register r12, which is the return value
of `tcp_recvmsg`. This means that we can force the `size` to be different than `h->length *
sizeof(u64)`, but this is relatively meaningless because we still can't hash data outside of the
boundaries of 0x38. This was a sad conclusion to this bug caused by modern mitigations.

## Race Condition

Around this point, I decided to look at the other ioctl a bit more, the `OPTION_PUT` ioctl. As
mentioned earlier, this frees the `sk->sk_user_data` structure, and then it sets this to NULL. If
there was a possible race condition here, it would involve being able to have access to this
structure after it is freed. Luckily, in the beginning of `stonks_rocket`, this pointer is assigned
to a local variable!

```
struct StonksSocket *s_sk = sk->sk_user_data;
```

This is perfect, because through `s_sk`, we can reference offsets into a fake `StonksSocket` on the
heap, which will actually be some other type of object. However, why is this useful to us? That
requires us to understand the members of this `StonksSocket` structure a bit more, as well as the
size of it.

```
struct StonksSocket {
    unsigned hash_size;
    u64 hash_rounds;
    u64 hash_key;
    int (*hash_function)(struct iov_iter *msg, struct Hash *hash);
};
```

As can be seen, we have complete control of the `hash_size`, `hash_rounds`, and `hash_key` members
through the ioctl anyway. However, we are forced to choose between two `hash_function` values. If we
can create a chunk of size 0x20 in the kernel heap with user controlled data at offset 0x18, we can
call an arbitrary function! This is a great primitive, but this requires us to understand some
useful kernel heap objects a bit more.


TODO: FINISH
