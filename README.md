# Fuse-Kai

Client for [KV-Server](git@github.com:JohndeVostok/KV-server.git).

#### Dependencies

fuse3
json-c
glib-2.0
libcurl

#### Installation & Usage

    sudo apt-get install libfuse-dev libjson-c-dev libcurl4-gnutls-dev libglib2.0-dev
    # You may also need to add several paths to your shell .rc
    ./compile.sh
    ./a.out [target directory]

#### Implementation Details

Directories are handled by examples/passthrough.c.

Permissions are fixed to 0755.

Each file stores 3 int: q0, q1, len. i.e. The key of the file and its length.

Block size is set to 4Kb (NOT 4KB), and each block of data is encoded by base64 in order to fix into json string.

The key string is a json string containing q0, q1 and block\_id.

The value string is the base64-encoded string.

The overall procedure is as follows:

    +--------+  Split to blocks  +------------+ Base64 +------------------+
    |Raw Data|------------------>|Blocked Data|------->|Base64 String Data|
    +--------+  Border handling  +------------+ Encode +------------------+
                                                               |
                                                           As  |  Value
                                                               v
    +-----------+   JSON     +---------------+   As    +--------------+
    |Stored Keys|----------->|JSON Key String|-------->|Key-Value Pair|
    +-----------+ Stringify  +---------------+   Key   +--------------+
                                                               |
                                                         HTTP  |  Pack
                                                               v
                                     +------+   CURL   +-----------------+
                                     |Server|<---------|HTTP POST Request|
                                     +------+ Perform  +-----------------+

Multithreading disabled due to json-c library not supporting parallel creating, even on different objects.

Parallel request disabled due to difficulties on curl callback functions with HTTP/TCP half-transferred packets. (UDP may completely bypass this issue, while the server currently doesn't support it).
