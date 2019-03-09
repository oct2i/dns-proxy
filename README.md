# Сaching Dns proxy

Сaching Dns proxy in the form of GNU/Linux kernel module.

Module was written and tested on Ubuntu 12.04.5 Server 32-bit (3.13 kernel), GCC 4.6.3.

Restrictions:
* support only protocol IPv4
* handles only requests of type A (i.e. conversion of the domain to the protocol IPv4)
* limited cache size (specified during configuration)
* delete cache on shutdown or restart (cache is located in RAM)


## Main moments
### Listening of network traffic

The path of the package inspection in the system **Netfilter**:
```txt
         +------------------+
        /                  /|
       +------------------+ |
       |                  | |
       |  Network driver  | |
       |                  |/
       +------------------+
                 |
                 V
      +-----------------------+
     /                       /|
    +-----------------------+ |
    |                       | |
    |  NF_INET_PRE_ROUTING  | |
    |                       |/
    +-----------------------+
                 |
                 V
            +-----------+             +-----------------------+
           /           /|            /                       /|
          +-----------+ |           +-----------------------+ |
          |           | |           |                       | |
          |  Routing  | | --------> |    NF_INET_LOCAL_IN   | |
          |           |/            |                       |/
          +-----------+             +-----------------------+
                 |                               |
                 |                               V
      +-----------------------+         +--------------------+
     /                       /|        /                    /|
    +-----------------------+ |       +--------------------+ |
    |                       | |       |                    | |
    |    NF_INET_FORWARD    | |       |  Local IP service  | |
    |                       |/        |                    |/
    +-----------------------+         +--------------------+
                 |                               |
                 V                               V
            +-----------+             +-----------------------+
           /           /|            /                       /|
          +-----------+ |           +-----------------------+ |
          |           | |           |                       | |
          |  Routing  | | <-------- |   NF_INET_LOCAL_OUT   | |
          |           |/            |                       |/
          +-----------+             +-----------------------+
                 |                      
                 V
      +-----------------------+
     /                       /|
    +-----------------------+ |
    |                       | |
    |  NF_INET_POST_ROUTING | |
    |                       |/
    +-----------------------+
                 |
                 V
         +------------------+
        /                  /|
       +------------------+ |
       |                  | |
       |  Network driver  | |
       |                  |/
       +------------------+
```


### Data processing

The format of the network packet:
```txt
      +----------+----------+----------+--------+
     /          /          /          /        /|
    +----------+----------+----------+--------+ |
    |          |          |          |        | |
    |   MAC    |    IP    |   UPD    |  DNS   | |
    |  header  |  header  |  header  |  data  | |
    |          |          |          |        |/
    +----------+----------+ ---------+--------+
```


### Forming a reply message

The structure of the DNS packet:
```txt
      +----------+------------+----------+-------------+--------------+
     /          /            /          /             /              /|
    +----------+------------+----------+-------------+--------------+ |
    |          |            |          |             |              | |
    |  Header  |  Question  |  Answer  |  Authority  |  Additional  | |
    |          |            |          |             |              |/
    +----------+------------+ ---------+-------------+--------------+
```


## How works caching Dns proxy

Scheme of work module:
```txt
                        +----------------------------------------------+
                       /|                                             /|
                      +----------------------------------------------+ |
                      | |                                            | |
                      | |               Gateway machine              | |
                      | |                                            | |
                      | |      ________________________________      | |
      +---------+     | |     |                                |     | |       +----------+
     /         /|     | |     |            Kernel              |     | |      /          /|
    +---------+ |     | |     |                                |     | |     +----------+ |
    |         | |     | |     |   +-------+     +----------+   |     | |     |   Dns    | |
    |  Client | |-----|-------|-->|  Dns  |---->| iptables |---|-----|------>|  Server  | |
    |(browser)| |<----|-------|---| proxy |<----|  (NAT)   |<--|-----|-------|    on    | |
    |         |/      | |     |   +-------+     +----------+   |     | |     | Internet |/
    +---------+       | |     |      | ^                       |     | |     +----------+
                      | |     |      V |                       |     | |
                      | |     |   +-------+                    |     | |
                      | |     |   | Cache |                    |     | |
                      | |     |   +-------+                    |     | |
                      | |     |________________________________|     | |
                      | |                                            | |
                      | |____________________________________________|_|
                      |/                                             |/
                      +----------------------------------------------+
```


## Cache

The entire cache is stored in RAM PC. Cache is implemented on a data structure: the hash table.

The hash table is static and has a fixed size. The size is defined in the header file `dnsproxy.h` constant `HASHTAB_SIZE`.

Used the **RS hash function** (for strings).

Function listing:
```c
static unsigned int rs_hash(unsigned char *str, unsigned int len)
{
    unsigned int b = 378551;
    unsigned int a = 63689;
    unsigned int hash = 0;
    unsigned int i = 0;

    for (i = 0; i < len; str++, i++){
        hash = hash * a + (unsigned char)(*str);
        a *= b;
    }
    
    return (hash % HASHTAB_SIZE);
}
```
Advantage hash function: 
* fast calculation of the hash code
* deterministic
* uniform distribution of hash values


## Installing

Building:
```bash
$ make
```
Installing:
```bash
$ make install
```
Uninstalling:
```bash
$ make uninstall
```


## License

This software is licensed under the terms of the GNU General Public License version 2.
