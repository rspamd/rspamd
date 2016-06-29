---
layout: doc
title: Usage of fuzzy hashes
---

# Usage of fuzzy hashes

## Introduction

Fuzzy hashes are used to search for similar messages – i.e. you can find messages with the same or a slightly modified text using this method. This technology is well suited for blocking spam that is simultaneously sent to many users. Since the hash function is unidirectional, it is impossible to restore the original text using hash only. And this allows you to send requests to third-party hash storages without risk of disclosure.

It should be emphasized that fuzzy hashes are applied not only for the text data but also for the images and other attachments in emails. However, in this case, due to missing fuzzy logic element rspamd looks for exact matches for similar objects.

This article is intended for mail system administrators who want to create their own hash storage and maintain it themselves.

## Step 1: Hash sources selection

The first step is to choose the sources of spam samples to learn on. The basic principle is to use spam that a lot of users receive, for learning. There are two main approaches to this task:

- working with users complaints;
- creating spam traps (honeypot).

### Working with users complaints

Users are one of the resources for evaluation of the quality of the spam filtering system. Therefore it is preferably to provide a mechanism for improving hash storages by working with user complaints. Unfortunately, users usually complain about legitimate mailing they’ve subscribed on to by themselves: distribution stores, notification systems from tickets booking and even personal emails, which they do not like for some reason. Many users simply do not see the difference between "Delete" and "Mark as Spam" buttons. Perhaps a good idea would be to prompt the user for additional information about the complaint, for example, why he or she decided that it is a spam email, as well as to draw the user's attention to the fact that user is able to unsubscribe from receiving mailings.

Another way to solve this problem is manual processing of user spam complaints, or combination of methods: assign greater weight to the handcrafted emails, and a smaller one to all the other complaints.

There are also two features in rspamd allowing filtering out some false alarms:

1. Hash weight.
2. Learning filters.

The first method is pretty simple: let's assign some weight to each complaint, and then we will add it to the stored value corresponding to the hash for the each next learning step. While verification we will not take into consideration hashes, which weights are less than a predetermined threshold. For instance, if the weight of complaint is w=1 and the threshold is t=20, then the beginning of the hash operation requires at least 20 user complaints. In addition, while verification for hashes, which weights are more than a predetermined threshold, rspamd assigns not the maximum score but scores size gradually increases from zero to a maximum (up to metric value) when the threshold of hash weight changes up to the twice threshold value (t .. 2 * t).

<center><img class="img-responsive" src="/img/rspamd-fuzzy-1.png" width="50%"></center>

The second method, learning filters, allows you to write some conditions, which prohibit the learning, on Lua language, for instance, for emails from a specific domain (for example, facebook.com). The possibilities of the filters are quite extensive, however they require manual setting and configuring.

### Configuring spam traps

This method requires a mailbox that doesn't receive legitimate emails but spam emails instead. The main idea is to show the address in the databases of spammers, but not to show it to legitimate users. For example, to do so it is enough to put *iframe* element on a fairly popular website. This element is not visible to users, it has *hidden* property or no apparent size, but it contains email-bots available email addresses traps. Recently, this method has become not so effective, as spammers have learnt how to circumvent these techniques.


Another possible way to create a trap is a search for domains that were previously popular, but they are not working at the moment (addresses from these domains are found in many spam databases). In this case, learning filters are required as the legitimate emails, for instance, social networking or distribution services, likely will be blacklisted.

In general, setting own traps is warranted when it is only a large mail system, because it might be costly both in terms of maintenance problems, and as direct material costs to purchase domains.

## Step 2: Configuring storage

This chapter specifies basic storage settings and how to optimize its performance.

**Important note:** storage does not work with emails but with ready hashes. Hence, in order to convert the email into its hash, a separate scanner or process controller is required:

<center><img class="img-responsive" src="/img/rspamd-fuzzy-2.png" width="75%"></center>

Storage functions:

1. Data storage and review
2. Transport Protocol Encryption
3. Obsolete hashes removal
4. Access Control (read and write)
5. Replication (since v. 1.3)


### Storage architecture

sqlite3 is used for data storage, and it imposes some restrictions on the storage architecture.

Firstly, sqlite quite poorly works with competing requests on write: in this case, the DBMS performance drops by several orders of magnitude. Secondly, it is quite difficult to ensure replication and scaling the database as it requires third-party tools.

Thereby hash storage rspamd always writes to the database strictly from one process. For this purpose, one of the processes leads updates queue, and other processes simply transmit write requests from clients to this common queue. Queue is written to the disk once per minute. Thus the store is designed for the load profile with a predominance of read requests.

### Hash obsolete

Another major priority of storage is the process of removing obsolete hashes from the database. As the duration of spam mailings is always limited, there is no reason to store hashes permanently. It would be better to verify the quantity of hashes coming to learn for some time, with sufficient storage size of RAM. For example, 400 thousand hashes occupy about 100 Mb and 1.5 million hashes occupy 0.5 Gb.

It is not recommended to increase storage volume up to the volume bigger than available RAM size due to a significant deterioration in performance. Furthermore, it makes no sense to store the hashes for longer than about three months. Therefore, if you have a small amount of hashes suitable for learning, it is better to establish the obsolescence of 90 days. Otherwise it is better to set a shorter period of obsolescence.

### Example of configuration

The rspamd process is responsible for fuzzy hashes storage called `fuzzy_storage`. To turn on and configure this process we may use the local file of rspamd configuration: `etc/rspamd/rspamd.conf.local`:

~~~ucl
worker "fuzzy_storage" {
  # Socket to listen on (UDP and TCP from rspamd 1.3)
  bind_socket = "*:11335";

  # Number of processes to serve this storage (useful for read scaling)
  count = 4;

  # Where data file is stored (must be owned by rspamd user)
  database = "${DBDIR}/fuzzy.db";

  # Hashes storage time (3 months)
  expire = 90d;

  # Synchronize updates to the storage each minute
  sync = 1m;
}
~~~

### Configuration of access

rspamd does not allow to modify the data in the repository by default. It is required to specify a list of trusted IP-addresses and/or networks to make learning possible. Practically, it is better to write from the local address only (127.0.0.1) because fuzzy storage uses UDP, which is not protected from forgery of the source IP-address. Such leak of protection is fixable by adjusting the reverse path verification on the router, but system administrators usually ignore this way):

~~~ucl
worker "fuzzy_storage" {
  # Same options as before ...

  allow_update = ["127.0.0.1"];

  # or 10.0.0.0/8, for internal network
}
~~~

Also transport encryption might be used for the access control, and we will consider further.

### Transport encryption

Protocol for operating with the hash storage allows to include optional (opportunistic) or mandatory encryption based on a public key. Encryption architecture is based on cryptobox design: <https://nacl.cr.yp.to/box.html> and it is similar to the algorithm for end-to-end encryption dnscurve: <https://dnscurve.org/>.

To set transport encryption first of all it is necessary to create a pair of keys for storage server with the command `rspamadm keypair -u`:

~~~ucl
keypair {
    pubkey = "og3snn8s37znxz53mr5yyyzktt3d5uczxecsp3kkrs495p4iaxzy";
    privkey = "o6wnij9r4wegqjnd46dyifwgf5gwuqguqxzntseectroq7b3gwty";
    id = "f5yior1ag3csbzjiuuynff9tczknoj9s9b454kuonqknthrdbwbqj63h3g9dht97fhp4a5jgof1eiifshcsnnrbj73ak8hkq6sbrhed";
    encoding = "base32";
    algorithm = "curve25519";
    type = "kex";
}
~~~

This command creates a **unique** pair of keys, where **public** key might be copied manually to the customer's host (e.g. via ssh) or published in any way to guarantee the reliability (e.g. certified digital signature or HTTPS-site hosting).

Each store is able to work simultaneously with any number of keys:

~~~ucl
worker "fuzzy_storage" {
  # Same options as before ...
  keypair {
    pubkey = ...
    privkey = ...
  }
  keypair {
    pubkey = ...
    privkey = ...
  }
  keypair {
    pubkey = ...
    privkey = ...
  }
}
~~~

This feature is useful for creating closed storages where access is allowed only to those customers who is aware about one of the public keys:

<center><img class="img-responsive" src="/img/rspamd-fuzzy-3.png" width="75%"></center>

To enable a mandatory encryption mode `encrypted_only` option is used:

~~~ucl
worker "fuzzy_storage" {
  # Same options as before ...
  encrypted_only = true;

  keypair {
    ...
  }
  ...
}
~~~

Clients who do not have a valid public key are not able to access the location in this mode.

### Storage testing

To test the storage we can use `rspamadm control fuzzystat` command:

```
Statistics for storage 73ee122ac2cfe0c4f12
invalid_requests: 6.69M
fuzzy_expired: 35.57k
fuzzy_found: (v0.6: 0), (v0.8: 0), (v0.9: 0), (v1.0+: 20.10M)
fuzzy_stored: 425.46k
fuzzy_shingles: (v0.6: 0), (v0.8: 41.78k), (v0.9: 23.60M), (v1.0+: 380.87M)
fuzzy_checked: (v0.6: 0), (v0.8: 95.29k), (v0.9: 55.47M), (v1.0+: 1.01G)

Keys statistics:
Key id: icy63itbhhni8
        Checked: 1.00G
        Matched: 18.29M
        Errors: 0
        Added: 1.81M
        Deleted: 0

        IPs stat:
        x.x.x.x
                Checked: 131.23M
                Matched: 1.85M
                Errors: 0
                Added: 0
                Deleted: 0

        x.x.x.x
                Checked: 119.86M
                ...
```

Primarily, a general storage statistics is shown, namely the number of stored and obsolete hashes, as well as the requests distribution for versions of the client Protocol:

* `v0.6` - requests from rspamd 0.6 - 0.8 (older versions, compatibility is limited)
* `v0.8` - requests from rspamd 0.8 - 0.9 (partially compatible)
* `v0.9` - unencrypted requests from rspamd 0.9 - 1.3 (fully compatible)
* `v1.1` - encrypted requests from rspamd 1.1 - 1.3 (fully compatible)
* `v1.3` - encrypted and unencrypted requests from rspamd 1.3+

And then detailed statistics is displayed for each of the keys configured in the storage and for the latest requested client IP-addresses. In conclusion, we see the overall statistics on IP-addresses.

To change the output from this command, we may use the following options: (e.g. `rspamadm control fuzzystat -n`):

* `-n`: display raw numbers without reduction
* `--short`: do not display detailed statistics on the keys and IP-addresses
* `--no-keys`: do not show statistics on keys
* `--no-ips`: do not show statistics on IP-addresses
* `--sort`: sort:
  + `checked`: by the number of trusted hashes (default)
  + `matched`: by the number of found hashes
  + `errors`: by the number of failed requests
  + `ip`: by IP-address lexicographically

## Step 3: Configuring plugin `fuzzy_check`

Plugin `fuzzy_check` is used by scanner processes for email validation and by  controllers proceses for storage learning.

Plugin functions:

1. Email processing and hashes creating of their parts
2. Querying the repository
3. Transport Encryption

Learning is performing by `rspamc fuzzy_add` command:

```
$ rspamc -f 1 -w 10 fuzzy_add <message|directory|stdin>
```

Where `-w` parameter is for setting the hash weight discussed above. `-f` parameter specifies the flag number.

Flags are allowed to store hashes of different origin in storage. For example, the hash of spam traps, hashes of user complaints and hashes of emails from the "white" list. Each flag may be associated with its own character and have a weight while checking emails:

<center><img class="img-responsive" src="/img/rspamd-fuzzy-4.png" width="75%"></center>

To configure compliance of symbols with flags we must go to the `rule` section.

Example:

~~~ucl
fuzzy_storage {
  # Global options

  # Rule definition
  rule "rspamd.com" {
    # Fuzzy storage servers list
    servers = "rspamd.com:11335";

    # Public key for transport encryption
    encryption_key = "icy63itbhhni8bq15ntp5n5symuixf73s1kpjh6skaq4e7nx5fiy";

    # Symbol for unknown flags
    symbol = "FUZZY_UNKNOWN";

    # Additional mime types to store within fuzzy storage
    mime_types = ["application/*"];

    # Hash weight threshold
    max_score = 20.0;

    # Whether we can learn this fuzzy
    read_only = yes;

    # Ignore unknown flags
    skip_unknown = yes;

    # Hashes generation algorithm
    algorithm = "siphash";

    # Map flags to symbols
    fuzzy_map = {
        # Key is symbol name
        FUZZY_DENIED {
            # Local threshold
            max_score = 20.0;
            # Flag to match
            flag = 1;
        }
        FUZZY_PROB {
            max_score = 10.0;
            flag = 2;
        }
        FUZZY_WHITE {
            max_score = 2.0;
            flag = 3;
        }
    }
  }
}
~~~

Let’s consider some useful options that can be set in the module.

Firstly, `max_score` is useful to specify the threshold weight of the hash:

<center><img class="img-responsive" src="/img/rspamd-fuzzy-1.png" width="50%"></center>

Another useful option is `mime_types` determining the types of attachments to check (and perform the learning) in the repository. This parameter is a list of valid types in the format `["type/subtype", "*/subtype", "type/*", "*"]`, where `*` replaces any valid type. As a rule, it is quite useful to save the hashes of all `application/*` attachments. Texts and embedded images are automatically checked by `fuzzy_check` plugin, i.e. there is no need to add `image/*` in the list of scanned attachments. It should also be considered that attachments and images are scanning for the exact match as distinct from the text, which may differ slightly.

`read_only` is quite important option for storage learning. It is set to `read_only=true` by default, and it means that storage learning is restricted:

~~~ucl
read_only = true; # disallow learning
read_only = false; # allow learning
~~~

`Encryption_key` parameter specifies the **public** storage key and enables encryption requests.

`Algorithm` parameter specifies the algorithm generating hashes from text parts of emails (for attachments and images are always used [blake2b](https://blake2.net/)). Initially rspamd was using siphash algorithm. However, it has some performance issues, especially on obsolete hardware (CPU until Intel Haswell). Therefore it will be better to use other faster algorithms when we create our own storage:

* `xxhash`
* `mumhash`
* `fasthash`

For major tasks we would recommend to use `mumhash` or `fasthash` demonstrating excellent performance on a variety of platforms. To evaluate the performance we are able to compile a set of the tests from rspamd source code:

```
$ make rspamd-test
```

and run the test of different variants of hashes calculation algorithms on user’s platform:

```
test/rspamd-test -p /rspamd/shingles
```

**Important note:** it is not possible to change the parameter without losing all the data in the storage, as only one algorithm can be used simultaneously for each storage and conversion of one type of hash to another is not possible, because full initial data recovery by hash is impossible by design.
