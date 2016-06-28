# Included from top-level .conf file

type = "fuzzy";
hash_file = "${DBDIR}/fuzzy.db";
expire = 90d;
allow_update = ["localhost"];

# Slave example (disabled by default)
/*
sync_keypair {
    pubkey = "53e6yt94fqbzccdqcsmoughxfxed7figuefkbs8f3hsybn3t9xhy";
    privkey = "eth4rod5xigw55tagtpo4ka98mya4nx8765wh5zozgjdk5weqd5y";
    id = "yf4mzjp5aexr39a9ijksth6cwumaxztg8iw84oee55n7hj6jkkhbtuwmph75ybsk79bm79cmmtz8ummzkeie4g4ony5x3z9i1hn5fqb";
    encoding = "base32";
    algorithm = "curve25519";
    type = "kex";
}

masters = "master.example.com";
master_key = "tmpaorg6cdyqia79wmy99j546tdj9muc9coou8ns9au6dubhxcfy";
*/

# Master example (disabled by default)

/*
sync_keypair {
    pubkey = "tmpaorg6cdyqia79wmy99j546tdj9muc9coou8ns9au6dubhxcfy";
    privkey = "a9d4kuz4grfienkfhuhreeiqqscng7sxntbnemkyo1ejxestquty";
    id = "q455stnkqf9r6f1e3bhcbdys9e179b97ymz1exb4ogwxxgerazz1nwy1sssrsri3ydjdag46ziok1ufx3xqifugdnewaqg4dsrdna8y";
    encoding = "base32";
    algorithm = "curve25519";
    type = "kex";
}
slave {
        name = "slave1";
        hosts = "slave.example.com";
        key = "53e6yt94fqbzccdqcsmoughxfxed7figuefkbs8f3hsybn3t9xhy";
}
*/
