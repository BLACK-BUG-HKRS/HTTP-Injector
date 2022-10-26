# HTTP-Injector
HTTP responses injector!

to run this:

- `pip3 install -r requirements.txt`

Enable IP Forwarding using [this Python script](https://github.com/BLACK-BUG-HKRS/ARP-spoofer), then it automatically enables it.

If you want to sniff http packets in the network, you gonna need the man-in-the-middle (MITM) using ARP spoofing, then you run the script.

You will find ARP spoofer and how to use it [here](https://github.com/BLACK-BUG-HKRS/ARP-spoofer), start ARP Spoofing against the target on [Kali Linux](https://www.kali.org/get-kali/).

Add new nfqueue FORWARDING rule on `iptables` :

```
$ iptables -I FORWARD -j NFQUEUE --queue-num 0
```

When you're done, make sure you CTRL+C the ARP spoof script, disable IP forwarding and flushing the iptables:
```
$ iptables --flush
```
