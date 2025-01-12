---
title: Finding Lost Spirits in the DHT
date: 2024-12-28
draft: False
banner: header.png
banner_desc: View from the Grand Dune in Merzouga, Morocco
---

I was curious about constructing an ID scheme that has a watermark that can only
be verified by those with a private key.
This is meant as a signalling mechanism over networks like the mainline
bittorrent DHT, so you could passively identify nodes with the IDs though
general usage and / or signal events have occured.
I also wanted anyone with your public key to be able to create these IDs
(otherwise I could obviously just use prearranged IDs, etc).

The main problem is that the mainline DHT has 20 byte node IDs, which limits
how much info we can place in them, so I eventually settled on using ECDH with
weaker custom curves and point compression to fit within size constraints.
If you have more than 40 bytes to work with, I'd just use Curve25519 and how
much of the partial hash you want to limit false positives for identification,
and avoid the custom curves.

As always, I am not a cryptographer and this scheme is probably broken in tons
of dumb ways. Just putting an idea out there so I can be torn to shreds :)
We are doing ECC with curves I randomly generated and using a random python
library that isn't for security applications.
Consider yourself warned.

I used 120 bit ECDH keys (so roughly 60 bits in strength, so it'll cost at least
$10,000 or so based on what I could gather the current cost to break DES is),
with 40 bits to counteract false positives.

The idea is partly inspired by how `alt.anonymous.messages` worked, where you
would have to try and attempt to decrypt every message posted to group to find
messages meant for you, which is one way of implementing a [PIR scheme](https://en.wikipedia.org/wiki/Private_information_retrieval).

Source is here [@bahorn/dht-spirits](https://github.com/bahorn/dht-spirits).

## Construction

We need to do a few things:
* Setup a custom curve
* Implement ECDH with it
* Implement Point compression
* Bring it all together

### Setting up the curve

First we want to generate a custom ECDH curve, for which I used [ecgen](https://github.com/J08nY/ecgen):
```
$ ./ecgen --fp -u -p -r 120
[
{
    "field": {
        "p": "0xda1340f1fd447a6dabddca2d478e93"
    },
    "a": "0x07f5fbf050f50defd961c2195aa3a7",
    "b": "0x21777d5d9db4a81066bfb4eea4047c",
    "order": "0xda1340f1fd447a660d568e634df589",
    "subgroups": [
        {
            "x": "0x71b5cb788f936abc21251be0cd2529",
            "y": "0x18acf357258ff1aab9a2f0f2d37735",
            "order": "0xda1340f1fd447a660d568e634df589",
            "cofactor": "0x1",
            "points": [
                {
                    "x": "0x71b5cb788f936abc21251be0cd2529",
                    "y": "0x18acf357258ff1aab9a2f0f2d37735",
                    "order": "0xda1340f1fd447a660d568e634df589"
                }
            ]
        }
    ]
}]
```

I have no idea if these are good parameters, so you really want to investigate
that further yourself.
I just chose a prime field of 120 bits as that would allow me to represent
public keys with 15 bytes.
I used `-p` as I think having a prime order is good, but I have no clue.

Maybe use `-K` without `-p` as koblitz curves seem to work well with certain
ECDH implementations.

Which I loaded with [tinyec](https://github.com/alexmgr/tinyec) with:
```python3
import tinyec as ec

def gen_curve(j):
    p = int(j['field']['p'], 16)
    x = int(j['subgroups'][0]['x'], 16)
    y = int(j['subgroups'][0]['y'], 16)
    order = int(j['subgroups'][0]['order'], 16)
    field = ec.SubGroup(p, (x, y), order, 1)

    curve = ec.Curve(int(j['a'], 16), int(j['b'], 16), field)
    return curve

curve = gen_curve(json.load(open('path/to/curve.json'))[0])
```

### Implementing ECDH

ECDH is easy to implement with the library, just multiply your private key by
the peers public key:

```python3
import secrets

class ECKey:
    """
    Our wrapper around tinyec to do ECDH and generate keys that meant our
    requirements.
    """

    def __init__(self, curve=None, key=None, include_odd=False):
        if curve:
            self._curve = curve
        else:
            from tinyec import registry
            self._curve = registry.get_curve('brainpoolP256r1')

        self._include_odd = include_odd

        if key:
            self._privkey = key
            self._pubkey = self._privkey * self._curve.g
        else:
            self.gen_key()

    def gen_key(self):
        """
        Generate a key that conforms to the requirements.
        """
        self._privkey = secrets.randbelow(self._curve.field.n)
        self._pubkey = self._privkey * self._curve.g

        while not self._include_odd and (self._pubkey.y % 2) != 0:
            self._privkey = secrets.randbelow(self._curve.field.n)
            self._pubkey = self._privkey * self._curve.g

    def pubkey(self):
        return compress(self._pubkey, include_odd=self._include_odd)

    def share_key(self, pubkey):
        """
        Just deriving a shared secret.
        """
        peer = decompress(
            self._curve,
            pubkey,
            include_odd=self._include_odd
        )

        return self._privkey * peer
```


You will notice this calls `compress()` and `decompress()`, which we will
implement next. The slightly weird `gen_key()` implementation is so the public
key always has an even y coordinate, which is just a space saving measure for
the compression part.

### Implementing Point Compression

Point compression is a bit harder to do, but not overly difficult. I used the
scheme described in [this blog post by Matthias Valvekens](https://mvalvekens.be/blog/2022/ecc-point-compression.html).


First, lets implement compression:
```python3
import math

def compress(point, include_odd=True):
    """
    Compress a curve point.
    """
    p = point.curve.field.p
    # determine how many bytes this curve needs to represent a point.
    count = math.ceil(math.ceil(math.log2(p)) / 8)

    top = b''
    if include_odd:
        top = bytes([0x32 if (point.y % 2 == 0) else 0x33])
    else:
        assert point.y % 2 == 0

    res = point.x.to_bytes(count, byteorder='big', signed=False)

    return top + res
```

You'll notice I included the `include_odd` argument.
The idea here is that if we force the public keys (which are points on the
curve) to always have an even y value, we don't need to indicate it.

Now moving onto decompression:

```python3
def decompress(curve, compressed, include_odd=True):
    """
    Decompress a curve point
    """
    if include_odd and compressed[0] not in [0x32, 0x33]:
        raise Exception('Invalid Point, missing label')
    # This is just a hack to save a byte if we make the y always even
    s = 0
    if include_odd and compressed[0] == 0x33:
        s = 1

    start = 1 if include_odd else 0

    x = int.from_bytes(compressed[start:], byteorder='big', signed=False)

    if x >= curve.field.p - 1:
        raise Exception('Invalid point, larger than p - 1')

    y_ = modular_sqrt(x**3 + x * curve.a + curve.b, curve.field.p)

    if s == (y_ % 2):
        res = ec.Point(curve, x, y_)
    else:
        res = ec.Point(curve, x, curve.field.p - y_)

    if not res.on_curve:
        raise Exception('Invalid Point, not on curve')

    return res
```

I ended up stealing my implementation of `modular_sqrt()` from
[here](https://gist.github.com/nakov/60d62bdf4067ea72b7832ce9f71ae079)

Now you can test the code works ok with the following, and see how many random
numbers pass the decompression code:
```python3
def test_decompress(curve):
    # tinyec outputs warnings if a point is not on the curve
    import warnings
    warnings.filterwarnings("ignore")
    c = 0
    for i in range(1000):
        try:
            decompress(curve, secrets.token_bytes(15), False)
            c += 1
        except Exception:
            continue
    print(c)
    warnings.filterwarnings("default")
```

### Bring it all together

Finally, we can hack up a class to implement the identifiers:

```python3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SECRET = b'random_secret'
LENGTH = 20


class Identify:
    """
    Our class to wrap up the Identifiers.

    Call with .gen(peer) to construct an identifier that the peer can validate.
    Call .verify(identifier) to validate one with your keys.
    """
    def __init__(self, curve, key=None, secret=SECRET, length=LENGTH):
        self._ec = ECKey(curve, key=key, include_odd=False)
        self._length = length
        self._secret = secret

    def pubkey(self):
        return self._ec.pubkey()

    def get_hash(self, peer, length):
        shared_key = compress(self._ec.share_key(peer))
        dervied_key = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=self._secret
        ).derive(shared_key)
        return dervied_key

    def gen(self, peer):
        pubkey = self.pubkey()
        length = self._length - len(pubkey)
        token = self.get_hash(peer, length)
        return pubkey + token

    def verify(self, combo):
        length = len(self.pubkey())
        pubkey, hash = combo[:length], combo[length:]
        return self.get_hash(pubkey, length=len(hash)) == hash
```


And test it all works fine with:
```python3
import base64
import binascii

def step(curve):
    a = Identify(curve)
    b = Identify(curve)
    c = Identify(curve)
    a_p = a.pubkey()
    b_p = b.pubkey()
    c_p = c.pubkey()
    print(
        binascii.hexlify(a.gen(b_p)).decode('ascii'),
        base64.b64encode(a.gen(b_p)).decode('ascii')
    )
    assert b.verify(a.gen(b_p))
    assert a.verify(b.gen(a_p))
    assert not a.verify(b.gen(c_p))
```

So you should now be able to find the lost spirits wandering the earthly plane.

## Attacks

Just a few things to note:
* Cracking your private key. Can't do much here as this a strength / false
  positive trade off with the DHTs small ID space.
* Flooding / Sybil attacks. Anyone can generate the IDs so this can be an issue
  depending on your application.
* Client behaviour being identifiable. This is just an ID scheme and if you can
  identify a client based on its behaviour you can bypass the need to crack the
  ID scheme.
* Biases in whats a valid public key, i.e what x values are valid. Can probably
  obtain a better than random chance here to guess if something is a node id.


## Extentions

* Hashcash your way to extra data being stored. If you overlay part of your
  public key with bytes from the output you can get a bit better space usage.
  Just a trade off between compute here, but this is potentially how you would
  want to implement support for the DHT security extentions that require your
  node ID to depend on your external IP without having to use smaller curves.
* Maybe do this over BLE device names, Wifi SSIDs or via certificate
  transparency lists. No reason you can't directly use this over either.
