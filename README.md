# PHP2Shell: sub-1 MiB PHP CLI server crash lab

This repository reproduces a two-request crash in PHP's built-in CLI web server using the session upload-progress path. It is a local, loopback-only differential lab for PHP 8.4.26 and 8.4.27. **It does not demonstrate information disclosure or remote code execution.**

The multipart request bodies are 355,594 bytes (A1) and 520,552 bytes (B1). A1 places session upload progress ahead of many nested file fields and triggers a pre-script out-of-memory condition under a 128 MiB PHP memory limit. B1 places a synthetic `zend_string` header in a large form value. In our local PHP 8.4.26 build, B1 sent after A1 reaches stale session state and the server process crashes. B1 alone completes normally. The A1/B1 pair completes normally on PHP 8.4.27.

## Reproduce

Build the official PHP 8.4.26 and 8.4.27 source releases on Linux with the same options:

```sh
./configure --disable-all --enable-cli --enable-session --without-pear
make -j4
```

Run Python 3 on the same Linux machine. Pass paths to the two resulting CLI binaries:

```sh
python3 repro.py --php-vulnerable /path/to/php-8.4.26/sapi/cli/php \
                 --php-fixed /path/to/php-8.4.27/sapi/cli/php
```

The script starts `php -S` bound to `127.0.0.1` with `memory_limit=128M`, `post_max_size=8M`, `session.upload_progress.enabled=1`, `display_errors=Off`, and the included `www/index.php`. It checks B1 alone in a fresh 8.4.26 process, then checks A1 followed by B1 in another fresh 8.4.26 process, and finally checks A1/B1 on 8.4.27. It prints HTTP outcomes, worker exit codes, and the last server log lines. It makes no external requests.

Observed with unmodified release sources built on Ubuntu 24.04:

| PHP | Request sequence | Outcome |
| --- | --- | --- |
| 8.4.26 | B1 alone | HTTP 200; worker survives |
| 8.4.26 | A1, then B1 | A1: HTTP 500; B1: connection closes; worker exits on SIGSEGV (`-11`) |
| 8.4.27 | A1, then B1 | Both HTTP 200; worker survives |

To generate the request bodies without running a server:

```sh
python3 repro.py --write-bodies ./out
```

| Body | Size | SHA-256 |
| --- | ---: | --- |
| A1 | 355,594 bytes | `a86ed7ef319f5303a259faeecc8addf11110184b4fc9171c520e891ab255fd68` |
| B1 | 520,552 bytes | `2466c650a7139a28f564e5fdcc75050fec1ef855bd6e31df7a5d653e773db6fb` |

The exact outcome can depend on allocator layout, build options, environment, and filesystem paths. A crash is evidence of reachability of the stale-state path in this configuration; it is not proof of a controlled read, write, or code execution. The 8.4.27 run is a version comparison, not a comprehensive security test.

The initial A1 included large trailing form fields. They were never parsed because the memory failure occurs during the nested file controls. Removing them reduced A1 from 1,027,886 to 355,594 bytes without changing the differential result.

## Research context

The PHP project published advisories for [OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp). This experiment adapts the multipart heap-shaping approach from [9bie's PHP2Shell work](https://github.com/9bie/php2shell-bypass-aslr-exp) to the built-in CLI server and a body under 1 MiB. Other public CLI-server labs include [VKKKV/php2shell-test](https://github.com/VKKKV/php2shell-test), [RemiPelloux/php-session-upload-progress-uaf](https://github.com/RemiPelloux/php-session-upload-progress-uaf), and [allureluoli/php2shell-lab](https://github.com/allureluoli/php2shell-lab).

The remaining research problem is to obtain a useful, reproducible memory disclosure or controlled primitive within this request-size budget and server lifecycle. This repository does not claim that such a chain has been found.
