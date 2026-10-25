# PHP2Shell: sub-1 MiB PHP CLI server memory-disclosure lab

This repository reproduces stale session state in PHP's built-in CLI web server using the session upload-progress path. It is a local, loopback-only differential lab for PHP 8.4.26 and 8.4.27. The latest two-request chain demonstrates a controlled session cookie and out-of-bounds heap disclosure. **It does not demonstrate remote code execution.**

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

## Second path: stale `BG(unserialize)`

`chain_unserialize.py` reproduces a separate pre-RINIT session-decoder use-after-free on the same unmodified PHP builds. Every POST body is below 1 MiB; the script creates the session records through HTTP alone, without manually seeding files or requiring application code to call `session_start()`.

```sh
python3 chain_unserialize.py --php-vulnerable /path/to/php-8.4.26/sapi/cli/php \
                             --php-fixed /path/to/php-8.4.27/sapi/cli/php
```

| Stage | Body size | Purpose | Observed on 8.4.26 |
| --- | ---: | --- | --- |
| Early A | 951,594 bytes | OOM leaves a 600,606-byte upload-progress session record | HTTP 500; worker survives |
| GET | — | Normal request resets stale Session globals | HTTP 200 |
| Early B | 951,594 bytes | Prepares a second session ID | HTTP 500; worker survives |
| GET | — | Resets stale Session globals again | HTTP 200 |
| Late | 433,103 bytes | OOM during pre-RINIT session decode | HTTP 500; worker survives |
| Consumer | 693,097 bytes | Reuses the stale decoder context | Connection closes; worker exits on SIGSEGV (`-11`) |

With PHP 8.4.27, every stage returns HTTP 200 and the worker survives. The consumer alone also returns HTTP 200 on a fresh 8.4.26 server. In an instrumented local build, the late OOM occurs in `ps_srlzr_decode_php()` while allocating the 600,016-byte session key; `BG(unserialize)` remains at level 1 with a pointer into freed request memory. The next request reuses that pointer before Basic RINIT and faults in `tmp_var()`. The repository's scripts do not need instrumentation to reproduce the version difference.

This path demonstrates reuse of freed decoder state, **not a controlled memory disclosure, write, or RCE**. Its heap layout and reliability may change with PHP build options, extensions, paths, or server configuration.

## Targeted reclaim of the freed context

`controlled_reclaim.py` inserts 113 short form values before nested file control 568. Each value is 295 bytes, putting its `zend_string` allocation in ZendMM's 320-byte bin. The consumer body is 733,664 bytes. It runs two fresh-server chains, one with `Y` fill and one with `Z` fill, plus a consumer-alone control and a fixed-version comparison:

```sh
python3 controlled_reclaim.py --php-vulnerable /path/to/php-8.4.26/sapi/cli/php \
                              --php-fixed /path/to/php-8.4.27/sapi/cli/php
```

On the tested unmodified Ubuntu 24.04 build, the consumer alone returns HTTP 200; either complete 8.4.26 chain makes the worker exit on SIGSEGV. The 8.4.27 chain returns HTTP 200 at every stage. In a separate instrumented 8.4.26 build, allocation traces showed that a form value overlaps the stale `BG(unserialize)` context: its first words were `0x5959595959595959` for `Y` and `0x5a5a5a5a5a5a5a5a` for `Z`. That establishes input control over bytes at the freed address in this local layout. It does **not** establish a usable arbitrary read, arbitrary write, address leak, or RCE. Small differences in working directory or build layout can shift the reclaim by a page and change the outcome.

## Controlled session cookie and heap disclosure

`cookie_leak.py` uses a separate two-request chain. The first body (947,495 bytes) exhausts the configured 128 MiB PHP memory limit while the upload-progress session is sending a cookie before normal request initialization. The process returns HTTP 500 and survives with stale `PS(id)` and `PS(mod_data)` pointers. The second body (235,803 bytes) uses nested form fields to reclaim the old session ID's `zend_string` header. It supplies a valid header and a marker as the ID contents. Both bodies fit below 1 MiB.

```sh
python3 cookie_leak.py --php /path/to/php-8.4.26/sapi/cli/php --read-length 128
python3 cookie_leak.py --php /path/to/php-8.4.26/sapi/cli/php --read-length 16000
python3 cookie_leak.py --php /path/to/php-8.4.27/sapi/cli/php --read-length 128
```

Observed with an unmodified Ubuntu 24.04 build of PHP 8.4.26: the first request returns HTTP 500, the second HTTP 200, and the worker survives. Its `Set-Cookie` begins with `LABID0031`. With a forged length of 128, the decoded cookie contains 81 bytes beyond the end of the controlling form value. With a length of 16,000, it also contains pointer-shaped words that point into the same PHP heap region as the stale ID in an instrumented comparison build. PHP 8.4.27 returns HTTP 200 for both requests and a normal 32-byte session ID. The script binds only to `127.0.0.1` and makes no external requests.

This establishes a usable local heap disclosure for this build and allocator layout. The OOM trigger and reclaim geometry may need adjustment for other build options, extensions, working directories, and memory limits. No arbitrary write or RCE has been shown.

## Research context

The PHP project published advisories for [OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp). This experiment adapts the multipart heap-shaping approach from [9bie's PHP2Shell work](https://github.com/9bie/php2shell-bypass-aslr-exp) to the built-in CLI server and a body under 1 MiB. Other public CLI-server labs include [VKKKV/php2shell-test](https://github.com/VKKKV/php2shell-test), [RemiPelloux/php-session-upload-progress-uaf](https://github.com/RemiPelloux/php-session-upload-progress-uaf), and [allureluoli/php2shell-lab](https://github.com/allureluoli/php2shell-lab).

The remaining research problem is to turn the controlled overlap and disclosure into an arbitrary write or code execution. This repository does not claim that such a chain has been found.
